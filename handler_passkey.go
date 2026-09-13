package authlier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Rahmannugar/authlier/passkey"
	"github.com/go-webauthn/webauthn/protocol"
)

type passkeyCompletionRequest struct {
	CeremonyToken string          `json:"ceremonyToken"`
	Response      json.RawMessage `json:"response"`
}

type passkeyRemovalRequest struct {
	CredentialID string `json:"credentialId"`
}

type passkeyRegistrationOptionsResponse struct {
	CeremonyToken string                       `json:"ceremonyToken"`
	Options       *protocol.CredentialCreation `json:"options"`
	ExpiresAt     time.Time                    `json:"expiresAt"`
}

type passkeySignInOptionsResponse struct {
	CeremonyToken string                        `json:"ceremonyToken"`
	Options       *protocol.CredentialAssertion `json:"options"`
	ExpiresAt     time.Time                     `json:"expiresAt"`
}

type passkeyResponse struct {
	CredentialID string `json:"credentialId"`
}

func registerPasskeyRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/passkey/register/options", handler.passkeyRegistrationOptions)
	handler.mux.HandleFunc("POST "+basePath+"/passkey/register/verify", handler.verifyPasskeyRegistration)
	handler.mux.HandleFunc("POST "+basePath+"/passkey/sign-in/options", handler.passkeySignInOptions)
	handler.mux.HandleFunc("POST "+basePath+"/passkey/sign-in/verify", handler.verifyPasskeySignIn)
	handler.mux.HandleFunc("POST "+basePath+"/passkey/remove", handler.removePasskey)
}

func (handler *httpHandler) passkeyRegistrationOptions(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	started, err := handler.auth.passkeys.BeginRegistration(request.Context(), session.SubjectID)
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, passkeyRegistrationOptionsResponse{
		CeremonyToken: started.Token, Options: started.Options, ExpiresAt: started.ExpiresAt,
	})
}

func (handler *httpHandler) verifyPasskeyRegistration(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	var input passkeyCompletionRequest
	if !readJSON(response, request, &input) {
		return
	}
	credential, err := handler.auth.passkeys.CompleteRegistration(request.Context(), passkey.CompleteInput{
		CeremonyToken: input.CeremonyToken,
		SubjectID:     session.SubjectID,
		Response:      input.Response,
		SourceKey:     handler.sourceKey(request),
	})
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, passkeyResponse{
		CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID),
	})
}

func (handler *httpHandler) passkeySignInOptions(response http.ResponseWriter, request *http.Request) {
	started, err := handler.auth.passkeys.BeginAuthentication(request.Context())
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, passkeySignInOptionsResponse{
		CeremonyToken: started.Token, Options: started.Options, ExpiresAt: started.ExpiresAt,
	})
}

func (handler *httpHandler) verifyPasskeySignIn(response http.ResponseWriter, request *http.Request) {
	var input passkeyCompletionRequest
	if !readJSON(response, request, &input) {
		return
	}
	authentication, err := handler.auth.passkeys.CompleteAuthentication(request.Context(), passkey.CompleteInput{
		CeremonyToken: input.CeremonyToken,
		Response:      input.Response,
		SourceKey:     handler.sourceKey(request),
	})
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	handler.createAuthenticatedSession(response, request, authentication.SubjectID)
}

func (handler *httpHandler) removePasskey(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	var input passkeyRemovalRequest
	if !readJSON(response, request, &input) {
		return
	}
	credentialID, err := base64.RawURLEncoding.DecodeString(input.CredentialID)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := handler.auth.passkeys.Remove(
		request.Context(), session.SubjectID, credentialID, handler.sourceKey(request),
	); err != nil {
		writePasskeyError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func writePasskeyError(response http.ResponseWriter, err error) {
	if errors.Is(err, passkey.ErrInvalidCeremony) || errors.Is(err, passkey.ErrInvalidInput) ||
		errors.Is(err, passkey.ErrVerification) {
		writeError(response, http.StatusBadRequest, "passkey_verification_failed")
		return
	}
	if errors.Is(err, passkey.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	if errors.Is(err, passkey.ErrLastCredential) {
		writeError(response, http.StatusConflict, "last_sign_in_method")
		return
	}
	if errors.Is(err, passkey.ErrNotFound) {
		writeError(response, http.StatusNotFound, "passkey_not_found")
		return
	}
	writeError(response, http.StatusInternalServerError, "passkey_failed")
}
