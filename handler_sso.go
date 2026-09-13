package authlier

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/saml"
)

type ssoSignInRequest struct {
	ConnectionID string `json:"connectionId"`
}

func registerSSORoutes(handler *httpHandler, basePath string) {
	if handler.auth.oidc != nil {
		handler.mux.HandleFunc("POST "+basePath+"/sso/oidc/sign-in", handler.beginOIDC)
		handler.mux.HandleFunc("GET "+basePath+"/sso/oidc/callback", handler.completeOIDC)
	}
	if handler.auth.saml != nil {
		handler.mux.HandleFunc("POST "+basePath+"/sso/saml/sign-in", handler.beginSAML)
		handler.mux.HandleFunc("POST "+basePath+"/sso/saml/callback", handler.completeSAML)
		handler.mux.HandleFunc("GET "+basePath+"/sso/saml/metadata", handler.samlMetadata)
		handler.crossSitePOSTs[basePath+"/sso/saml/callback"] = struct{}{}
	}
}

func (handler *httpHandler) beginOIDC(response http.ResponseWriter, request *http.Request) {
	var input ssoSignInRequest
	if !readJSON(response, request, &input) {
		return
	}
	started, err := handler.auth.oidc.Begin(request.Context(), oidc.BeginInput{
		ConnectionID: input.ConnectionID, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeOIDCError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, authorizationURLResponse{URL: started.AuthorizationURL})
}

func (handler *httpHandler) completeOIDC(response http.ResponseWriter, request *http.Request) {
	identity, err := handler.auth.oidc.Complete(request.Context(), oidc.CompleteInput{
		State:     request.URL.Query().Get("state"),
		Code:      request.URL.Query().Get("code"),
		SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeOIDCError(response, err)
		return
	}
	subjectID, err := handler.auth.resolveOIDCIdentity(request.Context(), identity)
	if err != nil || strings.TrimSpace(subjectID) == "" {
		writeError(response, http.StatusForbidden, "sso_identity_not_resolved")
		return
	}
	handler.completeProviderAuthentication(
		response, request, subjectID, handler.auth.oidcSuccessRedirectURL,
	)
}

func (handler *httpHandler) beginSAML(response http.ResponseWriter, request *http.Request) {
	var input ssoSignInRequest
	if !readJSON(response, request, &input) {
		return
	}
	started, err := handler.auth.saml.Begin(request.Context(), saml.BeginInput{
		ConnectionID: input.ConnectionID, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeSAMLError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, authorizationURLResponse{URL: started.AuthorizationURL})
}

func (handler *httpHandler) completeSAML(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, maximumRequestBody)
	if err := request.ParseForm(); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	identity, err := handler.auth.saml.Complete(request.Context(), saml.CompleteInput{
		State:        request.Form.Get("RelayState"),
		SAMLResponse: request.Form.Get("SAMLResponse"),
		SourceKey:    handler.sourceKey(request),
	})
	if err != nil {
		writeSAMLError(response, err)
		return
	}
	subjectID, err := handler.auth.resolveSAMLIdentity(request.Context(), identity)
	if err != nil || strings.TrimSpace(subjectID) == "" {
		writeError(response, http.StatusForbidden, "sso_identity_not_resolved")
		return
	}
	handler.completeProviderAuthentication(
		response, request, subjectID, handler.auth.samlSuccessRedirectURL,
	)
}

func (handler *httpHandler) samlMetadata(response http.ResponseWriter, request *http.Request) {
	metadata, err := handler.auth.saml.Metadata(request.Context(), request.URL.Query().Get("connectionId"))
	if err != nil {
		writeSAMLError(response, err)
		return
	}
	response.Header().Set("Content-Type", "application/samlmetadata+xml")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(metadata)
}

func writeOIDCError(response http.ResponseWriter, err error) {
	if errors.Is(err, oidc.ErrInvalidInput) || errors.Is(err, oidc.ErrInvalidState) ||
		errors.Is(err, oidc.ErrInvalidIdentity) || errors.Is(err, oidc.ErrUnverifiedEmail) {
		writeError(response, http.StatusBadRequest, "oidc_authentication_failed")
		return
	}
	if errors.Is(err, oidc.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	if errors.Is(err, oidc.ErrNotFound) {
		writeError(response, http.StatusNotFound, "sso_connection_not_found")
		return
	}
	writeError(response, http.StatusInternalServerError, "oidc_authentication_failed")
}

func writeSAMLError(response http.ResponseWriter, err error) {
	if errors.Is(err, saml.ErrInvalidInput) || errors.Is(err, saml.ErrInvalidState) ||
		errors.Is(err, saml.ErrInvalidIdentity) || errors.Is(err, saml.ErrInvalidResponse) {
		writeError(response, http.StatusBadRequest, "saml_authentication_failed")
		return
	}
	if errors.Is(err, saml.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	if errors.Is(err, saml.ErrNotFound) {
		writeError(response, http.StatusNotFound, "sso_connection_not_found")
		return
	}
	writeError(response, http.StatusInternalServerError, "saml_authentication_failed")
}
