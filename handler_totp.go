package authlier

import (
	"errors"
	"net/http"
	"time"

	"github.com/Rahmannugar/authlier/totp"
)

type totpEnrollmentRequest struct {
	AccountName string `json:"accountName"`
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

type twoFactorRequest struct {
	ChallengeToken string `json:"challengeToken"`
	Code           string `json:"code"`
}

type totpEnrollmentResponse struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type recoveryCodesResponse struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

type twoFactorRequiredResponse struct {
	TwoFactorRequired bool      `json:"twoFactorRequired"`
	ChallengeToken    string    `json:"challengeToken"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

func registerTOTPRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/two-factor/totp/enable", handler.enableTOTP)
	handler.mux.HandleFunc("POST "+basePath+"/two-factor/totp/confirm", handler.confirmTOTP)
	handler.mux.HandleFunc("POST "+basePath+"/two-factor/verify", handler.verifyTOTP)
	handler.mux.HandleFunc("POST "+basePath+"/two-factor/recover", handler.recoverTOTP)
	handler.mux.HandleFunc("POST "+basePath+"/two-factor/disable", handler.disableTOTP)
}

func (handler *httpHandler) enableTOTP(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	var input totpEnrollmentRequest
	if !readJSON(response, request, &input) {
		return
	}
	enrollment, err := handler.auth.totp.BeginEnrollment(
		request.Context(), session.SubjectID, input.AccountName,
	)
	if err != nil {
		writeTOTPError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, totpEnrollmentResponse{
		Secret: enrollment.Secret, URI: enrollment.URI, ExpiresAt: enrollment.ExpiresAt,
	})
}

func (handler *httpHandler) confirmTOTP(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	var input totpCodeRequest
	if !readJSON(response, request, &input) {
		return
	}
	confirmed, err := handler.auth.totp.ConfirmEnrollment(
		request.Context(), session.SubjectID, input.Code, handler.sourceKey(request),
	)
	if err != nil {
		writeTOTPError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, recoveryCodesResponse{RecoveryCodes: confirmed.RecoveryCodes})
}

func (handler *httpHandler) verifyTOTP(response http.ResponseWriter, request *http.Request) {
	var input twoFactorRequest
	if !readJSON(response, request, &input) {
		return
	}
	authentication, err := handler.auth.totp.Verify(request.Context(), totp.VerifyInput{
		ChallengeToken: input.ChallengeToken, Code: input.Code, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeTOTPError(response, err)
		return
	}
	handler.createAuthenticatedSession(response, request, authentication.SubjectID)
}

func (handler *httpHandler) recoverTOTP(response http.ResponseWriter, request *http.Request) {
	var input twoFactorRequest
	if !readJSON(response, request, &input) {
		return
	}
	authentication, err := handler.auth.totp.Recover(request.Context(), totp.VerifyInput{
		ChallengeToken: input.ChallengeToken, Code: input.Code, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeTOTPError(response, err)
		return
	}
	handler.createAuthenticatedSession(response, request, authentication.SubjectID)
}

func (handler *httpHandler) disableTOTP(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	if err := handler.auth.totp.Disable(request.Context(), session.SubjectID, handler.sourceKey(request)); err != nil {
		writeTOTPError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func writeTOTPError(response http.ResponseWriter, err error) {
	if errors.Is(err, totp.ErrInvalidCode) || errors.Is(err, totp.ErrInvalidChallenge) ||
		errors.Is(err, totp.ErrInvalidInput) {
		writeError(response, http.StatusBadRequest, "invalid_two_factor_input")
		return
	}
	if errors.Is(err, totp.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	if errors.Is(err, totp.ErrAlreadyEnabled) {
		writeError(response, http.StatusConflict, "two_factor_already_enabled")
		return
	}
	if errors.Is(err, totp.ErrNotFound) {
		writeError(response, http.StatusNotFound, "two_factor_not_found")
		return
	}
	writeError(response, http.StatusInternalServerError, "two_factor_failed")
}
