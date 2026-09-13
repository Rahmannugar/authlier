package authlier

import (
	"errors"
	"net/http"

	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/passwordreset"
)

type emailRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func registerEmailVerificationRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/send-verification-email", handler.sendVerificationEmail)
	handler.mux.HandleFunc("GET "+basePath+"/verify-email", handler.verifyEmail)
}

func registerPasswordResetRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/forgot-password", handler.forgotPassword)
	handler.mux.HandleFunc("POST "+basePath+"/reset-password", handler.resetPassword)
}

func (handler *httpHandler) sendVerificationEmail(response http.ResponseWriter, request *http.Request) {
	var input emailRequest
	if !readJSON(response, request, &input) {
		return
	}
	if err := handler.auth.emailVerification.Request(request.Context(), emailverification.RequestInput{
		Email: input.Email, SourceKey: handler.sourceKey(request),
	}); err != nil {
		writeEmailVerificationError(response, err)
		return
	}
	response.WriteHeader(http.StatusAccepted)
}

func (handler *httpHandler) verifyEmail(response http.ResponseWriter, request *http.Request) {
	token := request.URL.Query().Get("token")
	if token == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	user, err := handler.auth.emailVerification.Verify(request.Context(), emailverification.VerifyInput{
		Token: token, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeEmailVerificationError(response, err)
		return
	}
	if handler.auth.autoSignInAfterVerification {
		issued, err := handler.auth.sessions.Create(request.Context(), user.ID)
		if err != nil {
			writeError(response, http.StatusInternalServerError, "session_failed")
			return
		}
		handler.setSession(response, issued.Token, issued.Record.ExpiresAt)
	}
	writeJSON(response, http.StatusOK, newUserResponse(user.ID, user.Email))
}

func (handler *httpHandler) forgotPassword(response http.ResponseWriter, request *http.Request) {
	var input emailRequest
	if !readJSON(response, request, &input) {
		return
	}
	if err := handler.auth.passwordReset.Request(request.Context(), passwordreset.RequestInput{
		Email: input.Email, SourceKey: handler.sourceKey(request),
	}); err != nil {
		writePasswordResetError(response, err)
		return
	}
	response.WriteHeader(http.StatusAccepted)
}

func (handler *httpHandler) resetPassword(response http.ResponseWriter, request *http.Request) {
	var input resetPasswordRequest
	if !readJSON(response, request, &input) {
		return
	}
	user, err := handler.auth.passwordReset.Reset(request.Context(), passwordreset.ResetInput{
		Token: input.Token, NewPassword: input.NewPassword, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writePasswordResetError(response, err)
		return
	}
	if handler.auth.revokeSessionsOnPasswordReset {
		if err := handler.auth.sessions.RevokeAll(request.Context(), user.ID); err != nil {
			writeError(response, http.StatusInternalServerError, "session_revocation_failed")
			return
		}
		handler.clearSession(response)
	}
	writeJSON(response, http.StatusOK, newUserResponse(user.ID, user.Email))
}

func writeEmailVerificationError(response http.ResponseWriter, err error) {
	if errors.Is(err, emailverification.ErrInvalidToken) {
		writeError(response, http.StatusBadRequest, "invalid_token")
		return
	}
	if errors.Is(err, emailverification.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	writeError(response, http.StatusInternalServerError, "email_verification_failed")
}

func writePasswordResetError(response http.ResponseWriter, err error) {
	if errors.Is(err, passwordreset.ErrInvalidToken) {
		writeError(response, http.StatusBadRequest, "invalid_token")
		return
	}
	if errors.Is(err, passwordreset.ErrInvalidPassword) {
		writeError(response, http.StatusBadRequest, "invalid_password")
		return
	}
	if errors.Is(err, passwordreset.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	writeError(response, http.StatusInternalServerError, "password_reset_failed")
}
