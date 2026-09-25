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

type verifyEmailOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func registerEmailVerificationRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/resend-verification", handler.resendVerification)
	if handler.auth.emailVerificationDelivery == emailverification.DeliveryMethodOTP {
		handler.mux.HandleFunc("POST "+basePath+"/verify-email", handler.verifyEmailOTP)
	} else {
		handler.mux.HandleFunc("GET "+basePath+"/verify-email", handler.verifyEmailLink)
	}
}

func registerPasswordResetRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/forgot-password", handler.forgotPassword)
	handler.mux.HandleFunc("POST "+basePath+"/reset-password", handler.resetPassword)
}

func (handler *httpHandler) resendVerification(response http.ResponseWriter, request *http.Request) {
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

func (handler *httpHandler) verifyEmailLink(response http.ResponseWriter, request *http.Request) {
	token := request.URL.Query().Get("token")
	if token == "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	handler.completeEmailVerification(response, request, emailverification.VerifyInput{
		Token: token, SourceKey: handler.sourceKey(request),
	})
}

func (handler *httpHandler) verifyEmailOTP(response http.ResponseWriter, request *http.Request) {
	var input verifyEmailOTPRequest
	if !readJSON(response, request, &input) {
		return
	}
	handler.completeEmailVerification(response, request, emailverification.VerifyInput{
		Email: input.Email, Code: input.Code, SourceKey: handler.sourceKey(request),
	})
}

func (handler *httpHandler) completeEmailVerification(
	response http.ResponseWriter,
	request *http.Request,
	input emailverification.VerifyInput,
) {
	user, err := handler.auth.emailVerification.Verify(request.Context(), input)
	if err != nil {
		writeEmailVerificationError(response, err)
		return
	}
	if handler.auth.autoSignInAfterVerification {
		session, tokens, ok := handler.issueSession(response, request, user.ID)
		if !ok {
			return
		}
		writeJSON(response, http.StatusOK, userResponse{
			User: userDetails{ID: user.ID, Email: user.Email}, Session: &session, Tokens: tokens,
		})
		return
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
		if err := handler.revokeAllSessions(request, user.ID); err != nil {
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
