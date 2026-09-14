package authlier

import (
	"errors"
	"net/http"

	"github.com/Rahmannugar/authlier/emailpassword"
)

type changePasswordRequest struct {
	CurrentPassword     string `json:"currentPassword"`
	NewPassword         string `json:"newPassword"`
	RevokeOtherSessions bool   `json:"revokeOtherSessions"`
}

type setPasswordRequest struct {
	Password string `json:"password"`
}

type removePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
}

func registerAccountRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/change-password", handler.changePassword)
	handler.mux.HandleFunc("POST "+basePath+"/set-password", handler.setPassword)
	handler.mux.HandleFunc("POST "+basePath+"/remove-password", handler.removePassword)
}

func (handler *httpHandler) changePassword(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	var input changePasswordRequest
	if !readJSON(response, request, &input) {
		return
	}
	user, err := handler.auth.password.ChangePassword(request.Context(), emailpassword.ChangePasswordInput{
		SubjectID:       session.SubjectID,
		CurrentPassword: input.CurrentPassword,
		NewPassword:     input.NewPassword,
		SourceKey:       handler.sourceKey(request),
	})
	if err != nil {
		writeCredentialError(response, err)
		return
	}
	if input.RevokeOtherSessions {
		if err := handler.revokeAllSessions(request, session.SubjectID); err != nil {
			writeError(response, http.StatusInternalServerError, "session_revocation_failed")
			return
		}
		handler.createAuthenticatedSession(response, request, session.SubjectID)
		return
	}
	writeJSON(response, http.StatusOK, newUserResponse(user.ID, user.Email))
}

func (handler *httpHandler) setPassword(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	var input setPasswordRequest
	if !readJSON(response, request, &input) {
		return
	}
	user, err := handler.auth.password.AddPassword(request.Context(), emailpassword.AddPasswordInput{
		SubjectID: session.SubjectID,
		Password:  input.Password,
		SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeCredentialError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, newUserResponse(user.ID, user.Email))
}

func (handler *httpHandler) removePassword(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	var input removePasswordRequest
	if !readJSON(response, request, &input) {
		return
	}
	err := handler.auth.password.RemovePassword(request.Context(), emailpassword.RemovePasswordInput{
		SubjectID:       session.SubjectID,
		CurrentPassword: input.CurrentPassword,
		SourceKey:       handler.sourceKey(request),
	})
	if err != nil {
		writeCredentialError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func writeCredentialError(response http.ResponseWriter, err error) {
	if errors.Is(err, emailpassword.ErrInvalidInput) || errors.Is(err, emailpassword.ErrInvalidPassword) {
		writeError(response, http.StatusBadRequest, "invalid_password")
		return
	}
	if errors.Is(err, emailpassword.ErrInvalidCredentials) {
		writeError(response, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if errors.Is(err, emailpassword.ErrPasswordUnchanged) {
		writeError(response, http.StatusConflict, "password_unchanged")
		return
	}
	if errors.Is(err, emailpassword.ErrLastCredential) {
		writeError(response, http.StatusConflict, "last_sign_in_method")
		return
	}
	if errors.Is(err, emailpassword.ErrConflict) {
		writeError(response, http.StatusConflict, "password_already_set")
		return
	}
	if errors.Is(err, emailpassword.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	writeError(response, http.StatusInternalServerError, "credential_update_failed")
}
