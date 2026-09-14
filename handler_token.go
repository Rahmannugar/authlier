package authlier

import (
	"errors"
	"net/http"

	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/token"
)

type refreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func invalidRefreshTokenError(err error) bool {
	return errors.Is(err, refreshtoken.ErrInactive) ||
		errors.Is(err, refreshtoken.ErrInvalidRecord) ||
		errors.Is(err, refreshtoken.ErrNotFound) ||
		errors.Is(err, refreshtoken.ErrReuseDetected) ||
		errors.Is(err, token.ErrInvalidToken) ||
		errors.Is(err, accesstoken.ErrInactiveSession)
}

func registerTokenRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/token/refresh", handler.refreshAccessToken)
}

func (handler *httpHandler) refreshAccessToken(
	response http.ResponseWriter,
	request *http.Request,
) {
	var input refreshTokenRequest
	if !readJSON(response, request, &input) {
		return
	}
	issued, err := handler.auth.bearerSessions.Refresh(request.Context(), input.RefreshToken)
	if err != nil {
		if invalidRefreshTokenError(err) {
			writeError(response, http.StatusUnauthorized, "invalid_refresh_token")
			return
		}
		writeError(response, http.StatusInternalServerError, "token_refresh_failed")
		return
	}
	writeJSON(response, http.StatusOK, sessionResponse{
		Session: newSessionDetails(issued.Session),
		Tokens:  newTokenDetails(issued),
	})
}
