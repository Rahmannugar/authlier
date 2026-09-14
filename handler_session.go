package authlier

import (
	"errors"
	"net/http"
	"time"

	"github.com/Rahmannugar/authlier/sessiontoken"
)

type listedSessionDetails struct {
	sessionDetails
	Current bool `json:"current"`
}

type sessionsResponse struct {
	Sessions []listedSessionDetails `json:"sessions"`
}

type revokeSessionRequest struct {
	SessionID string `json:"sessionId"`
}

func registerSessionRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("GET "+basePath+"/list-sessions", handler.listSessions)
	handler.mux.HandleFunc("POST "+basePath+"/revoke-session", handler.revokeSession)
	handler.mux.HandleFunc("POST "+basePath+"/revoke-other-sessions", handler.revokeOtherSessions)
	handler.mux.HandleFunc("POST "+basePath+"/revoke-sessions", handler.revokeSessions)
}

func (handler *httpHandler) listSessions(response http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	records, err := handler.auth.sessions.List(request.Context(), current.SubjectID)
	if err != nil {
		writeSessionError(response, err)
		return
	}
	now := time.Now().UTC()
	sessions := make([]listedSessionDetails, 0, len(records))
	for _, record := range records {
		if !record.ActiveAt(now) {
			continue
		}
		sessions = append(sessions, listedSessionDetails{
			sessionDetails: newSessionDetails(record),
			Current:        record.ID == current.ID,
		})
	}
	writeJSON(response, http.StatusOK, sessionsResponse{Sessions: sessions})
}

func (handler *httpHandler) revokeSession(response http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	var input revokeSessionRequest
	if !readJSON(response, request, &input) {
		return
	}
	if err := handler.auth.sessions.RevokeByID(
		request.Context(), current.SubjectID, input.SessionID,
	); err != nil {
		writeSessionError(response, err)
		return
	}
	if input.SessionID == current.ID {
		handler.clearSession(response)
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *httpHandler) revokeOtherSessions(response http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	if err := handler.auth.sessions.RevokeAll(request.Context(), current.SubjectID); err != nil {
		writeSessionError(response, err)
		return
	}
	handler.clearSession(response)
	handler.createAuthenticatedSession(response, request, current.SubjectID)
}

func (handler *httpHandler) revokeSessions(response http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	if err := handler.auth.sessions.RevokeAll(request.Context(), current.SubjectID); err != nil {
		writeSessionError(response, err)
		return
	}
	handler.clearSession(response)
	response.WriteHeader(http.StatusNoContent)
}

func writeSessionError(response http.ResponseWriter, err error) {
	if errors.Is(err, sessiontoken.ErrNotFound) {
		writeError(response, http.StatusNotFound, "session_not_found")
		return
	}
	writeError(response, http.StatusInternalServerError, "session_update_failed")
}
