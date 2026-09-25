package authlier

import (
	"errors"
	"net/http"

	"github.com/Rahmannugar/authlier/googleoauth"
)

type authorizationURLResponse struct {
	URL string `json:"url"`
}

func registerGoogleRoutes(handler *httpHandler, basePath string, accountBasePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/google", handler.signInWithGoogle)
	handler.mux.HandleFunc("GET "+basePath+"/google/callback", handler.completeGoogleSignIn)
	handler.mux.HandleFunc("POST "+accountBasePath+"/google", handler.linkGoogle)
	handler.mux.HandleFunc("DELETE "+accountBasePath+"/google", handler.unlinkGoogle)
}

func (handler *httpHandler) signInWithGoogle(response http.ResponseWriter, request *http.Request) {
	started, err := handler.auth.google.Begin(request.Context(), "")
	if err != nil {
		writeGoogleError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, authorizationURLResponse{URL: started.AuthorizationURL})
}

func (handler *httpHandler) linkGoogle(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	started, err := handler.auth.google.Begin(request.Context(), session.SubjectID)
	if err != nil {
		writeGoogleError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, authorizationURLResponse{URL: started.AuthorizationURL})
}

func (handler *httpHandler) completeGoogleSignIn(response http.ResponseWriter, request *http.Request) {
	user, err := handler.auth.google.Complete(
		request.Context(), request.URL.Query().Get("state"), request.URL.Query().Get("code"),
	)
	if err != nil {
		writeGoogleError(response, err)
		return
	}
	handler.completeProviderAuthentication(
		response, request, user.ID, handler.auth.googleSuccessRedirectURL,
	)
}

func (handler *httpHandler) unlinkGoogle(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, true)
	if !ok {
		return
	}
	if err := handler.auth.google.Unlink(
		request.Context(), session.SubjectID, handler.sourceKey(request),
	); err != nil {
		writeGoogleError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func writeGoogleError(response http.ResponseWriter, err error) {
	if errors.Is(err, googleoauth.ErrInvalidInput) || errors.Is(err, googleoauth.ErrInvalidState) ||
		errors.Is(err, googleoauth.ErrUnverified) {
		writeError(response, http.StatusBadRequest, "google_authentication_failed")
		return
	}
	if errors.Is(err, googleoauth.ErrLinkRequired) {
		writeError(response, http.StatusConflict, "account_linking_required")
		return
	}
	if errors.Is(err, googleoauth.ErrConflict) {
		writeError(response, http.StatusConflict, "google_account_already_linked")
		return
	}
	if errors.Is(err, googleoauth.ErrLastCredential) {
		writeError(response, http.StatusConflict, "last_sign_in_method")
		return
	}
	if errors.Is(err, googleoauth.ErrNotFound) {
		writeError(response, http.StatusNotFound, "google_account_not_found")
		return
	}
	writeError(response, http.StatusInternalServerError, "google_authentication_failed")
}
