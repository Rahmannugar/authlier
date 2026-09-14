package authlier

import (
	"errors"
	"net/http"
	"time"

	"github.com/Rahmannugar/authlier/googleoauth"
)

type authorizationURLResponse struct {
	URL string `json:"url"`
}

type unlinkGoogleRequest struct {
	ProviderSubject string `json:"providerSubject"`
}

type googleAccountDetails struct {
	ProviderSubject string    `json:"providerSubject"`
	Email           string    `json:"email"`
	LinkedAt        time.Time `json:"linkedAt"`
}

type googleAccountsResponse struct {
	Accounts []googleAccountDetails `json:"accounts"`
}

func registerGoogleRoutes(handler *httpHandler, basePath string) {
	handler.mux.HandleFunc("POST "+basePath+"/sign-in/google", handler.signInWithGoogle)
	handler.mux.HandleFunc("GET "+basePath+"/callback/google", handler.completeGoogleSignIn)
	handler.mux.HandleFunc("POST "+basePath+"/link-account/google", handler.linkGoogle)
	handler.mux.HandleFunc("GET "+basePath+"/list-accounts/google", handler.listGoogleAccounts)
	handler.mux.HandleFunc("POST "+basePath+"/unlink-account/google", handler.unlinkGoogle)
}

func (handler *httpHandler) listGoogleAccounts(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.requireSession(response, request, false)
	if !ok {
		return
	}
	identities, err := handler.auth.google.List(request.Context(), session.SubjectID)
	if err != nil {
		writeGoogleError(response, err)
		return
	}
	accounts := make([]googleAccountDetails, len(identities))
	for index, identity := range identities {
		accounts[index] = googleAccountDetails{
			ProviderSubject: identity.ProviderSubject,
			Email:           identity.Email,
			LinkedAt:        identity.LinkedAt,
		}
	}
	writeJSON(response, http.StatusOK, googleAccountsResponse{Accounts: accounts})
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
	var input unlinkGoogleRequest
	if !readJSON(response, request, &input) {
		return
	}
	if err := handler.auth.google.Unlink(
		request.Context(), session.SubjectID, input.ProviderSubject, handler.sourceKey(request),
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
