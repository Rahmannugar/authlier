package authlier

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnlySAMLCallbackAcceptsCrossSitePOST(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/sso/saml/callback", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/auth/sign-out", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	handler := &httpHandler{
		allowedOrigins: []string{"https://app.example.com"},
		crossSitePOSTs: map[string]struct{}{"/api/auth/sso/saml/callback": {}},
		mux:            mux,
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(
		http.MethodPost, "/api/auth/sso/saml/callback", nil,
	))
	if response.Code != http.StatusNoContent {
		t.Fatalf("SAML callback status = %d, want %d", response.Code, http.StatusNoContent)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/auth/sign-out", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("ordinary cross-site POST status = %d, want %d", response.Code, http.StatusForbidden)
	}
}
