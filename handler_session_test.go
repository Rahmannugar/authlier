package authlier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionRoutesListAndRevokeTheCurrentSessionByID(t *testing.T) {
	accounts := &authenticationStore{}
	sessions := newSessionStore(time.Now().UTC())
	auth, err := New(Config{
		AppName: "Acme",
		BaseURL: "https://app.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword: accounts,
			Sessions:      sessions,
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Session:          SessionConfig{Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	signUp := httptest.NewRecorder()
	auth.Handler().ServeHTTP(signUp, newAuthRequest(
		"/api/auth/sign-up",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	cookies := signUp.Result().Cookies()
	if signUp.Code != http.StatusCreated || len(cookies) != 1 {
		t.Fatalf("sign up: status=%d body=%s", signUp.Code, signUp.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/auth/list-sessions", nil)
	listRequest.AddCookie(cookies[0])
	listedResponse := httptest.NewRecorder()
	auth.Handler().ServeHTTP(listedResponse, listRequest)
	var listed sessionsResponse
	if err := json.Unmarshal(listedResponse.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if listedResponse.Code != http.StatusOK || len(listed.Sessions) != 1 ||
		!listed.Sessions[0].Current || listed.Sessions[0].ID == "" {
		t.Fatalf("listed sessions: status=%d response=%+v", listedResponse.Code, listed)
	}

	revokeRequest := newAuthRequest(
		"/api/auth/revoke-session",
		`{"sessionId":"`+listed.Sessions[0].ID+`"}`,
	)
	revokeRequest.AddCookie(cookies[0])
	revokedResponse := httptest.NewRecorder()
	auth.Handler().ServeHTTP(revokedResponse, revokeRequest)
	if revokedResponse.Code != http.StatusNoContent || sessions.record.RevokedAt == nil {
		t.Fatalf("revoke current session: status=%d", revokedResponse.Code)
	}
}
