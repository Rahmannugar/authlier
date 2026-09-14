package authlier

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChangePasswordCanRevokeOtherSessionsAndKeepTheUserSignedIn(t *testing.T) {
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
		"/api/auth/sign-up/email",
		`{"email":"owner@example.com","password":"original password"}`,
	))
	if signUp.Code != http.StatusCreated || len(signUp.Result().Cookies()) != 1 {
		t.Fatalf("sign up: status=%d body=%s", signUp.Code, signUp.Body.String())
	}

	request := newAuthRequest(
		"/api/auth/change-password",
		`{"currentPassword":"original password","newPassword":"replacement password","revokeOtherSessions":true}`,
	)
	request.AddCookie(signUp.Result().Cookies()[0])
	changed := httptest.NewRecorder()
	auth.Handler().ServeHTTP(changed, request)
	if changed.Code != http.StatusOK {
		t.Fatalf("change password: status=%d body=%s", changed.Code, changed.Body.String())
	}
	if !sessions.revokedAll || sessions.created != 2 || len(changed.Result().Cookies()) != 1 {
		t.Fatalf(
			"session replacement: revoked=%t created=%d cookies=%d",
			sessions.revokedAll,
			sessions.created,
			len(changed.Result().Cookies()),
		)
	}

	oldPassword := httptest.NewRecorder()
	auth.Handler().ServeHTTP(oldPassword, newAuthRequest(
		"/api/auth/sign-in/email",
		`{"email":"owner@example.com","password":"original password"}`,
	))
	if oldPassword.Code != http.StatusUnauthorized {
		t.Fatalf("old password sign in: status=%d", oldPassword.Code)
	}

	newPassword := httptest.NewRecorder()
	auth.Handler().ServeHTTP(newPassword, newAuthRequest(
		"/api/auth/sign-in/email",
		`{"email":"owner@example.com","password":"replacement password"}`,
	))
	if newPassword.Code != http.StatusOK {
		t.Fatalf("new password sign in: status=%d body=%s", newPassword.Code, newPassword.Body.String())
	}
}
