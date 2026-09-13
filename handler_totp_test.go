package authlier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/totp"
	otplibrary "github.com/pquerna/otp/totp"
)

func TestPasswordSignInWaitsForTOTPBeforeCreatingSession(t *testing.T) {
	accounts := &authenticationStore{}
	sessions := newSessionStore(time.Now().UTC())
	totpStore := &handlerTOTPStore{secret: "JBSWY3DPEHPK3PXP"}
	auth, err := New(Config{
		AppName: "Acme",
		BaseURL: "https://app.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword: accounts,
			Sessions:      sessions,
			TOTP:          totpStore,
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Session: SessionConfig{
			Lifetime: time.Hour,
			FreshAge: time.Minute,
		},
		TOTP: TOTPConfig{
			Enabled:            true,
			EnrollmentLifetime: 10 * time.Minute,
			ChallengeLifetime:  5 * time.Minute,
			RecoveryCodeCount:  8,
		},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-up/email",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	if response.Code != http.StatusCreated || sessions.created != 1 {
		t.Fatalf("sign up: status=%d sessions=%d", response.Code, sessions.created)
	}
	totpStore.enabled = true

	response = httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-in/email",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	if response.Code != http.StatusOK || sessions.created != 1 {
		t.Fatalf("primary sign in: status=%d sessions=%d body=%s", response.Code, sessions.created, response.Body.String())
	}
	var challenge twoFactorRequiredResponse
	if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode TOTP challenge: %v", err)
	}
	if !challenge.TwoFactorRequired || challenge.ChallengeToken == "" {
		t.Fatalf("unexpected TOTP challenge: %+v", challenge)
	}

	code, err := otplibrary.GenerateCode(totpStore.secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	response = httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/two-factor/verify",
		`{"challengeToken":"`+challenge.ChallengeToken+`","code":"`+code+`"}`,
	))
	if response.Code != http.StatusOK || sessions.created != 2 {
		t.Fatalf("complete TOTP: status=%d sessions=%d body=%s", response.Code, sessions.created, response.Body.String())
	}
}

type handlerTOTPStore struct {
	secret    string
	enabled   bool
	challenge totp.Challenge
}

func (store *handlerTOTPStore) IsEnabled(context.Context, string) (bool, error) {
	return store.enabled, nil
}

func (store *handlerTOTPStore) BeginEnrollment(context.Context, totp.Enrollment) error {
	return nil
}

func (store *handlerTOTPStore) FindEnrollment(context.Context, string) (totp.Enrollment, error) {
	return totp.Enrollment{}, totp.ErrNotFound
}

func (store *handlerTOTPStore) Enable(
	context.Context,
	string,
	uint64,
	[]totp.RecoveryCodeHash,
	time.Time,
) error {
	return nil
}

func (store *handlerTOTPStore) Disable(context.Context, string, time.Time) error {
	store.enabled = false
	return nil
}

func (store *handlerTOTPStore) CreateChallenge(_ context.Context, challenge totp.Challenge) error {
	store.challenge = challenge
	return nil
}

func (store *handlerTOTPStore) FindChallenge(
	_ context.Context,
	hash totp.ChallengeHash,
) (totp.Challenge, totp.Credential, error) {
	if hash != store.challenge.TokenHash {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	}
	return store.challenge, totp.Credential{
		SubjectID: store.challenge.SubjectID,
		Secret:    store.secret,
		EnabledAt: store.challenge.CreatedAt,
	}, nil
}

func (store *handlerTOTPStore) CompleteCode(
	_ context.Context,
	hash totp.ChallengeHash,
	_ uint64,
	completedAt time.Time,
) (string, error) {
	if hash != store.challenge.TokenHash || !completedAt.Before(store.challenge.ExpiresAt) {
		return "", totp.ErrInactiveChallenge
	}
	subjectID := store.challenge.SubjectID
	store.challenge = totp.Challenge{}
	return subjectID, nil
}

func (store *handlerTOTPStore) CompleteRecovery(
	context.Context,
	totp.ChallengeHash,
	totp.RecoveryCodeHash,
	time.Time,
) (string, error) {
	return "", totp.ErrInvalidCode
}
