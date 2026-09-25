package authlier

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/password"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/Rahmannugar/authlier/sessiontoken"
)

func TestEmailVerificationRoutesCompleteTheIssuedToken(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	store := &verificationStore{user: emailverification.User{
		ID: "user_123", Email: "owner@example.com",
	}}
	sender := &verificationSender{}
	manager, err := emailverification.NewManager(store, emailverification.Config{
		Lifetime: time.Hour,
		Sender:   sender,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create email verification manager: %v", err)
	}
	handler := newEmailHandler(t, manager, nil, newSessionStore(now))

	request := newAuthRequest("/api/auth/resend-verification", `{"email":"owner@example.com"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || sender.token == "" {
		t.Fatalf("request verification: status=%d token=%q", response.Code, sender.token)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/auth/verify-email?token="+sender.token, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("verify email: status=%d body=%s", response.Code, response.Body.String())
	}
	if !store.user.Verified {
		t.Fatal("email was not marked verified")
	}
}

func TestPasswordResetRouteRevokesExistingSessions(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	store := &resetStore{user: passwordreset.User{ID: "user_123", Email: "owner@example.com"}}
	sender := &resetSender{}
	manager, err := passwordreset.NewManager(store, passwordreset.Config{
		Lifetime:  time.Hour,
		Sender:    sender,
		Passwords: resetHasher{},
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create password reset manager: %v", err)
	}
	sessions := newSessionStore(now)
	handler := newEmailHandler(t, nil, manager, sessions)

	request := newAuthRequest("/api/auth/forgot-password", `{"email":"owner@example.com"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || sender.token == "" {
		t.Fatalf("request password reset: status=%d token=%q", response.Code, sender.token)
	}

	request = newAuthRequest(
		"/api/auth/reset-password",
		`{"token":"`+sender.token+`","newPassword":"a new password"}`,
	)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("reset password: status=%d body=%s", response.Code, response.Body.String())
	}
	if store.passwordHash != "hashed:a new password" || !sessions.revokedAll {
		t.Fatalf("reset result: hash=%q revoked=%t", store.passwordHash, sessions.revokedAll)
	}
}

func TestRequiredEmailVerificationControlsSessionCreation(t *testing.T) {
	accounts := &authenticationStore{}
	sender := &verificationSender{}
	sessions := newSessionStore(time.Now().UTC())
	database := handlerDatabase{stores: Stores{
		EmailPassword:     accounts,
		EmailVerification: accounts,
		Sessions:          sessions,
	}}
	auth, err := New(Config{
		AppName:  "Acme",
		BaseURL:  "https://app.example.com",
		Database: database,
		EmailAndPassword: EmailAndPasswordConfig{
			Enabled:                  true,
			RequireEmailVerification: true,
		},
		EmailVerification: EmailVerificationConfig{
			Enabled:                     true,
			Lifetime:                    time.Hour,
			Sender:                      sender,
			SendOnSignIn:                true,
			AutoSignInAfterVerification: true,
		},
		Session: SessionConfig{Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-up",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	if response.Code != http.StatusCreated || sender.token == "" ||
		sender.url != "https://app.example.com/api/auth/verify-email?token="+sender.token ||
		sessions.created != 0 {
		t.Fatalf("sign up: status=%d token=%q url=%q sessions=%d", response.Code, sender.token, sender.url, sessions.created)
	}

	response = httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-in",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	if response.Code != http.StatusForbidden || sessions.created != 0 {
		t.Fatalf("unverified sign in: status=%d sessions=%d", response.Code, sessions.created)
	}

	response = httptest.NewRecorder()
	auth.Handler().ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/api/auth/verify-email?token="+sender.token, nil),
	)
	if response.Code != http.StatusOK || sessions.created != 1 {
		t.Fatalf("verify email: status=%d sessions=%d body=%s", response.Code, sessions.created, response.Body.String())
	}
}

func TestRequiredEmailOTPVerificationControlsSessionCreation(t *testing.T) {
	accounts := &authenticationStore{}
	sender := &verificationSender{}
	sessions := newSessionStore(time.Now().UTC())
	database := handlerDatabase{stores: Stores{
		EmailPassword:     accounts,
		EmailVerification: accounts,
		Sessions:          sessions,
	}}
	auth, err := New(Config{
		AppName: "Acme", BaseURL: "https://app.example.com", Database: database,
		EmailAndPassword: EmailAndPasswordConfig{
			Enabled: true, RequireEmailVerification: true,
		},
		EmailVerification: EmailVerificationConfig{
			Enabled:                     true,
			Delivery:                    emailverification.DeliveryMethodOTP,
			OTPSecret:                   []byte("0123456789abcdef0123456789abcdef"),
			Sender:                      sender,
			SendOnSignUp:                true,
			AutoSignInAfterVerification: true,
			AttemptGuard:                allowVerificationAttempts{},
		},
	})
	if err != nil {
		t.Fatalf("create Authlier with email OTP: %v", err)
	}

	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-up",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	if response.Code != http.StatusCreated || len(sender.code) != 6 || sender.token != "" ||
		sender.url != "" || sessions.created != 0 {
		t.Fatalf(
			"sign up: status=%d code=%q token=%q url=%q sessions=%d",
			response.Code, sender.code, sender.token, sender.url, sessions.created,
		)
	}

	response = httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/verify-email",
		`{"email":"owner@example.com","code":"`+sender.code+`"}`,
	))
	if response.Code != http.StatusOK || sessions.created != 1 {
		t.Fatalf("verify OTP: status=%d sessions=%d body=%s", response.Code, sessions.created, response.Body.String())
	}
}

func TestEmailOTPVerificationRejectsGETRoute(t *testing.T) {
	accounts := &authenticationStore{}
	auth, err := New(Config{
		AppName: "Acme", BaseURL: "https://app.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword: accounts, EmailVerification: accounts,
			Sessions: newSessionStore(time.Now().UTC()),
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		EmailVerification: EmailVerificationConfig{
			Enabled: true, Delivery: emailverification.DeliveryMethodOTP,
			OTPSecret: []byte("0123456789abcdef0123456789abcdef"),
			Sender:    &verificationSender{}, AttemptGuard: allowVerificationAttempts{},
		},
	})
	if err != nil {
		t.Fatalf("create Authlier with email OTP: %v", err)
	}
	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/api/auth/verify-email?token=unused", nil),
	)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET OTP verification status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestConfiguredBcryptHashesNewPasswords(t *testing.T) {
	accounts := &authenticationStore{}
	database := handlerDatabase{stores: Stores{
		EmailPassword: accounts,
		Sessions:      newSessionStore(time.Now().UTC()),
	}}
	auth, err := New(Config{
		AppName:  "Acme",
		BaseURL:  "https://app.example.com",
		Database: database,
		EmailAndPassword: EmailAndPasswordConfig{
			Enabled:               true,
			PasswordHashAlgorithm: password.Bcrypt,
		},
		Session: SessionConfig{Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatalf("create Authlier with bcrypt: %v", err)
	}

	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-up",
		`{"email":"owner@example.com","password":"correct horse battery staple"}`,
	))
	if response.Code != http.StatusCreated {
		t.Fatalf("sign up: status=%d body=%s", response.Code, response.Body.String())
	}
	verification, err := password.VerifyWithAlgorithm(
		"correct horse battery staple",
		accounts.passwordHash,
		password.Bcrypt,
	)
	if err != nil || !verification.Matches || verification.NeedsRehash {
		t.Fatalf("password was not stored as current bcrypt: verification=%+v err=%v", verification, err)
	}
}

func TestConfiguredBcryptRejectsPasswordsBeyondItsInputLimit(t *testing.T) {
	accounts := &authenticationStore{}
	database := handlerDatabase{stores: Stores{
		EmailPassword: accounts,
		Sessions:      newSessionStore(time.Now().UTC()),
	}}
	auth, err := New(Config{
		AppName:  "Acme",
		BaseURL:  "https://app.example.com",
		Database: database,
		EmailAndPassword: EmailAndPasswordConfig{
			Enabled:               true,
			PasswordHashAlgorithm: password.Bcrypt,
		},
		Session: SessionConfig{Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatalf("create Authlier with bcrypt: %v", err)
	}

	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/sign-up",
		`{"email":"owner@example.com","password":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	))
	if response.Code != http.StatusBadRequest || accounts.user.ID != "" ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"code":"invalid_request"`)) {
		t.Fatalf("long bcrypt password: status=%d user=%+v body=%s", response.Code, accounts.user, response.Body.String())
	}
}

func TestConfiguredBcryptHashesPasswordRecovery(t *testing.T) {
	accounts := &authenticationStore{}
	resets := &resetStore{user: passwordreset.User{ID: "user_123", Email: "owner@example.com"}}
	sender := &resetSender{}
	database := handlerDatabase{stores: Stores{
		EmailPassword: accounts,
		PasswordReset: resets,
		Sessions:      newSessionStore(time.Now().UTC()),
	}}
	auth, err := New(Config{
		AppName:  "Acme",
		BaseURL:  "https://app.example.com",
		Database: database,
		EmailAndPassword: EmailAndPasswordConfig{
			Enabled:               true,
			PasswordHashAlgorithm: password.Bcrypt,
		},
		PasswordReset: PasswordResetConfig{
			Enabled: true,
			Sender:  sender,
		},
		Session: SessionConfig{Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatalf("create Authlier with bcrypt recovery: %v", err)
	}

	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/forgot-password",
		`{"email":"owner@example.com"}`,
	))
	if response.Code != http.StatusAccepted || sender.token == "" {
		t.Fatalf("request password reset: status=%d token=%q", response.Code, sender.token)
	}
	response = httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, newAuthRequest(
		"/api/auth/reset-password",
		`{"token":"`+sender.token+`","newPassword":"a new password"}`,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("reset password: status=%d body=%s", response.Code, response.Body.String())
	}
	verification, err := password.VerifyWithAlgorithm("a new password", resets.passwordHash, password.Bcrypt)
	if err != nil || !verification.Matches || verification.NeedsRehash {
		t.Fatalf("reset password was not stored as current bcrypt: verification=%+v err=%v", verification, err)
	}
}

func TestUnsupportedPasswordHashAlgorithmIsRejected(t *testing.T) {
	_, err := New(Config{
		AppName:  "Acme",
		BaseURL:  "https://app.example.com",
		Database: handlerDatabase{},
		EmailAndPassword: EmailAndPasswordConfig{
			Enabled:               true,
			PasswordHashAlgorithm: password.Algorithm("unsupported"),
		},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unsupported password hash algorithm: got %v, want invalid config", err)
	}
}

func newEmailHandler(
	t *testing.T,
	verification *emailverification.Manager,
	reset *passwordreset.Manager,
	store *handlerSessionStore,
) http.Handler {
	t.Helper()
	sessions, err := sessiontoken.NewManager(store, nil, sessiontoken.Config{Lifetime: time.Hour})
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	auth := &Auth{
		emailVerification:             verification,
		passwordReset:                 reset,
		sessions:                      sessions,
		revokeSessionsOnPasswordReset: reset != nil,
	}
	baseURL, err := url.Parse("https://app.example.com")
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	handler, err := newHandler(auth, Config{}, baseURL, "/api/auth", "/api/account")
	if err != nil {
		t.Fatalf("create HTTP handler: %v", err)
	}
	return handler
}

func newAuthRequest(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	request.Header.Set("Origin", "https://app.example.com")
	return request
}

type verificationStore struct {
	user   emailverification.User
	record emailverification.Record
	used   bool
}

func (store *verificationStore) FindUserByEmail(
	_ context.Context,
	email string,
) (emailverification.User, error) {
	if store.user.Email != email {
		return emailverification.User{}, emailverification.ErrNotFound
	}
	return store.user, nil
}

func (store *verificationStore) Issue(_ context.Context, record emailverification.Record) error {
	store.record = record
	store.used = false
	return nil
}

func (store *verificationStore) Verify(
	_ context.Context,
	hash emailverification.TokenHash,
	verifiedAt time.Time,
) (emailverification.User, error) {
	if store.used || hash != store.record.TokenHash || !verifiedAt.Before(store.record.ExpiresAt) {
		return emailverification.User{}, emailverification.ErrNotFound
	}
	store.used = true
	store.user.Verified = true
	return store.user, nil
}

type verificationSender struct {
	token string
	code  string
	url   string
}

func (sender *verificationSender) SendVerification(
	_ context.Context,
	message emailverification.Message,
) error {
	sender.token = message.Token
	sender.code = message.Code
	sender.url = message.URL
	return nil
}

type allowVerificationAttempts struct{}

func (allowVerificationAttempts) Check(context.Context, emailverification.Attempt) error { return nil }

type resetStore struct {
	user         passwordreset.User
	record       passwordreset.Record
	passwordHash string
	used         bool
}

func (store *resetStore) FindUserByEmail(
	_ context.Context,
	email string,
) (passwordreset.User, error) {
	if store.user.Email != email {
		return passwordreset.User{}, passwordreset.ErrNotFound
	}
	return store.user, nil
}

func (store *resetStore) Issue(_ context.Context, record passwordreset.Record) error {
	store.record = record
	store.used = false
	return nil
}

func (store *resetStore) ResetPassword(
	_ context.Context,
	hash passwordreset.TokenHash,
	passwordHash string,
	resetAt time.Time,
) (passwordreset.User, error) {
	if store.used || hash != store.record.TokenHash || !resetAt.Before(store.record.ExpiresAt) {
		return passwordreset.User{}, passwordreset.ErrNotFound
	}
	store.used = true
	store.passwordHash = passwordHash
	return store.user, nil
}

type resetSender struct {
	token string
}

func (sender *resetSender) SendPasswordReset(
	_ context.Context,
	message passwordreset.Message,
) error {
	sender.token = message.Token
	return nil
}

type resetHasher struct{}

func (resetHasher) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

type handlerSessionStore struct {
	record     sessiontoken.Record
	revokedAll bool
	created    int
}

func newSessionStore(now time.Time) *handlerSessionStore {
	return &handlerSessionStore{record: sessiontoken.Record{
		ID:        "01994f4e-0000-7000-8000-000000000001",
		SubjectID: "user_123",
		TokenHash: sessiontoken.TokenHash{1},
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}}
}

func (store *handlerSessionStore) Create(_ context.Context, record sessiontoken.Record) error {
	store.record = record
	store.created++
	return nil
}

type handlerDatabase struct {
	stores Stores
}

func (database handlerDatabase) Migrate(context.Context) error {
	return nil
}

func (database handlerDatabase) Stores() Stores {
	return database.stores
}

type authenticationStore struct {
	user         emailpassword.User
	passwordHash string
	verification emailverification.Record
	verified     bool
}

func (store *authenticationStore) Register(
	_ context.Context,
	registration emailpassword.Registration,
) (emailpassword.User, error) {
	if store.user.ID != "" {
		return emailpassword.User{}, emailpassword.ErrConflict
	}
	store.user = emailpassword.User{ID: "user_123", Email: registration.Email}
	store.passwordHash = registration.PasswordHash
	return store.user, nil
}

func (store *authenticationStore) FindByEmail(
	_ context.Context,
	email string,
) (emailpassword.User, emailpassword.PasswordCredential, error) {
	if store.user.Email != email {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
	}
	return store.user, emailpassword.PasswordCredential{
		UserID: store.user.ID, PasswordHash: store.passwordHash,
	}, nil
}

func (store *authenticationStore) ReplacePasswordHash(
	_ context.Context,
	userID string,
	currentHash string,
	replacementHash string,
	_ time.Time,
) error {
	if userID != store.user.ID || currentHash != store.passwordHash {
		return emailpassword.ErrConflict
	}
	store.passwordHash = replacementHash
	return nil
}

func (store *authenticationStore) FindBySubject(
	_ context.Context,
	subjectID string,
) (emailpassword.User, emailpassword.PasswordCredential, error) {
	if subjectID != store.user.ID {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
	}
	return store.user, emailpassword.PasswordCredential{
		UserID: store.user.ID, PasswordHash: store.passwordHash,
	}, nil
}

func (store *authenticationStore) AddPassword(
	context.Context,
	string,
	string,
	time.Time,
) (emailpassword.User, error) {
	return emailpassword.User{}, errors.New("unexpected AddPassword call")
}

func (store *authenticationStore) RemovePassword(
	context.Context,
	string,
	string,
	time.Time,
) error {
	return errors.New("unexpected RemovePassword call")
}

func (store *authenticationStore) FindUserByEmail(
	_ context.Context,
	email string,
) (emailverification.User, error) {
	if store.user.Email != email {
		return emailverification.User{}, emailverification.ErrNotFound
	}
	return emailverification.User{
		ID: store.user.ID, Email: store.user.Email, Verified: store.verified,
	}, nil
}

func (store *authenticationStore) Issue(_ context.Context, record emailverification.Record) error {
	store.verification = record
	return nil
}

func (store *authenticationStore) Verify(
	_ context.Context,
	hash emailverification.TokenHash,
	verifiedAt time.Time,
) (emailverification.User, error) {
	if hash != store.verification.TokenHash || !verifiedAt.Before(store.verification.ExpiresAt) {
		return emailverification.User{}, emailverification.ErrNotFound
	}
	store.verified = true
	return emailverification.User{ID: store.user.ID, Email: store.user.Email, Verified: true}, nil
}

func (store *handlerSessionStore) FindByTokenHash(
	_ context.Context,
	tokenHash sessiontoken.TokenHash,
) (sessiontoken.Record, error) {
	if tokenHash != store.record.TokenHash {
		return sessiontoken.Record{}, sessiontoken.ErrNotFound
	}
	return store.record, nil
}

func (store *handlerSessionStore) ListBySubject(context.Context, string) ([]sessiontoken.Record, error) {
	return []sessiontoken.Record{store.record}, nil
}

func (store *handlerSessionStore) Extend(
	context.Context,
	sessiontoken.TokenHash,
	time.Time,
	time.Time,
) (sessiontoken.Record, error) {
	return sessiontoken.Record{}, errors.New("not implemented")
}

func (store *handlerSessionStore) Rotate(
	context.Context,
	sessiontoken.TokenHash,
	sessiontoken.Record,
	time.Time,
) error {
	return errors.New("not implemented")
}

func (store *handlerSessionStore) Revoke(
	_ context.Context,
	tokenHash sessiontoken.TokenHash,
	revokedAt time.Time,
) error {
	if tokenHash != store.record.TokenHash {
		return sessiontoken.ErrNotFound
	}
	store.record.RevokedAt = &revokedAt
	return nil
}

func (store *handlerSessionStore) RevokeAll(
	_ context.Context,
	subjectID string,
	_ time.Time,
) ([]sessiontoken.Record, error) {
	if subjectID != store.record.SubjectID {
		return nil, sessiontoken.ErrNotFound
	}
	store.revokedAll = true
	return []sessiontoken.Record{store.record}, nil
}
