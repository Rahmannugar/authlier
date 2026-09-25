package authlier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
)

func TestBearerSessionsSupportNativeClientsAndRefreshReuseRevocation(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	accounts := &authenticationStore{}
	tokenSessions := newHandlerTokenStore()
	auth, err := New(Config{
		AppName: "Acme",
		BaseURL: "https://server.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword:  accounts,
			AccessSessions: tokenSessions,
			RefreshTokens:  tokenSessions,
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Session: SessionConfig{
			Mode: SessionModeBearer,
			Bearer: BearerSessionConfig{
				Audience: "acme-api", KeyID: "current", PrivateKey: privateKey,
				AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
			},
		},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	signUpRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/sign-up",
		bytes.NewBufferString(`{"email":"owner@example.com","password":"correct horse battery staple"}`),
	)
	signUp := httptest.NewRecorder()
	auth.Handler().ServeHTTP(signUp, signUpRequest)
	var created userResponse
	if err := json.Unmarshal(signUp.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode sign-up response: %v", err)
	}
	if signUp.Code != http.StatusCreated || created.Session == nil || created.Tokens == nil ||
		created.Tokens.AccessToken == "" || created.Tokens.RefreshToken == "" {
		t.Fatalf("sign up: status=%d response=%+v", signUp.Code, created)
	}
	if len(signUp.Result().Cookies()) != 0 {
		t.Fatal("bearer session response unexpectedly set a cookie")
	}

	sessionRequest := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	sessionRequest.Header.Set("Authorization", "Bearer "+created.Tokens.AccessToken)
	sessionResponseRecorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(sessionResponseRecorder, sessionRequest)
	if sessionResponseRecorder.Code != http.StatusOK {
		t.Fatalf("resolve bearer session: status=%d body=%s", sessionResponseRecorder.Code, sessionResponseRecorder.Body.String())
	}

	refreshRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/token/refresh",
		bytes.NewBufferString(`{"refreshToken":"`+created.Tokens.RefreshToken+`"}`),
	)
	refreshedResponse := httptest.NewRecorder()
	auth.Handler().ServeHTTP(refreshedResponse, refreshRequest)
	var refreshed sessionResponse
	if err := json.Unmarshal(refreshedResponse.Body.Bytes(), &refreshed); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if refreshedResponse.Code != http.StatusOK || refreshed.Tokens == nil ||
		refreshed.Tokens.RefreshToken == created.Tokens.RefreshToken {
		t.Fatalf("refresh: status=%d response=%+v", refreshedResponse.Code, refreshed)
	}

	reuseRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/token/refresh",
		bytes.NewBufferString(`{"refreshToken":"`+created.Tokens.RefreshToken+`"}`),
	)
	reused := httptest.NewRecorder()
	auth.Handler().ServeHTTP(reused, reuseRequest)
	if reused.Code != http.StatusUnauthorized {
		t.Fatalf("reuse refresh token: status=%d body=%s", reused.Code, reused.Body.String())
	}

	revokedRequest := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	revokedRequest.Header.Set("Authorization", "Bearer "+refreshed.Tokens.AccessToken)
	revoked := httptest.NewRecorder()
	auth.Handler().ServeHTTP(revoked, revokedRequest)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("resolve session after refresh reuse: status=%d", revoked.Code)
	}
}

func TestBearerSessionsRejectUntrustedBrowserOriginsAndAllowAuthorizationPreflight(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	tokenSessions := newHandlerTokenStore()
	auth, err := New(Config{
		AppName: "Acme",
		BaseURL: "https://server.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword:  &authenticationStore{},
			AccessSessions: tokenSessions,
			RefreshTokens:  tokenSessions,
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Session: SessionConfig{Mode: SessionModeBearer, Bearer: BearerSessionConfig{
			Audience: "acme-api", KeyID: "current", PrivateKey: privateKey,
		}},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	untrusted := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/sign-in",
		bytes.NewBufferString(`{"email":"owner@example.com","password":"password"}`),
	)
	untrusted.Header.Set("Origin", "https://malicious.example")
	untrustedResponse := httptest.NewRecorder()
	auth.Handler().ServeHTTP(untrustedResponse, untrusted)
	if untrustedResponse.Code != http.StatusForbidden {
		t.Fatalf("untrusted browser origin: status=%d", untrustedResponse.Code)
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/api/auth/session", nil)
	preflight.Header.Set("Origin", "https://server.example.com")
	preflightResponse := httptest.NewRecorder()
	auth.Handler().ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent ||
		preflightResponse.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization" {
		t.Fatalf("preflight: status=%d headers=%v", preflightResponse.Code, preflightResponse.Header())
	}
}

func TestBearerSignOutAcceptsRefreshTokenWhenAccessTokenCannotBeResolved(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	tokenSessions := newHandlerTokenStore()
	auth, err := New(Config{
		AppName: "Acme",
		BaseURL: "https://server.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword:  &authenticationStore{},
			AccessSessions: tokenSessions,
			RefreshTokens:  tokenSessions,
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Session: SessionConfig{Mode: SessionModeBearer, Bearer: BearerSessionConfig{
			Audience: "acme-api", KeyID: "current", PrivateKey: privateKey,
		}},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	issued, err := auth.bearerSessions.Create(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("create bearer session: %v", err)
	}
	signOutRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/sign-out",
		bytes.NewBufferString(`{"refreshToken":"`+issued.RefreshToken+`"}`),
	)
	signOutRequest.Header.Set("Authorization", "Bearer expired-or-invalid")
	signOut := httptest.NewRecorder()
	auth.Handler().ServeHTTP(signOut, signOutRequest)
	if signOut.Code != http.StatusNoContent {
		t.Fatalf("sign out: status=%d body=%s", signOut.Code, signOut.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	request.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("resolve revoked session: status=%d", response.Code)
	}
}

func TestBearerSessionConfigurationRequiresSigningAndStorageSettings(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	base := Config{
		AppName: "Acme",
		BaseURL: "https://server.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword: &authenticationStore{},
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Session: SessionConfig{Mode: SessionModeBearer, Bearer: BearerSessionConfig{
			Audience: "acme-api", KeyID: "current", PrivateKey: privateKey,
		}},
	}
	if _, err := New(base); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing bearer stores: got %v, want invalid config", err)
	}

	tokenSessions := newHandlerTokenStore()
	base.Database = handlerDatabase{stores: Stores{
		EmailPassword:  &authenticationStore{},
		AccessSessions: tokenSessions,
		RefreshTokens:  tokenSessions,
	}}
	base.Session.Bearer.PrivateKey = nil
	if _, err := New(base); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing signing key: got %v, want invalid config", err)
	}

	base.Session.Bearer.PrivateKey = privateKey
	base.Session.Bearer.RefreshTokenLifetime = 5 * time.Minute
	base.Session.Bearer.AccessTokenLifetime = 5 * time.Minute
	if _, err := New(base); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("non-longer refresh lifetime: got %v, want invalid config", err)
	}
}

func TestBearerSessionConfigurationRejectsBrowserProviderFlows(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	tokenSessions := newHandlerTokenStore()
	_, err = New(Config{
		AppName: "Acme",
		BaseURL: "https://server.example.com",
		Database: handlerDatabase{stores: Stores{
			EmailPassword:  &authenticationStore{},
			AccessSessions: tokenSessions,
			RefreshTokens:  tokenSessions,
		}},
		EmailAndPassword: EmailAndPasswordConfig{Enabled: true},
		Google: GoogleConfig{
			Enabled: true,
		},
		Session: SessionConfig{Mode: SessionModeBearer, Bearer: BearerSessionConfig{
			Audience: "acme-api", KeyID: "current", PrivateKey: privateKey,
		}},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("browser provider in bearer mode: got %v, want invalid config", err)
	}
}

type handlerTokenStore struct {
	mu       sync.Mutex
	sessions map[string]AccessSession
	tokens   map[refreshtoken.TokenHash]refreshtoken.Record
}

func newHandlerTokenStore() *handlerTokenStore {
	return &handlerTokenStore{
		sessions: make(map[string]AccessSession),
		tokens:   make(map[refreshtoken.TokenHash]refreshtoken.Record),
	}
}

func (store *handlerTokenStore) CreateSession(
	_ context.Context,
	session AccessSession,
	refreshToken refreshtoken.Record,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.sessions[session.ID]; exists {
		return errors.New("session conflict")
	}
	if _, exists := store.tokens[refreshToken.TokenHash]; exists {
		return refreshtoken.ErrConflict
	}
	store.sessions[session.ID] = session
	store.tokens[refreshToken.TokenHash] = refreshToken
	return nil
}

func (store *handlerTokenStore) ResolveSession(
	_ context.Context,
	sessionID string,
) (accesstoken.Session, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	session, exists := store.sessions[sessionID]
	if !exists || session.RevokedAt != nil || !time.Now().UTC().Before(session.ExpiresAt) {
		return accesstoken.Session{}, accesstoken.ErrInactiveSession
	}
	return accesstoken.Session{
		ID: session.ID, SubjectID: session.SubjectID,
		CreatedAt: session.CreatedAt, ExpiresAt: session.ExpiresAt,
	}, nil
}

func (store *handlerTokenStore) ListBySubject(
	_ context.Context,
	subjectID string,
) ([]AccessSession, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]AccessSession, 0)
	for _, session := range store.sessions {
		if session.SubjectID == subjectID {
			records = append(records, session)
		}
	}
	return records, nil
}

func (store *handlerTokenStore) Revoke(
	_ context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revokeSession(sessionID, revokedAt)
	return nil
}

func (store *handlerTokenStore) RevokeAll(
	_ context.Context,
	subjectID string,
	revokedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for sessionID, session := range store.sessions {
		if session.SubjectID == subjectID {
			store.revokeSession(sessionID, revokedAt)
		}
	}
	return nil
}

func (store *handlerTokenStore) Create(
	_ context.Context,
	record refreshtoken.Record,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.tokens[record.TokenHash]; exists {
		return refreshtoken.ErrConflict
	}
	store.tokens[record.TokenHash] = record
	return nil
}

func (store *handlerTokenStore) FindByTokenHash(
	_ context.Context,
	tokenHash refreshtoken.TokenHash,
) (refreshtoken.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.tokens[tokenHash]
	if !exists {
		return refreshtoken.Record{}, refreshtoken.ErrNotFound
	}
	return record, nil
}

func (store *handlerTokenStore) Rotate(
	_ context.Context,
	currentHash refreshtoken.TokenHash,
	replacement refreshtoken.Record,
	rotatedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.tokens[currentHash]
	if !exists {
		return refreshtoken.ErrNotFound
	}
	if current.RotatedAt != nil || current.RevokedAt != nil || !current.ActiveAt(rotatedAt) {
		store.revokeSession(current.SessionID, rotatedAt)
		return refreshtoken.ErrReuseDetected
	}
	if _, exists := store.tokens[replacement.TokenHash]; exists {
		return refreshtoken.ErrConflict
	}
	current.RotatedAt = &rotatedAt
	store.tokens[currentHash] = current
	store.tokens[replacement.TokenHash] = replacement
	return nil
}

func (store *handlerTokenStore) RevokeSession(
	_ context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revokeSession(sessionID, revokedAt)
	return nil
}

func (store *handlerTokenStore) revokeSession(sessionID string, revokedAt time.Time) {
	session, exists := store.sessions[sessionID]
	if exists && session.RevokedAt == nil {
		session.RevokedAt = &revokedAt
		store.sessions[sessionID] = session
	}
	for hash, record := range store.tokens {
		if record.SessionID == sessionID && record.RevokedAt == nil {
			record.RevokedAt = &revokedAt
			store.tokens[hash] = record
		}
	}
}

var _ AccessSessionStore = (*handlerTokenStore)(nil)
var _ refreshtoken.Store = (*handlerTokenStore)(nil)
