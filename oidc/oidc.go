// Package oidc provides OpenID Connect authentication orchestration.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
	"github.com/Rahmannugar/authlier/token"
	oidclibrary "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const challengeAttempts = 3

var (
	ErrAttemptBlocked  = errors.New("OIDC attempt blocked")
	ErrConflict        = errors.New("OIDC challenge conflict")
	ErrInactiveState   = errors.New("OIDC state is inactive")
	ErrInvalidConfig   = errors.New("invalid OIDC configuration")
	ErrInvalidIdentity = errors.New("invalid OIDC identity")
	ErrInvalidInput    = errors.New("invalid OIDC input")
	ErrInvalidRecord   = errors.New("invalid OIDC record")
	ErrInvalidState    = errors.New("invalid or expired OIDC state")
	ErrNotFound        = errors.New("OIDC record not found")
	ErrUnverifiedEmail = errors.New("OIDC email is not verified")
)

type StateHash token.Hash

type Connection struct {
	ID                   string
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	Scopes               []string
	RequireVerifiedEmail bool
}

type ConnectionSource interface {
	Find(ctx context.Context, connectionID string) (Connection, error)
}

type Challenge struct {
	StateHash            StateHash
	ConnectionID         string
	Issuer               string
	ClientID             string
	RedirectURL          string
	Scopes               []string
	RequireVerifiedEmail bool
	Nonce                string
	CodeVerifier         string
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

// Store creates and consumes each state in one operation.
type Store interface {
	CreateChallenge(ctx context.Context, challenge Challenge) error
	ConsumeChallenge(ctx context.Context, stateHash StateHash, consumedAt time.Time) (Challenge, error)
}

type Operation string

const (
	OperationBegin    Operation = "begin"
	OperationComplete Operation = "complete"
)

type Attempt struct {
	Operation    Operation
	ConnectionID string
	SourceKey    string
}

type AttemptGuard interface {
	Check(ctx context.Context, attempt Attempt) error
}

type EventType string

const (
	EventAuthenticationFailed    EventType = "oidc_authentication_failed"
	EventAuthenticationSucceeded EventType = "oidc_authentication_succeeded"
)

type SecurityEvent struct {
	Type            EventType
	ConnectionID    string
	ProviderSubject string
	SourceKey       string
	OccurredAt      time.Time
}

type SecurityEventSink interface {
	Record(ctx context.Context, event SecurityEvent)
}

type Config struct {
	StateLifetime  time.Duration
	HTTPClient     *http.Client
	AttemptGuard   AttemptGuard
	SecurityEvents SecurityEventSink
	Now            func() time.Time
}

type Manager struct {
	store          Store
	connections    ConnectionSource
	protocol       protocol
	lifetime       time.Duration
	attemptGuard   AttemptGuard
	securityEvents SecurityEventSink
	now            func() time.Time
}

type BeginInput struct {
	ConnectionID string
	SourceKey    string
}

type Started struct {
	AuthorizationURL string
	State            string
	ExpiresAt        time.Time
}

type CompleteInput struct {
	State     string
	Code      string
	SourceKey string
}

type Identity struct {
	ConnectionID    string
	Issuer          string
	ProviderSubject string
	Email           string
	EmailVerified   bool
	Name            string
}

func NewManager(store Store, connections ConnectionSource, config Config) (*Manager, error) {
	if store == nil || connections == nil {
		return nil, fmt.Errorf("%w: store and connections are required", ErrInvalidConfig)
	}
	if config.StateLifetime <= 0 {
		return nil, fmt.Errorf("%w: state lifetime must be positive", ErrInvalidConfig)
	}
	if config.HTTPClient == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", ErrInvalidConfig)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		store:          store,
		connections:    connections,
		protocol:       newOIDCProtocol(config.HTTPClient, now),
		lifetime:       config.StateLifetime,
		attemptGuard:   config.AttemptGuard,
		securityEvents: config.SecurityEvents,
		now:            now,
	}, nil
}

func (manager *Manager) Begin(ctx context.Context, input BeginInput) (Started, error) {
	connectionID := strings.TrimSpace(input.ConnectionID)
	if connectionID == "" {
		return Started{}, ErrInvalidInput
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation:    OperationBegin,
		ConnectionID: connectionID,
		SourceKey:    input.SourceKey,
	}); err != nil {
		return Started{}, err
	}
	connection, err := manager.findConnection(ctx, connectionID)
	if err != nil {
		return Started{}, err
	}

	for range challengeAttempts {
		state, stateHash, err := token.Generate()
		if err != nil {
			return Started{}, fmt.Errorf("generate OIDC state: %w", err)
		}
		nonce, _, err := token.Generate()
		if err != nil {
			return Started{}, fmt.Errorf("generate OIDC nonce: %w", err)
		}
		codeVerifier, _, err := token.Generate()
		if err != nil {
			return Started{}, fmt.Errorf("generate PKCE verifier: %w", err)
		}
		authorizationURL, err := manager.protocol.AuthorizationURL(
			ctx,
			connection,
			state,
			nonce,
			codeVerifier,
		)
		if err != nil {
			return Started{}, fmt.Errorf("create OIDC authorization URL: %w", err)
		}
		now := manager.now().UTC()
		challenge := Challenge{
			StateHash:            StateHash(stateHash),
			ConnectionID:         connection.ID,
			Issuer:               connection.Issuer,
			ClientID:             connection.ClientID,
			RedirectURL:          connection.RedirectURL,
			Scopes:               slices.Clone(connection.Scopes),
			RequireVerifiedEmail: connection.RequireVerifiedEmail,
			Nonce:                nonce,
			CodeVerifier:         codeVerifier,
			CreatedAt:            now,
			ExpiresAt:            now.Add(manager.lifetime),
		}
		if err := manager.store.CreateChallenge(ctx, challenge); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Started{}, fmt.Errorf("store OIDC challenge: %w", err)
		}
		return Started{
			AuthorizationURL: authorizationURL,
			State:            state,
			ExpiresAt:        challenge.ExpiresAt,
		}, nil
	}
	return Started{}, fmt.Errorf("create unique OIDC state: %w", ErrConflict)
}

func (manager *Manager) Complete(ctx context.Context, input CompleteInput) (Identity, error) {
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationComplete,
		SourceKey: input.SourceKey,
	}); err != nil {
		return Identity{}, err
	}
	stateHash, err := token.HashToken(strings.TrimSpace(input.State))
	if err != nil || strings.TrimSpace(input.Code) == "" {
		manager.record(ctx, EventAuthenticationFailed, "", "", input.SourceKey)
		return Identity{}, ErrInvalidState
	}
	now := manager.now().UTC()
	challenge, err := manager.store.ConsumeChallenge(ctx, StateHash(stateHash), now)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveState) {
		manager.record(ctx, EventAuthenticationFailed, "", "", input.SourceKey)
		return Identity{}, ErrInvalidState
	}
	if err != nil {
		return Identity{}, fmt.Errorf("consume OIDC challenge: %w", err)
	}
	if !validChallenge(challenge, StateHash(stateHash), now) {
		return Identity{}, ErrInvalidRecord
	}
	connection, err := manager.findConnection(ctx, challenge.ConnectionID)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidConfig) {
		return Identity{}, ErrInvalidState
	}
	if err != nil {
		return Identity{}, err
	}
	if !challengeMatchesConnection(challenge, connection) {
		return Identity{}, ErrInvalidState
	}

	providerIdentity, err := manager.protocol.Exchange(
		ctx,
		connection,
		strings.TrimSpace(input.Code),
		challenge.CodeVerifier,
	)
	if err != nil {
		return Identity{}, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	providerSubject := strings.TrimSpace(providerIdentity.ProviderSubject)
	if providerIdentity.Issuer != connection.Issuer ||
		providerIdentity.Nonce != challenge.Nonce || providerSubject == "" {
		manager.record(ctx, EventAuthenticationFailed, connection.ID, providerSubject, input.SourceKey)
		return Identity{}, ErrInvalidIdentity
	}
	email := ""
	if strings.TrimSpace(providerIdentity.Email) != "" {
		email, err = emailaddress.Normalize(providerIdentity.Email)
		if err != nil {
			return Identity{}, ErrInvalidIdentity
		}
	}
	if connection.RequireVerifiedEmail && (email == "" || !providerIdentity.EmailVerified) {
		manager.record(ctx, EventAuthenticationFailed, connection.ID, providerSubject, input.SourceKey)
		return Identity{}, ErrUnverifiedEmail
	}
	identity := Identity{
		ConnectionID:    connection.ID,
		Issuer:          connection.Issuer,
		ProviderSubject: providerSubject,
		Email:           email,
		EmailVerified:   providerIdentity.EmailVerified,
		Name:            strings.TrimSpace(providerIdentity.Name),
	}
	manager.record(ctx, EventAuthenticationSucceeded, connection.ID, providerSubject, input.SourceKey)
	return identity, nil
}

func (manager *Manager) findConnection(ctx context.Context, connectionID string) (Connection, error) {
	connection, err := manager.connections.Find(ctx, connectionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Connection{}, ErrNotFound
		}
		return Connection{}, fmt.Errorf("find OIDC connection: %w", err)
	}
	connection, err = normalizeConnection(connection)
	if err != nil || connection.ID != connectionID {
		return Connection{}, ErrInvalidConfig
	}
	return connection, nil
}

func (manager *Manager) checkAttempt(ctx context.Context, attempt Attempt) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, attempt); err != nil {
		return fmt.Errorf("check OIDC attempt: %w", err)
	}
	return nil
}

func (manager *Manager) record(
	ctx context.Context,
	eventType EventType,
	connectionID string,
	providerSubject string,
	sourceKey string,
) {
	if manager.securityEvents == nil {
		return
	}
	manager.securityEvents.Record(ctx, SecurityEvent{
		Type:            eventType,
		ConnectionID:    connectionID,
		ProviderSubject: providerSubject,
		SourceKey:       sourceKey,
		OccurredAt:      manager.now().UTC(),
	})
}

func normalizeConnection(connection Connection) (Connection, error) {
	connection.ID = strings.TrimSpace(connection.ID)
	connection.Issuer = strings.TrimSpace(connection.Issuer)
	connection.ClientID = strings.TrimSpace(connection.ClientID)
	connection.RedirectURL = strings.TrimSpace(connection.RedirectURL)
	if connection.ID == "" || connection.ClientID == "" ||
		!validIssuerURL(connection.Issuer) || !validRedirectURL(connection.RedirectURL) {
		return Connection{}, ErrInvalidConfig
	}
	if len(connection.Scopes) == 0 {
		connection.Scopes = []string{oidclibrary.ScopeOpenID, oidclibrary.ScopeEmail, oidclibrary.ScopeProfile}
	} else {
		seen := make(map[string]struct{}, len(connection.Scopes)+1)
		scopes := make([]string, 0, len(connection.Scopes)+1)
		for _, scope := range append([]string{oidclibrary.ScopeOpenID}, connection.Scopes...) {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				return Connection{}, ErrInvalidConfig
			}
			if _, exists := seen[scope]; exists {
				continue
			}
			seen[scope] = struct{}{}
			scopes = append(scopes, scope)
		}
		connection.Scopes = scopes
	}
	return connection, nil
}

func validIssuerURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return parsed.Scheme == "https"
}

func validRedirectURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}

func validEndpointURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.Scheme == "https"
}

func validChallenge(challenge Challenge, expectedHash StateHash, now time.Time) bool {
	return challenge.StateHash == expectedHash &&
		strings.TrimSpace(challenge.ConnectionID) != "" &&
		strings.TrimSpace(challenge.Issuer) != "" &&
		strings.TrimSpace(challenge.ClientID) != "" &&
		strings.TrimSpace(challenge.RedirectURL) != "" &&
		strings.TrimSpace(challenge.Nonce) != "" &&
		strings.TrimSpace(challenge.CodeVerifier) != "" &&
		!challenge.CreatedAt.IsZero() && challenge.ExpiresAt.After(challenge.CreatedAt) &&
		now.Before(challenge.ExpiresAt)
}

func challengeMatchesConnection(challenge Challenge, connection Connection) bool {
	return challenge.ConnectionID == connection.ID &&
		challenge.Issuer == connection.Issuer &&
		challenge.ClientID == connection.ClientID &&
		challenge.RedirectURL == connection.RedirectURL &&
		challenge.RequireVerifiedEmail == connection.RequireVerifiedEmail &&
		slices.Equal(challenge.Scopes, connection.Scopes)
}

type providerIdentity struct {
	Issuer          string
	ProviderSubject string
	Nonce           string
	Email           string
	EmailVerified   bool
	Name            string
}

type protocol interface {
	AuthorizationURL(
		ctx context.Context,
		connection Connection,
		state string,
		nonce string,
		codeVerifier string,
	) (string, error)
	Exchange(
		ctx context.Context,
		connection Connection,
		code string,
		codeVerifier string,
	) (providerIdentity, error)
}

type discoveredProvider struct {
	provider *oidclibrary.Provider
	endpoint oauth2.Endpoint
}

type oidcProtocol struct {
	httpClient *http.Client
	now        func() time.Time
	mu         sync.RWMutex
	providers  map[string]discoveredProvider
}

func newOIDCProtocol(httpClient *http.Client, now func() time.Time) *oidcProtocol {
	return &oidcProtocol{
		httpClient: httpClient,
		now:        now,
		providers:  make(map[string]discoveredProvider),
	}
}

func (oidc *oidcProtocol) AuthorizationURL(
	ctx context.Context,
	connection Connection,
	state string,
	nonce string,
	codeVerifier string,
) (string, error) {
	provider, err := oidc.provider(ctx, connection.Issuer)
	if err != nil {
		return "", err
	}
	config := oauthConfig(connection, provider.endpoint)
	return config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(codeVerifier),
	), nil
}

func (oidc *oidcProtocol) Exchange(
	ctx context.Context,
	connection Connection,
	code string,
	codeVerifier string,
) (providerIdentity, error) {
	provider, err := oidc.provider(ctx, connection.Issuer)
	if err != nil {
		return providerIdentity{}, err
	}
	ctx = oidclibrary.ClientContext(ctx, oidc.httpClient)
	config := oauthConfig(connection, provider.endpoint)
	oauthToken, err := config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(codeVerifier),
	)
	if err != nil {
		return providerIdentity{}, err
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return providerIdentity{}, ErrInvalidIdentity
	}
	idToken, err := provider.provider.Verifier(&oidclibrary.Config{
		ClientID: connection.ClientID,
		Now:      oidc.now,
	}).Verify(ctx, rawIDToken)
	if err != nil {
		return providerIdentity{}, ErrInvalidIdentity
	}
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(oauthToken.AccessToken); err != nil {
			return providerIdentity{}, ErrInvalidIdentity
		}
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return providerIdentity{}, ErrInvalidIdentity
	}
	return providerIdentity{
		Issuer:          idToken.Issuer,
		ProviderSubject: idToken.Subject,
		Nonce:           idToken.Nonce,
		Email:           claims.Email,
		EmailVerified:   claims.EmailVerified,
		Name:            claims.Name,
	}, nil
}

func (oidc *oidcProtocol) provider(ctx context.Context, issuer string) (discoveredProvider, error) {
	oidc.mu.RLock()
	provider, exists := oidc.providers[issuer]
	oidc.mu.RUnlock()
	if exists {
		return provider, nil
	}
	ctx = oidclibrary.ClientContext(ctx, oidc.httpClient)
	discovered, err := oidclibrary.NewProvider(ctx, issuer)
	if err != nil {
		return discoveredProvider{}, err
	}
	endpoint := discovered.Endpoint()
	if !validEndpointURL(endpoint.AuthURL) || !validEndpointURL(endpoint.TokenURL) {
		return discoveredProvider{}, ErrInvalidConfig
	}
	provider = discoveredProvider{provider: discovered, endpoint: endpoint}
	oidc.mu.Lock()
	if existing, found := oidc.providers[issuer]; found {
		provider = existing
	} else {
		oidc.providers[issuer] = provider
	}
	oidc.mu.Unlock()
	return provider, nil
}

func oauthConfig(connection Connection, endpoint oauth2.Endpoint) oauth2.Config {
	return oauth2.Config{
		ClientID:     connection.ClientID,
		ClientSecret: connection.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  connection.RedirectURL,
		Scopes:       slices.Clone(connection.Scopes),
	}
}
