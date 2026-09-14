// Package googleoauth provides Google Authorization Code flow orchestration.
package googleoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
)

var (
	ErrConflict       = errors.New("Google identity is linked to another user")
	ErrInvalidConfig  = errors.New("invalid Google OAuth configuration")
	ErrInvalidInput   = errors.New("invalid Google OAuth input")
	ErrInvalidRecord  = errors.New("invalid Google OAuth record")
	ErrInvalidState   = errors.New("invalid or expired OAuth state")
	ErrLastCredential = errors.New("cannot remove the last sign-in method")
	ErrLinkRequired   = errors.New("existing user must authenticate before linking Google")
	ErrNotFound       = errors.New("Google OAuth record not found")
	ErrUnverified     = errors.New("Google identity email is not verified")
)

type Challenge struct {
	StateHash    [32]byte
	Nonce        string
	CodeVerifier string
	SubjectID    string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type Identity struct {
	ProviderSubject string
	Email           string
	EmailVerified   bool
	Nonce           string
}

type User struct {
	ID string
}

type IdentityResolution struct {
	ProviderSubject string
	Email           string
	SubjectID       string
}

type LinkedIdentity struct {
	ProviderSubject string
	Email           string
	LinkedAt        time.Time
}

type Store interface {
	CreateChallenge(ctx context.Context, challenge Challenge) error
	ConsumeChallenge(ctx context.Context, stateHash [32]byte, consumedAt time.Time) (Challenge, error)
	// ResolveIdentity finds, links, or creates a user atomically. ProviderSubject
	// is the permanent account key; an existing unlinked email returns ErrLinkRequired.
	ResolveIdentity(ctx context.Context, resolution IdentityResolution) (User, error)
}

// IdentityStore must atomically refuse removal of the user's last sign-in method.
type IdentityStore interface {
	ListIdentities(ctx context.Context, subjectID string) ([]LinkedIdentity, error)
	UnlinkIdentity(ctx context.Context, subjectID, providerSubject string, unlinkedAt time.Time) error
}

type ExchangeInput struct {
	Code         string
	CodeVerifier string
	RedirectURL  string
	Audience     string
}

// Provider verifies the Google ID token signature, issuer, audience, and expiry.
type Provider interface {
	Exchange(ctx context.Context, input ExchangeInput) (Identity, error)
}

type EventType string

const EventUnlinked EventType = "google_unlinked"

type SecurityEvent struct {
	Type       EventType
	SubjectID  string
	SourceKey  string
	OccurredAt time.Time
}

type SecurityEventSink interface {
	Record(ctx context.Context, event SecurityEvent)
}

type Config struct {
	ClientID         string
	AuthorizationURL string
	RedirectURL      string
	StateLifetime    time.Duration
	Identities       IdentityStore
	SecurityEvents   SecurityEventSink
	Now              func() time.Time
}

type Manager struct {
	store            Store
	identities       IdentityStore
	provider         Provider
	clientID         string
	authorizationURL url.URL
	redirectURL      string
	lifetime         time.Duration
	securityEvents   SecurityEventSink
	now              func() time.Time
}

type Started struct {
	AuthorizationURL string
	State            string
}

func NewManager(store Store, provider Provider, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if provider == nil {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidConfig)
	}
	clientID := strings.TrimSpace(config.ClientID)
	if clientID == "" {
		return nil, fmt.Errorf("%w: client ID is required", ErrInvalidConfig)
	}
	authorizationURL, err := parseURL(config.AuthorizationURL, true)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid authorization URL", ErrInvalidConfig)
	}
	redirectURL, err := parseURL(config.RedirectURL, false)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid redirect URL", ErrInvalidConfig)
	}
	if config.StateLifetime <= 0 {
		return nil, fmt.Errorf("%w: state lifetime must be positive", ErrInvalidConfig)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	identities := config.Identities
	if identities == nil {
		identities, _ = store.(IdentityStore)
	}
	return &Manager{
		store:            store,
		identities:       identities,
		provider:         provider,
		clientID:         clientID,
		authorizationURL: *authorizationURL,
		redirectURL:      redirectURL.String(),
		lifetime:         config.StateLifetime,
		securityEvents:   config.SecurityEvents,
		now:              now,
	}, nil
}

func (manager *Manager) Unlink(
	ctx context.Context,
	subjectID string,
	providerSubject string,
	sourceKey string,
) error {
	if manager.identities == nil {
		return fmt.Errorf("%w: identity store is required", ErrInvalidConfig)
	}
	subjectID = strings.TrimSpace(subjectID)
	providerSubject = strings.TrimSpace(providerSubject)
	if subjectID == "" || providerSubject == "" {
		return ErrInvalidInput
	}
	if err := manager.identities.UnlinkIdentity(
		ctx,
		subjectID,
		providerSubject,
		manager.now().UTC(),
	); err != nil {
		if errors.Is(err, ErrLastCredential) || errors.Is(err, ErrNotFound) {
			return err
		}
		return fmt.Errorf("unlink Google identity: %w", err)
	}
	manager.record(ctx, EventUnlinked, subjectID, sourceKey)
	return nil
}

func (manager *Manager) List(ctx context.Context, subjectID string) ([]LinkedIdentity, error) {
	if manager.identities == nil {
		return nil, fmt.Errorf("%w: identity store is required", ErrInvalidConfig)
	}
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, ErrInvalidInput
	}
	identities, err := manager.identities.ListIdentities(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("list Google identities: %w", err)
	}
	for _, identity := range identities {
		if strings.TrimSpace(identity.ProviderSubject) == "" ||
			strings.TrimSpace(identity.Email) == "" || identity.LinkedAt.IsZero() {
			return nil, ErrInvalidRecord
		}
	}
	return identities, nil
}

func (manager *Manager) Begin(ctx context.Context, subjectID string) (Started, error) {
	state, err := randomString()
	if err != nil {
		return Started{}, fmt.Errorf("generate OAuth state: %w", err)
	}
	nonce, err := randomString()
	if err != nil {
		return Started{}, fmt.Errorf("generate OAuth nonce: %w", err)
	}
	codeVerifier, err := randomString()
	if err != nil {
		return Started{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	now := manager.now().UTC()
	challenge := Challenge{
		StateHash:    hash(state),
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		SubjectID:    strings.TrimSpace(subjectID),
		CreatedAt:    now,
		ExpiresAt:    now.Add(manager.lifetime),
	}
	if err := manager.store.CreateChallenge(ctx, challenge); err != nil {
		return Started{}, fmt.Errorf("store OAuth challenge: %w", err)
	}

	authorizationURL := manager.authorizationURL
	query := authorizationURL.Query()
	query.Set("client_id", manager.clientID)
	query.Set("redirect_uri", manager.redirectURL)
	query.Set("response_type", "code")
	query.Set("scope", "openid email profile")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", pkceChallenge(codeVerifier))
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()

	return Started{AuthorizationURL: authorizationURL.String(), State: state}, nil
}

func (manager *Manager) Complete(ctx context.Context, state, code string) (User, error) {
	state = strings.TrimSpace(state)
	code = strings.TrimSpace(code)
	if state == "" || code == "" {
		return User{}, ErrInvalidState
	}

	stateHash := hash(state)
	now := manager.now().UTC()
	challenge, err := manager.store.ConsumeChallenge(ctx, stateHash, now)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidState) {
		return User{}, ErrInvalidState
	}
	if err != nil {
		return User{}, fmt.Errorf("consume OAuth challenge: %w", err)
	}
	if !validChallenge(challenge, stateHash, now) {
		return User{}, ErrInvalidRecord
	}

	identity, err := manager.provider.Exchange(ctx, ExchangeInput{
		Code:         code,
		CodeVerifier: challenge.CodeVerifier,
		RedirectURL:  manager.redirectURL,
		Audience:     manager.clientID,
	})
	if err != nil {
		return User{}, fmt.Errorf("exchange Google authorization code: %w", err)
	}
	if identity.Nonce != challenge.Nonce {
		return User{}, ErrInvalidState
	}
	providerSubject := strings.TrimSpace(identity.ProviderSubject)
	if providerSubject == "" {
		return User{}, ErrInvalidRecord
	}
	if !identity.EmailVerified {
		return User{}, ErrUnverified
	}
	normalizedEmail, err := emailaddress.Normalize(identity.Email)
	if err != nil {
		return User{}, ErrInvalidRecord
	}

	user, err := manager.store.ResolveIdentity(ctx, IdentityResolution{
		ProviderSubject: providerSubject,
		Email:           normalizedEmail,
		SubjectID:       challenge.SubjectID,
	})
	if err != nil {
		return User{}, fmt.Errorf("resolve Google identity: %w", err)
	}
	if strings.TrimSpace(user.ID) == "" {
		return User{}, ErrInvalidRecord
	}
	return user, nil
}

func parseURL(rawURL string, requireHTTPS bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if requireHTTPS && parsed.Scheme != "https" {
		return nil, ErrInvalidConfig
	}
	if !requireHTTPS && parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, ErrInvalidConfig
	}
	return parsed, nil
}

func validChallenge(challenge Challenge, stateHash [32]byte, now time.Time) bool {
	return challenge.StateHash == stateHash &&
		strings.TrimSpace(challenge.Nonce) != "" &&
		strings.TrimSpace(challenge.CodeVerifier) != "" &&
		!challenge.CreatedAt.IsZero() &&
		challenge.ExpiresAt.After(challenge.CreatedAt) &&
		now.Before(challenge.ExpiresAt)
}

func randomString() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func hash(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func pkceChallenge(codeVerifier string) string {
	digest := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (manager *Manager) record(
	ctx context.Context,
	eventType EventType,
	subjectID string,
	sourceKey string,
) {
	if manager.securityEvents == nil {
		return
	}
	manager.securityEvents.Record(ctx, SecurityEvent{
		Type:       eventType,
		SubjectID:  subjectID,
		SourceKey:  sourceKey,
		OccurredAt: manager.now().UTC(),
	})
}
