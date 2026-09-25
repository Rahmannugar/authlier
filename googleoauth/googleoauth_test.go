package googleoauth_test

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/googleoauth"
)

func TestAuthorizationCodeFlowUsesStateNonceAndPKCE(t *testing.T) {
	store := newStore()
	provider := &providerStub{}
	manager := newManager(t, store, provider)

	started, err := manager.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin Google authentication: %v", err)
	}
	authorizationURL, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	query := authorizationURL.Query()
	if query.Get("state") != started.State || query.Get("nonce") == "" ||
		query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL lacks security parameters: %s", started.AuthorizationURL)
	}
	challenge := store.challenge()
	provider.identity = googleoauth.Identity{
		ProviderSubject: "google-account-1",
		Email:           " OWNER@Example.COM ",
		EmailVerified:   true,
		Nonce:           challenge.Nonce,
	}

	user, err := manager.Complete(context.Background(), started.State, "authorization-code")
	if err != nil {
		t.Fatalf("complete Google authentication: %v", err)
	}
	if user.ID == "" {
		t.Fatal("Google authentication returned an empty user ID")
	}
	if provider.input.CodeVerifier != challenge.CodeVerifier ||
		provider.input.Audience != "client-id" ||
		provider.input.RedirectURL != "https://app.example.com/auth/google/callback" {
		t.Fatalf("provider received incomplete exchange input: %+v", provider.input)
	}
	resolution := store.resolution()
	if resolution.ProviderSubject != "google-account-1" || resolution.Email != "owner@example.com" {
		t.Fatalf("identity was not resolved by Google account ID: %+v", resolution)
	}
	if _, err := manager.Complete(context.Background(), started.State, "authorization-code"); !errors.Is(err, googleoauth.ErrInvalidState) {
		t.Fatalf("reuse OAuth state: got %v, want invalid state", err)
	}
}

func TestGoogleEmailChangeKeepsTheSameLinkedUser(t *testing.T) {
	store := newStore()
	provider := &providerStub{}
	manager := newManager(t, store, provider)

	first := beginWithProviderIdentity(t, manager, store, provider, googleoauth.Identity{
		ProviderSubject: "google-account-1",
		Email:           "old@example.com",
		EmailVerified:   true,
	})
	firstUser, err := manager.Complete(context.Background(), first.State, "first-code")
	if err != nil {
		t.Fatalf("complete first login: %v", err)
	}

	second := beginWithProviderIdentity(t, manager, store, provider, googleoauth.Identity{
		ProviderSubject: "google-account-1",
		Email:           "new@example.com",
		EmailVerified:   true,
	})
	secondUser, err := manager.Complete(context.Background(), second.State, "second-code")
	if err != nil {
		t.Fatalf("complete login after email change: %v", err)
	}
	if secondUser.ID != firstUser.ID {
		t.Fatalf("email change resolved user %q, want %q", secondUser.ID, firstUser.ID)
	}
}

func TestCompleteRejectsMismatchedNonce(t *testing.T) {
	store := newStore()
	provider := &providerStub{}
	manager := newManager(t, store, provider)
	started := beginWithProviderIdentity(t, manager, store, provider, googleoauth.Identity{
		ProviderSubject: "google-account-1",
		Email:           "owner@example.com",
		EmailVerified:   true,
		Nonce:           "attacker-nonce",
	})

	if _, err := manager.Complete(context.Background(), started.State, "authorization-code"); !errors.Is(err, googleoauth.ErrInvalidState) {
		t.Fatalf("complete with wrong nonce: got %v, want invalid state", err)
	}
	if store.resolveCalls() != 0 {
		t.Fatal("mismatched nonce reached identity storage")
	}
}

func TestUnlinkedExistingEmailRequiresAuthenticatedLinking(t *testing.T) {
	store := newStore()
	store.usersByEmail["owner@example.com"] = googleoauth.User{ID: "password-user"}
	provider := &providerStub{}
	manager := newManager(t, store, provider)
	started := beginWithProviderIdentity(t, manager, store, provider, googleoauth.Identity{
		ProviderSubject: "google-account-1",
		Email:           "owner@example.com",
		EmailVerified:   true,
	})

	if _, err := manager.Complete(context.Background(), started.State, "authorization-code"); !errors.Is(err, googleoauth.ErrLinkRequired) {
		t.Fatalf("complete for existing email: got %v, want link required", err)
	}

	linked, err := manager.Begin(context.Background(), "password-user")
	if err != nil {
		t.Fatalf("begin authenticated linking: %v", err)
	}
	provider.identity = googleoauth.Identity{
		ProviderSubject: "google-account-1",
		Email:           "owner@example.com",
		EmailVerified:   true,
		Nonce:           store.challenge().Nonce,
	}
	user, err := manager.Complete(context.Background(), linked.State, "authorization-code")
	if err != nil {
		t.Fatalf("link from authenticated user: %v", err)
	}
	if user.ID != "password-user" {
		t.Fatalf("linked user = %q, want password-user", user.ID)
	}
}

func TestChallengeStoreFailureRemainsOperationalError(t *testing.T) {
	store := newStore()
	provider := &providerStub{}
	manager := newManager(t, store, provider)
	started, err := manager.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin Google authentication: %v", err)
	}
	store.consumeErr = errors.New("database unavailable")

	_, err = manager.Complete(context.Background(), started.State, "authorization-code")
	if err == nil || errors.Is(err, googleoauth.ErrInvalidState) {
		t.Fatalf("challenge store failure was hidden: %v", err)
	}
}

func TestUnlinkRemovesTheGoogleAccount(t *testing.T) {
	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	store := newStore()
	events := &eventRecorder{}
	manager := newManagerWithConfig(t, store, &providerStub{}, googleoauth.Config{
		ClientID:         "client-id",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		RedirectURL:      "https://app.example.com/auth/google/callback",
		StateLifetime:    time.Minute,
		SecurityEvents:   events,
		Now:              func() time.Time { return now },
	})

	err := manager.Unlink(
		context.Background(),
		"user_123",
		"client:203.0.113.10",
	)
	if err != nil {
		t.Fatalf("unlink Google account: %v", err)
	}
	if store.unlinked.subjectID != "user_123" || !store.unlinked.at.Equal(now) {
		t.Fatalf("unexpected unlink request: %+v", store.unlinked)
	}
	if len(events.events) != 1 || events.events[0].Type != googleoauth.EventUnlinked ||
		events.events[0].SubjectID != "user_123" {
		t.Fatalf("unexpected security events: %+v", events.events)
	}
}

func TestUnlinkCannotRemoveTheLastSignInMethod(t *testing.T) {
	store := newStore()
	store.unlinkErr = googleoauth.ErrLastCredential
	manager := newManager(t, store, &providerStub{})

	err := manager.Unlink(context.Background(), "user_123", "")
	if !errors.Is(err, googleoauth.ErrLastCredential) {
		t.Fatalf("unlink last sign-in method: got %v, want last credential", err)
	}
}

func newManager(
	t *testing.T,
	store googleoauth.Store,
	provider googleoauth.Provider,
) *googleoauth.Manager {
	t.Helper()
	return newManagerWithConfig(t, store, provider, googleoauth.Config{
		ClientID:         "client-id",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth?prompt=select_account",
		RedirectURL:      "https://app.example.com/auth/google/callback",
		StateLifetime:    time.Minute,
	})
}

func newManagerWithConfig(
	t *testing.T,
	store googleoauth.Store,
	provider googleoauth.Provider,
	config googleoauth.Config,
) *googleoauth.Manager {
	t.Helper()
	manager, err := googleoauth.NewManager(store, provider, config)
	if err != nil {
		t.Fatalf("create Google OAuth manager: %v", err)
	}
	return manager
}

func beginWithProviderIdentity(
	t *testing.T,
	manager *googleoauth.Manager,
	store *memoryStore,
	provider *providerStub,
	identity googleoauth.Identity,
) googleoauth.Started {
	t.Helper()
	started, err := manager.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin Google authentication: %v", err)
	}
	if identity.Nonce == "" {
		identity.Nonce = store.challenge().Nonce
	}
	provider.identity = identity
	return started
}

type providerStub struct {
	identity googleoauth.Identity
	input    googleoauth.ExchangeInput
}

func (provider *providerStub) Exchange(
	_ context.Context,
	input googleoauth.ExchangeInput,
) (googleoauth.Identity, error) {
	provider.input = input
	return provider.identity, nil
}

type memoryStore struct {
	mu              sync.Mutex
	challenges      map[[32]byte]googleoauth.Challenge
	latestState     [32]byte
	identities      map[string]googleoauth.User
	usersByEmail    map[string]googleoauth.User
	lastResolution  googleoauth.IdentityResolution
	resolutionCalls int
	consumeErr      error
	unlinked        unlinkRequest
	unlinkErr       error
	nextUser        int
}

type unlinkRequest struct {
	subjectID string
	at        time.Time
}

func newStore() *memoryStore {
	return &memoryStore{
		challenges:   make(map[[32]byte]googleoauth.Challenge),
		identities:   make(map[string]googleoauth.User),
		usersByEmail: make(map[string]googleoauth.User),
	}
}

func (store *memoryStore) CreateChallenge(
	_ context.Context,
	challenge googleoauth.Challenge,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.challenges[challenge.StateHash] = challenge
	store.latestState = challenge.StateHash
	return nil
}

func (store *memoryStore) ConsumeChallenge(
	_ context.Context,
	stateHash [32]byte,
	consumedAt time.Time,
) (googleoauth.Challenge, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.consumeErr != nil {
		return googleoauth.Challenge{}, store.consumeErr
	}
	challenge, exists := store.challenges[stateHash]
	if !exists || !consumedAt.Before(challenge.ExpiresAt) {
		return googleoauth.Challenge{}, googleoauth.ErrNotFound
	}
	delete(store.challenges, stateHash)
	return challenge, nil
}

func (store *memoryStore) ResolveIdentity(
	_ context.Context,
	resolution googleoauth.IdentityResolution,
) (googleoauth.User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.resolutionCalls++
	store.lastResolution = resolution

	if linked, exists := store.identities[resolution.ProviderSubject]; exists {
		if resolution.SubjectID != "" && resolution.SubjectID != linked.ID {
			return googleoauth.User{}, googleoauth.ErrConflict
		}
		return linked, nil
	}
	if resolution.SubjectID != "" {
		for _, linked := range store.identities {
			if linked.ID == resolution.SubjectID {
				return googleoauth.User{}, googleoauth.ErrConflict
			}
		}
		user := googleoauth.User{ID: resolution.SubjectID}
		store.identities[resolution.ProviderSubject] = user
		return user, nil
	}
	if _, exists := store.usersByEmail[resolution.Email]; exists {
		return googleoauth.User{}, googleoauth.ErrLinkRequired
	}
	store.nextUser++
	user := googleoauth.User{ID: "google-user-" + strconv.Itoa(store.nextUser)}
	store.identities[resolution.ProviderSubject] = user
	store.usersByEmail[resolution.Email] = user
	return user, nil
}

func (store *memoryStore) UnlinkIdentity(
	_ context.Context,
	subjectID string,
	unlinkedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.unlinked = unlinkRequest{
		subjectID: subjectID,
		at:        unlinkedAt,
	}
	return store.unlinkErr
}

func (store *memoryStore) challenge() googleoauth.Challenge {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.challenges[store.latestState]
}

func (store *memoryStore) resolution() googleoauth.IdentityResolution {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lastResolution
}

func (store *memoryStore) resolveCalls() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.resolutionCalls
}

type eventRecorder struct {
	events []googleoauth.SecurityEvent
}

func (recorder *eventRecorder) Record(_ context.Context, event googleoauth.SecurityEvent) {
	recorder.events = append(recorder.events, event)
}
