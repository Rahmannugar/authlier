package oidc

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)

func TestAuthorizationFlowProtectsStateNonceAndPKCE(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections()
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)

	started, err := manager.Begin(context.Background(), BeginInput{
		ConnectionID: "company-sso",
		SourceKey:    "client:203.0.113.10",
	})
	if err != nil {
		t.Fatalf("begin OIDC authentication: %v", err)
	}
	if started.State == "" || provider.state != started.State ||
		provider.nonce == "" || provider.codeVerifier == "" {
		t.Fatalf("missing authorization protection: started=%+v provider=%+v", started, provider)
	}
	authorizationURL, err := url.Parse(started.AuthorizationURL)
	if err != nil || authorizationURL.Host != "idp.example.com" {
		t.Fatalf("invalid authorization URL: %q", started.AuthorizationURL)
	}
	challenge := store.latestChallenge()
	if challenge.Nonce != provider.nonce || challenge.CodeVerifier != provider.codeVerifier ||
		len(challenge.Scopes) != 3 || challenge.Scopes[0] != "openid" {
		t.Fatalf("unexpected stored challenge: %+v", challenge)
	}
	provider.identity = providerIdentity{
		Issuer:          "https://idp.example.com",
		ProviderSubject: "provider-user-1",
		Nonce:           challenge.Nonce,
		Email:           " OWNER@Example.COM ",
		EmailVerified:   true,
		Name:            "Owner",
	}

	identity, err := manager.Complete(context.Background(), CompleteInput{
		State:     started.State,
		Code:      "authorization-code",
		SourceKey: "client:203.0.113.10",
	})
	if err != nil {
		t.Fatalf("complete OIDC authentication: %v", err)
	}
	if identity.ConnectionID != "company-sso" ||
		identity.ProviderSubject != "provider-user-1" ||
		identity.Email != "owner@example.com" || provider.exchangeVerifier != challenge.CodeVerifier {
		t.Fatalf("unexpected verified identity: %+v", identity)
	}
	if _, err := manager.Complete(context.Background(), CompleteInput{
		State: started.State,
		Code:  "authorization-code",
	}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reuse OIDC state: got %v, want invalid state", err)
	}
}

func TestCompleteRejectsNonceMismatchAndUnverifiedRequiredEmail(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections()
	connection := connections.values["company-sso"]
	connection.RequireVerifiedEmail = true
	connections.values[connection.ID] = connection
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)

	started, err := manager.Begin(context.Background(), BeginInput{ConnectionID: connection.ID})
	if err != nil {
		t.Fatalf("begin OIDC authentication: %v", err)
	}
	provider.identity = providerIdentity{
		Issuer:          connection.Issuer,
		ProviderSubject: "provider-user-1",
		Nonce:           "wrong-nonce",
		Email:           "owner@example.com",
		EmailVerified:   true,
	}
	if _, err := manager.Complete(context.Background(), CompleteInput{
		State: started.State,
		Code:  "authorization-code",
	}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("complete with wrong nonce: got %v, want invalid identity", err)
	}

	started, err = manager.Begin(context.Background(), BeginInput{ConnectionID: connection.ID})
	if err != nil {
		t.Fatalf("begin second OIDC authentication: %v", err)
	}
	provider.identity = providerIdentity{
		Issuer:          connection.Issuer,
		ProviderSubject: "provider-user-1",
		Nonce:           store.latestChallenge().Nonce,
		Email:           "owner@example.com",
	}
	if _, err := manager.Complete(context.Background(), CompleteInput{
		State: started.State,
		Code:  "authorization-code",
	}); !errors.Is(err, ErrUnverifiedEmail) {
		t.Fatalf("complete with unverified email: got %v, want unverified email", err)
	}
}

func TestConnectionChangeInvalidatesPendingState(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections()
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)
	started, err := manager.Begin(context.Background(), BeginInput{ConnectionID: "company-sso"})
	if err != nil {
		t.Fatalf("begin OIDC authentication: %v", err)
	}
	connection := connections.values["company-sso"]
	connection.ClientID = "replacement-client"
	connections.values[connection.ID] = connection

	_, err = manager.Complete(context.Background(), CompleteInput{
		State: started.State,
		Code:  "authorization-code",
	})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("complete after connection change: got %v, want invalid state", err)
	}
	if provider.exchangeCalls != 0 {
		t.Fatal("changed connection reached the token exchange")
	}
}

func TestConcurrentCompletionConsumesStateOnce(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections()
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)
	started, err := manager.Begin(context.Background(), BeginInput{ConnectionID: "company-sso"})
	if err != nil {
		t.Fatalf("begin OIDC authentication: %v", err)
	}
	provider.identity = providerIdentity{
		Issuer:          "https://idp.example.com",
		ProviderSubject: "provider-user-1",
		Nonce:           store.latestChallenge().Nonce,
	}

	var successes atomic.Int32
	var rejected atomic.Int32
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := manager.Complete(context.Background(), CompleteInput{
				State: started.State,
				Code:  "authorization-code",
			})
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ErrInvalidState) {
				rejected.Add(1)
			} else {
				t.Errorf("unexpected completion error: %v", err)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 || rejected.Load() != 1 {
		t.Fatalf("successes=%d rejected=%d, want one each", successes.Load(), rejected.Load())
	}
}

func newTestManager(store Store, connections ConnectionSource, provider protocol) *Manager {
	return &Manager{
		store:       store,
		connections: connections,
		protocol:    provider,
		lifetime:    time.Minute,
		now:         func() time.Time { return fixedTime },
	}
}

type connectionMemory struct {
	values map[string]Connection
}

func newConnections() *connectionMemory {
	return &connectionMemory{values: map[string]Connection{
		"company-sso": {
			ID:           "company-sso",
			Issuer:       "https://idp.example.com",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://app.example.com/auth/oidc/callback",
		},
	}}
}

func (connections *connectionMemory) Find(
	_ context.Context,
	connectionID string,
) (Connection, error) {
	connection, exists := connections.values[connectionID]
	if !exists {
		return Connection{}, ErrNotFound
	}
	connection.Scopes = append([]string(nil), connection.Scopes...)
	return connection, nil
}

type memoryStore struct {
	mu         sync.Mutex
	challenges map[StateHash]Challenge
	latest     StateHash
}

func newMemoryStore() *memoryStore {
	return &memoryStore{challenges: make(map[StateHash]Challenge)}
}

func (store *memoryStore) CreateChallenge(_ context.Context, challenge Challenge) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.challenges[challenge.StateHash]; exists {
		return ErrConflict
	}
	challenge.Scopes = append([]string(nil), challenge.Scopes...)
	store.challenges[challenge.StateHash] = challenge
	store.latest = challenge.StateHash
	return nil
}

func (store *memoryStore) ConsumeChallenge(
	_ context.Context,
	stateHash StateHash,
	consumedAt time.Time,
) (Challenge, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, exists := store.challenges[stateHash]
	if !exists || !consumedAt.Before(challenge.ExpiresAt) {
		return Challenge{}, ErrNotFound
	}
	delete(store.challenges, stateHash)
	return challenge, nil
}

func (store *memoryStore) latestChallenge() Challenge {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.challenges[store.latest]
}

type fakeProtocol struct {
	connection       Connection
	state            string
	nonce            string
	codeVerifier     string
	exchangeVerifier string
	exchangeCalls    int
	identity         providerIdentity
}

func (provider *fakeProtocol) AuthorizationURL(
	_ context.Context,
	connection Connection,
	state string,
	nonce string,
	codeVerifier string,
) (string, error) {
	provider.connection = connection
	provider.state = state
	provider.nonce = nonce
	provider.codeVerifier = codeVerifier
	return "https://idp.example.com/authorize", nil
}

func (provider *fakeProtocol) Exchange(
	_ context.Context,
	_ Connection,
	_ string,
	codeVerifier string,
) (providerIdentity, error) {
	provider.exchangeCalls++
	provider.exchangeVerifier = codeVerifier
	return provider.identity, nil
}
