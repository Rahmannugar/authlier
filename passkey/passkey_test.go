package passkey

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlibrary "github.com/go-webauthn/webauthn/webauthn"
)

var fixedTime = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func TestManagerRequiresUserVerificationAndDiscoverableCredentials(t *testing.T) {
	store := newMemoryStore()
	manager, err := NewManager(store, Config{
		RelyingPartyID:   "example.com",
		RelyingPartyName: "Example",
		Origins:          []string{"https://example.com"},
		CeremonyLifetime: 2 * time.Minute,
		Now:              func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	registration, err := manager.BeginRegistration(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	selection := registration.Options.Response.AuthenticatorSelection
	if selection.ResidentKey != protocol.ResidentKeyRequirementRequired ||
		selection.UserVerification != protocol.VerificationRequired {
		t.Fatalf("unsafe registration options: %+v", selection)
	}
	authentication, err := manager.BeginAuthentication(context.Background())
	if err != nil {
		t.Fatalf("begin authentication: %v", err)
	}
	if authentication.Options.Response.UserVerification != protocol.VerificationRequired {
		t.Fatalf("user verification = %q, want required", authentication.Options.Response.UserVerification)
	}
}

func TestRegistrationCreatesCredentialAndConsumesCeremony(t *testing.T) {
	store := newMemoryStore()
	engine := &fakeProtocol{registered: credential("credential-1", 0)}
	manager := newTestManager(store, engine, func() time.Time { return fixedTime })

	started, err := manager.BeginRegistration(context.Background(), "user-1")
	if err != nil || started.Options == nil || started.Token == "" {
		t.Fatalf("begin registration: started=%+v error=%v", started, err)
	}
	created, err := manager.CompleteRegistration(context.Background(), CompleteInput{
		CeremonyToken: started.Token,
		Response:      []byte("registration-response"),
	})
	if err != nil || !reflect.DeepEqual(created, engine.registered) {
		t.Fatalf("complete registration: credential=%+v error=%v", created, err)
	}
	if !store.hasCredential("user-1", created.ID) {
		t.Fatal("registered credential was not stored")
	}
	if _, err := manager.CompleteRegistration(context.Background(), CompleteInput{
		CeremonyToken: started.Token,
		Response:      []byte("registration-response"),
	}); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("reuse registration ceremony: got %v, want invalid ceremony", err)
	}
}

func TestRegistrationCeremonyCannotBeCompletedByAnotherSession(t *testing.T) {
	store := newMemoryStore()
	manager := newTestManager(
		store,
		&fakeProtocol{registered: credential("credential-1", 0)},
		func() time.Time { return fixedTime },
	)
	started, err := manager.BeginRegistration(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	_, err = manager.CompleteRegistration(context.Background(), CompleteInput{
		CeremonyToken: started.Token,
		SubjectID:     "user-2",
		Response:      []byte("registration-response"),
	})
	if !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("complete registration as another user: got %v, want invalid ceremony", err)
	}
}

func TestDiscoverableAuthenticationResolvesCredentialOwner(t *testing.T) {
	store := newMemoryStore()
	stored := credential("credential-1", 1)
	store.addCredential("user-1", stored)
	updated := credential("credential-1", 2)
	updated.Authenticator.CloneWarning = true
	engine := &fakeProtocol{
		credentialID: []byte("credential-1"),
		userHandle:   []byte("handle-1"),
		previous:     stored,
		updated:      updated,
	}
	manager := newTestManager(store, engine, func() time.Time { return fixedTime })

	started, err := manager.BeginAuthentication(context.Background())
	if err != nil || started.Options == nil {
		t.Fatalf("begin authentication: started=%+v error=%v", started, err)
	}
	authentication, err := manager.CompleteAuthentication(context.Background(), CompleteInput{
		CeremonyToken: started.Token,
		Response:      []byte("assertion-response"),
	})
	if err != nil || authentication.SubjectID != "user-1" || !authentication.CloneWarning {
		t.Fatalf("complete authentication: authentication=%+v error=%v", authentication, err)
	}
	if store.credential("user-1", []byte("credential-1")).Authenticator.SignCount != 2 {
		t.Fatal("credential counter was not updated")
	}
}

func TestConcurrentAssertionsCannotBothUpdateTheSameCredential(t *testing.T) {
	store := newMemoryStore()
	stored := credential("credential-1", 1)
	store.addCredential("user-1", stored)
	engine := &fakeProtocol{
		credentialID: []byte("credential-1"),
		userHandle:   []byte("handle-1"),
		previous:     stored,
		updated:      credential("credential-1", 2),
	}
	manager := newTestManager(store, engine, func() time.Time { return fixedTime })
	first, _ := manager.BeginAuthentication(context.Background())
	second, _ := manager.BeginAuthentication(context.Background())

	var successes atomic.Int32
	var conflicts atomic.Int32
	var waitGroup sync.WaitGroup
	for _, token := range []string{first.Token, second.Token} {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := manager.CompleteAuthentication(context.Background(), CompleteInput{
				CeremonyToken: token,
				Response:      []byte("assertion-response"),
			})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrConflict):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected authentication error: %v", err)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 || conflicts.Load() != 1 {
		t.Fatalf("successes=%d conflicts=%d, want one each", successes.Load(), conflicts.Load())
	}
}

func TestExpiredCeremonyCannotAuthenticate(t *testing.T) {
	store := newMemoryStore()
	now := fixedTime
	manager := newTestManager(store, &fakeProtocol{}, func() time.Time { return now })
	started, err := manager.BeginAuthentication(context.Background())
	if err != nil {
		t.Fatalf("begin authentication: %v", err)
	}
	now = now.Add(3 * time.Minute)
	if _, err := manager.CompleteAuthentication(context.Background(), CompleteInput{
		CeremonyToken: started.Token,
		Response:      []byte("assertion-response"),
	}); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("complete expired ceremony: got %v, want invalid ceremony", err)
	}
}

func TestRemoveCannotDeleteTheLastSignInMethod(t *testing.T) {
	store := newMemoryStore()
	store.deleteErr = ErrLastCredential
	manager := newTestManager(store, &fakeProtocol{}, func() time.Time { return fixedTime })

	err := manager.Remove(context.Background(), "user-1", []byte("credential-1"), "")
	if !errors.Is(err, ErrLastCredential) {
		t.Fatalf("remove last sign-in method: got %v, want last credential", err)
	}
}

func newTestManager(store Store, engine ceremonyProtocol, now func() time.Time) *Manager {
	return &Manager{
		store:    store,
		protocol: engine,
		lifetime: 2 * time.Minute,
		now:      now,
	}
}

func credential(id string, counter uint32) Credential {
	return Credential{
		ID:        []byte(id),
		PublicKey: []byte("public-key"),
		Authenticator: webauthnlibrary.Authenticator{
			SignCount: counter,
		},
	}
}

type fakeProtocol struct {
	registered   Credential
	credentialID []byte
	userHandle   []byte
	previous     Credential
	updated      Credential
}

func (engine *fakeProtocol) BeginRegistration(User) (*protocol.CredentialCreation, webauthnlibrary.SessionData, error) {
	return &protocol.CredentialCreation{}, webauthnlibrary.SessionData{
		Challenge: "registration-challenge",
		UserID:    []byte("handle-1"),
	}, nil
}

func (engine *fakeProtocol) FinishRegistration(
	_ User,
	_ webauthnlibrary.SessionData,
	_ []byte,
) (Credential, error) {
	return engine.registered, nil
}

func (engine *fakeProtocol) BeginAuthentication() (*protocol.CredentialAssertion, webauthnlibrary.SessionData, error) {
	return &protocol.CredentialAssertion{}, webauthnlibrary.SessionData{
		Challenge: "authentication-challenge",
	}, nil
}

func (engine *fakeProtocol) FinishAuthentication(
	_ webauthnlibrary.SessionData,
	_ []byte,
	lookup credentialLookup,
) (User, Credential, Credential, error) {
	user, err := lookup(engine.credentialID, engine.userHandle)
	if err != nil {
		return User{}, Credential{}, Credential{}, err
	}
	return user, engine.previous, engine.updated, nil
}

type memoryStore struct {
	mu         sync.Mutex
	users      map[string]User
	ceremonies map[CeremonyHash]Ceremony
	deleteErr  error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		users: map[string]User{
			"user-1": {
				SubjectID:   "user-1",
				Handle:      []byte("handle-1"),
				Name:        "owner@example.com",
				DisplayName: "Owner",
			},
		},
		ceremonies: make(map[CeremonyHash]Ceremony),
	}
}

func (store *memoryStore) FindUserBySubject(_ context.Context, subjectID string) (User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	user, exists := store.users[subjectID]
	if !exists {
		return User{}, ErrNotFound
	}
	return cloneUser(user), nil
}

func (store *memoryStore) FindUserByCredential(
	_ context.Context,
	credentialID []byte,
	userHandle []byte,
) (User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, user := range store.users {
		if !bytes.Equal(user.Handle, userHandle) {
			continue
		}
		for _, credential := range user.Credentials {
			if bytes.Equal(credential.ID, credentialID) {
				return cloneUser(user), nil
			}
		}
	}
	return User{}, ErrNotFound
}

func (store *memoryStore) CreateCeremony(_ context.Context, ceremony Ceremony) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.ceremonies[ceremony.TokenHash]; exists {
		return ErrConflict
	}
	store.ceremonies[ceremony.TokenHash] = ceremony
	return nil
}

func (store *memoryStore) FindCeremony(_ context.Context, ceremonyHash CeremonyHash) (Ceremony, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ceremony, exists := store.ceremonies[ceremonyHash]
	if !exists {
		return Ceremony{}, ErrNotFound
	}
	return ceremony, nil
}

func (store *memoryStore) CompleteRegistration(
	_ context.Context,
	ceremonyHash CeremonyHash,
	subjectID string,
	credential Credential,
	completedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	ceremony, exists := store.ceremonies[ceremonyHash]
	if !exists || ceremony.Type != CeremonyRegistration ||
		ceremony.SubjectID != subjectID || !completedAt.Before(ceremony.ExpiresAt) {
		return ErrInactiveCeremony
	}
	for _, user := range store.users {
		for _, existing := range user.Credentials {
			if bytes.Equal(existing.ID, credential.ID) {
				return ErrConflict
			}
		}
	}
	user, exists := store.users[subjectID]
	if !exists {
		return ErrNotFound
	}
	user.Credentials = append(user.Credentials, credential)
	store.users[subjectID] = user
	delete(store.ceremonies, ceremonyHash)
	return nil
}

func (store *memoryStore) CompleteAuthentication(
	_ context.Context,
	ceremonyHash CeremonyHash,
	subjectID string,
	previous Credential,
	updated Credential,
	completedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	ceremony, exists := store.ceremonies[ceremonyHash]
	if !exists || ceremony.Type != CeremonyAuthentication || !completedAt.Before(ceremony.ExpiresAt) {
		return ErrInactiveCeremony
	}
	user, exists := store.users[subjectID]
	if !exists {
		return ErrNotFound
	}
	for index, existing := range user.Credentials {
		if bytes.Equal(existing.ID, previous.ID) {
			if !reflect.DeepEqual(existing, previous) {
				return ErrConflict
			}
			user.Credentials[index] = updated
			store.users[subjectID] = user
			delete(store.ceremonies, ceremonyHash)
			return nil
		}
	}
	return ErrNotFound
}

func (store *memoryStore) DeleteCredential(
	_ context.Context,
	subjectID string,
	credentialID []byte,
	_ time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deleteErr != nil {
		return store.deleteErr
	}
	user, exists := store.users[subjectID]
	if !exists {
		return ErrNotFound
	}
	for index, credential := range user.Credentials {
		if bytes.Equal(credential.ID, credentialID) {
			user.Credentials = append(user.Credentials[:index], user.Credentials[index+1:]...)
			store.users[subjectID] = user
			return nil
		}
	}
	return ErrNotFound
}

func (store *memoryStore) addCredential(subjectID string, credential Credential) {
	store.mu.Lock()
	defer store.mu.Unlock()
	user := store.users[subjectID]
	user.Credentials = append(user.Credentials, credential)
	store.users[subjectID] = user
}

func (store *memoryStore) hasCredential(subjectID string, credentialID []byte) bool {
	return len(store.credential(subjectID, credentialID).ID) > 0
}

func (store *memoryStore) credential(subjectID string, credentialID []byte) Credential {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, credential := range store.users[subjectID].Credentials {
		if bytes.Equal(credential.ID, credentialID) {
			return credential
		}
	}
	return Credential{}
}

func cloneUser(user User) User {
	user.Handle = append([]byte(nil), user.Handle...)
	user.Credentials = append([]Credential(nil), user.Credentials...)
	return user
}
