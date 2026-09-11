package emailpassword_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/password"
)

func TestRegisterNormalizesIdentityAndPersistsOnlyThePasswordHash(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	store := &stubStore{}
	passwords := newStubPasswords()
	events := &eventRecorder{}
	guard := &attemptRecorder{}
	manager := newManager(t, store, passwords, guard, events, now)

	user, err := manager.Register(ctx, emailpassword.RegisterInput{
		Email:     "  OWNER@Example.COM ",
		Password:  "correct horse battery staple",
		SourceKey: "client:203.0.113.10",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.ID != "user_123" || user.Email != "owner@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if store.registration.Email != "owner@example.com" {
		t.Fatalf("stored non-canonical email: %q", store.registration.Email)
	}
	if store.registration.PasswordHash != "preferred:correct horse battery staple" {
		t.Fatalf("stored unexpected password hash: %q", store.registration.PasswordHash)
	}
	if store.registration.PasswordHash == "correct horse battery staple" {
		t.Fatal("store received the raw password")
	}
	if !store.registration.CreatedAt.Equal(now) {
		t.Fatalf("registration time = %v, want %v", store.registration.CreatedAt, now)
	}
	if len(guard.attempts) != 1 || guard.attempts[0].Email != "owner@example.com" {
		t.Fatalf("guard did not receive canonical identity: %+v", guard.attempts)
	}
	if len(events.events) != 1 || events.events[0].Type != emailpassword.EventRegistrationSucceeded {
		t.Fatalf("unexpected security events: %+v", events.events)
	}
	if events.events[0].SubjectID != user.ID || events.events[0].SourceKey != "client:203.0.113.10" {
		t.Fatalf("security event lost bounded context: %+v", events.events[0])
	}
}

func TestDuplicateRegistrationUsesGenericErrorAfterHashing(t *testing.T) {
	store := &stubStore{registerErr: emailpassword.ErrConflict}
	passwords := newStubPasswords()
	events := &eventRecorder{}
	manager := newManager(t, store, passwords, nil, events, time.Now())
	hashesBeforeRegistration := len(passwords.hashed)

	_, err := manager.Register(context.Background(), emailpassword.RegisterInput{
		Email:    "owner@example.com",
		Password: "password",
	})
	if !errors.Is(err, emailpassword.ErrRegistrationUnavailable) {
		t.Fatalf("duplicate registration: got %v, want generic unavailable error", err)
	}
	if len(passwords.hashed) != hashesBeforeRegistration+1 {
		t.Fatal("duplicate registration skipped password hashing")
	}
	if len(events.events) != 1 || events.events[0].Type != emailpassword.EventRegistrationRejected {
		t.Fatalf("unexpected security events: %+v", events.events)
	}
}

func TestUnknownIdentityAndWrongPasswordShareTheCredentialFailurePath(t *testing.T) {
	ctx := context.Background()
	passwords := newStubPasswords()
	missingStore := &stubStore{findErr: emailpassword.ErrNotFound}
	missingManager := newManager(t, missingStore, passwords, nil, nil, time.Now())

	_, missingErr := missingManager.Login(ctx, emailpassword.LoginInput{
		Email:    "missing@example.com",
		Password: "wrong",
	})
	if !errors.Is(missingErr, emailpassword.ErrInvalidCredentials) {
		t.Fatalf("unknown identity: got %v, want invalid credentials", missingErr)
	}
	if len(passwords.verified) != 1 || passwords.verified[0].encodedHash != "preferred:dummy" {
		t.Fatalf("unknown identity did not verify against dummy hash: %+v", passwords.verified)
	}

	passwords.verified = nil
	wrongStore := &stubStore{
		user:       emailpassword.User{ID: "user_123", Email: "owner@example.com"},
		credential: emailpassword.PasswordCredential{UserID: "user_123", PasswordHash: "preferred:correct"},
	}
	wrongManager := newManager(t, wrongStore, passwords, nil, nil, time.Now())
	_, wrongErr := wrongManager.Login(ctx, emailpassword.LoginInput{
		Email:    "owner@example.com",
		Password: "wrong",
	})
	if !errors.Is(wrongErr, emailpassword.ErrInvalidCredentials) {
		t.Fatalf("wrong password: got %v, want invalid credentials", wrongErr)
	}
	if len(passwords.verified) != 1 || passwords.verified[0].encodedHash != "preferred:correct" {
		t.Fatalf("known identity did not verify stored hash: %+v", passwords.verified)
	}
}

func TestMalformedLoginStillVerifiesDummyHashWithoutQueryingTheStore(t *testing.T) {
	store := &stubStore{}
	passwords := newStubPasswords()
	manager := newManager(t, store, passwords, nil, nil, time.Now())

	_, err := manager.Login(context.Background(), emailpassword.LoginInput{
		Email:    "not an email",
		Password: "wrong",
	})
	if !errors.Is(err, emailpassword.ErrInvalidCredentials) {
		t.Fatalf("malformed login: got %v, want invalid credentials", err)
	}
	if store.findCalls != 0 {
		t.Fatal("malformed login queried the durable store")
	}
	if len(passwords.verified) != 1 || passwords.verified[0].encodedHash != "preferred:dummy" {
		t.Fatalf("malformed login did not verify against dummy hash: %+v", passwords.verified)
	}
}

func TestMatchingLegacyPasswordIsRehashedBeforeLoginSucceeds(t *testing.T) {
	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	store := &stubStore{
		user:       emailpassword.User{ID: "user_123", Email: "owner@example.com"},
		credential: emailpassword.PasswordCredential{UserID: "user_123", PasswordHash: "legacy:correct"},
	}
	passwords := newStubPasswords()
	events := &eventRecorder{}
	manager := newManager(t, store, passwords, nil, events, now)

	result, err := manager.Login(context.Background(), emailpassword.LoginInput{
		Email:     "owner@example.com",
		Password:  "correct",
		SourceKey: "client:203.0.113.10",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !result.PasswordRehashed || result.User.ID != "user_123" {
		t.Fatalf("unexpected login result: %+v", result)
	}
	if store.replacement.userID != "user_123" ||
		store.replacement.currentHash != "legacy:correct" ||
		store.replacement.replacementHash != "preferred:correct" ||
		!store.replacement.updatedAt.Equal(now) {
		t.Fatalf("unexpected compare-and-swap replacement: %+v", store.replacement)
	}
	wantEvents := []emailpassword.EventType{
		emailpassword.EventPasswordRehashed,
		emailpassword.EventLoginSucceeded,
	}
	if len(events.events) != len(wantEvents) {
		t.Fatalf("security events = %+v, want %v", events.events, wantEvents)
	}
	for index, eventType := range wantEvents {
		if events.events[index].Type != eventType {
			t.Fatalf("security event %d = %q, want %q", index, events.events[index].Type, eventType)
		}
	}
}

func TestConcurrentPasswordChangePreventsStaleLogin(t *testing.T) {
	store := &stubStore{
		user:       emailpassword.User{ID: "user_123", Email: "owner@example.com"},
		credential: emailpassword.PasswordCredential{UserID: "user_123", PasswordHash: "legacy:correct"},
		replaceErr: emailpassword.ErrConflict,
	}
	manager := newManager(t, store, newStubPasswords(), nil, nil, time.Now())

	_, err := manager.Login(context.Background(), emailpassword.LoginInput{
		Email:    "owner@example.com",
		Password: "correct",
	})
	if !errors.Is(err, emailpassword.ErrInvalidCredentials) {
		t.Fatalf("stale login: got %v, want invalid credentials", err)
	}
}

func TestAttemptGuardBlocksWorkBeforeStoreAndPasswordVerification(t *testing.T) {
	store := &stubStore{}
	passwords := newStubPasswords()
	guard := &attemptRecorder{err: emailpassword.ErrAttemptBlocked}
	manager := newManager(t, store, passwords, guard, nil, time.Now())
	hashesAfterConstruction := len(passwords.hashed)

	_, err := manager.Login(context.Background(), emailpassword.LoginInput{
		Email:    "owner@example.com",
		Password: "password",
	})
	if !errors.Is(err, emailpassword.ErrAttemptBlocked) {
		t.Fatalf("guarded login: got %v, want blocked", err)
	}
	if store.findCalls != 0 || len(passwords.verified) != 0 || len(passwords.hashed) != hashesAfterConstruction {
		t.Fatal("blocked login performed authentication work")
	}
}

func TestDefaultPasswordEngineMigratesBcryptToArgon2id(t *testing.T) {
	legacyHash, err := password.HashWithAlgorithm("correct", password.Bcrypt)
	if err != nil {
		t.Fatalf("create bcrypt hash: %v", err)
	}
	store := &stubStore{
		user:       emailpassword.User{ID: "user_123", Email: "owner@example.com"},
		credential: emailpassword.PasswordCredential{UserID: "user_123", PasswordHash: legacyHash},
	}
	manager, err := emailpassword.NewManager(store, emailpassword.Config{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	result, err := manager.Login(context.Background(), emailpassword.LoginInput{
		Email:    "owner@example.com",
		Password: "correct",
	})
	if err != nil {
		t.Fatalf("login with bcrypt credential: %v", err)
	}
	if !result.PasswordRehashed {
		t.Fatal("bcrypt credential did not request replacement")
	}
	verification, err := password.Verify("correct", store.replacement.replacementHash)
	if err != nil || !verification.Matches || verification.NeedsRehash {
		t.Fatalf("replacement is not a current Argon2id hash: verification=%+v err=%v", verification, err)
	}
}

func newManager(
	t *testing.T,
	store emailpassword.Store,
	passwords emailpassword.Passwords,
	guard emailpassword.AttemptGuard,
	events emailpassword.SecurityEventSink,
	now time.Time,
) *emailpassword.Manager {
	t.Helper()
	manager, err := emailpassword.NewManager(store, emailpassword.Config{
		Passwords:      passwords,
		AttemptGuard:   guard,
		SecurityEvents: events,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return manager
}

type stubStore struct {
	registration emailpassword.Registration
	registerErr  error
	user         emailpassword.User
	credential   emailpassword.PasswordCredential
	findErr      error
	findCalls    int
	replacement  replacement
	replaceErr   error
}

type replacement struct {
	userID          string
	currentHash     string
	replacementHash string
	updatedAt       time.Time
}

func (store *stubStore) Register(
	_ context.Context,
	registration emailpassword.Registration,
) (emailpassword.User, error) {
	store.registration = registration
	if store.registerErr != nil {
		return emailpassword.User{}, store.registerErr
	}
	return emailpassword.User{ID: "user_123", Email: registration.Email}, nil
}

func (store *stubStore) FindByEmail(
	_ context.Context,
	_ string,
) (emailpassword.User, emailpassword.PasswordCredential, error) {
	store.findCalls++
	if store.findErr != nil {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, store.findErr
	}
	return store.user, store.credential, nil
}

func (store *stubStore) ReplacePasswordHash(
	_ context.Context,
	userID string,
	currentHash string,
	replacementHash string,
	updatedAt time.Time,
) error {
	store.replacement = replacement{
		userID:          userID,
		currentHash:     currentHash,
		replacementHash: replacementHash,
		updatedAt:       updatedAt,
	}
	return store.replaceErr
}

type verificationCall struct {
	plainPassword string
	encodedHash   string
}

type stubPasswords struct {
	hashed   []string
	verified []verificationCall
}

func newStubPasswords() *stubPasswords {
	return &stubPasswords{}
}

func (passwords *stubPasswords) Hash(plainPassword string) (string, error) {
	passwords.hashed = append(passwords.hashed, plainPassword)
	if plainPassword == "authlier dummy password for unknown identities" {
		return "preferred:dummy", nil
	}
	return "preferred:" + plainPassword, nil
}

func (passwords *stubPasswords) Verify(
	plainPassword string,
	encodedHash string,
) (password.Verification, error) {
	passwords.verified = append(passwords.verified, verificationCall{
		plainPassword: plainPassword,
		encodedHash:   encodedHash,
	})
	if encodedHash == "legacy:"+plainPassword {
		return password.Verification{Matches: true, NeedsRehash: true}, nil
	}
	return password.Verification{Matches: encodedHash == "preferred:"+plainPassword}, nil
}

type attemptRecorder struct {
	attempts []emailpassword.Attempt
	err      error
}

func (recorder *attemptRecorder) Check(_ context.Context, attempt emailpassword.Attempt) error {
	recorder.attempts = append(recorder.attempts, attempt)
	return recorder.err
}

type eventRecorder struct {
	events []emailpassword.SecurityEvent
}

func (recorder *eventRecorder) Record(_ context.Context, event emailpassword.SecurityEvent) {
	recorder.events = append(recorder.events, event)
}
