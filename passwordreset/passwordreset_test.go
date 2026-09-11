package passwordreset_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/Rahmannugar/authlier/token"
)

func TestRequestStoresOnlyTheTokenHashAndSendsTheRawToken(t *testing.T) {
	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore(passwordreset.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManager(t, store, sender, now)

	if err := manager.Request(context.Background(), passwordreset.RequestInput{
		Email: " OWNER@Example.COM ",
	}); err != nil {
		t.Fatalf("request password reset: %v", err)
	}
	if len(sender.messages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(sender.messages))
	}
	message := sender.messages[0]
	record := store.currentRecord()
	hash, err := token.HashToken(message.Token)
	if err != nil {
		t.Fatalf("hash delivered token: %v", err)
	}
	if record.TokenHash != passwordreset.TokenHash(hash) {
		t.Fatal("stored hash does not match delivered token")
	}
	if record.Email != "owner@example.com" || !record.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected password reset record: %+v", record)
	}
}

func TestRequestDoesNotDiscloseUnknownOrMalformedEmails(t *testing.T) {
	store := newMemoryStore(passwordreset.User{})
	sender := &messageSender{}
	manager := newManager(t, store, sender, time.Now())

	for _, email := range []string{"missing@example.com", "not an email"} {
		if err := manager.Request(context.Background(), passwordreset.RequestInput{Email: email}); err != nil {
			t.Fatalf("request password reset for %q: %v", email, err)
		}
	}
	if len(sender.messages) != 0 {
		t.Fatal("unknown or malformed request sent a message")
	}
}

func TestReplacementTokenResetsPasswordOnce(t *testing.T) {
	store := newMemoryStore(passwordreset.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	passwords := &stubPasswords{}
	manager := newManagerWithPasswords(t, store, sender, passwords, time.Now())
	ctx := context.Background()

	if err := manager.Request(ctx, passwordreset.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request first token: %v", err)
	}
	if err := manager.Request(ctx, passwordreset.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request replacement token: %v", err)
	}
	if _, err := manager.Reset(ctx, passwordreset.ResetInput{
		Token:       sender.messages[0].Token,
		NewPassword: "new password",
	}); !errors.Is(err, passwordreset.ErrInvalidToken) {
		t.Fatalf("use replaced token: got %v, want invalid token", err)
	}
	user, err := manager.Reset(ctx, passwordreset.ResetInput{
		Token:       sender.messages[1].Token,
		NewPassword: "new password",
	})
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if user.ID != "user_123" || store.currentPasswordHash() != "hashed:new password" {
		t.Fatalf("password was not replaced: user=%+v hash=%q", user, store.currentPasswordHash())
	}
	if _, err := manager.Reset(ctx, passwordreset.ResetInput{
		Token:       sender.messages[1].Token,
		NewPassword: "another password",
	}); !errors.Is(err, passwordreset.ErrInvalidToken) {
		t.Fatalf("reuse consumed token: got %v, want invalid token", err)
	}
}

func TestResetTokenIsSingleUseUnderConcurrency(t *testing.T) {
	store := newMemoryStore(passwordreset.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManagerWithPasswords(t, store, sender, &stubPasswords{}, time.Now())
	ctx := context.Background()
	if err := manager.Request(ctx, passwordreset.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request password reset: %v", err)
	}

	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := manager.Reset(ctx, passwordreset.ResetInput{
				Token:       sender.messages[0].Token,
				NewPassword: "new password",
			})
			results <- err
		}()
	}
	var successes, invalid int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, passwordreset.ErrInvalidToken):
			invalid++
		default:
			t.Fatalf("unexpected reset result: %v", err)
		}
	}
	if successes != 1 || invalid != 1 {
		t.Fatalf("successes = %d, invalid = %d", successes, invalid)
	}
}

func TestExpiredResetTokenIsRejected(t *testing.T) {
	store := newMemoryStore(passwordreset.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManagerWithPasswords(t, store, sender, &stubPasswords{}, time.Now())
	ctx := context.Background()
	if err := manager.Request(ctx, passwordreset.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request password reset: %v", err)
	}
	store.expireCurrent()

	if _, err := manager.Reset(ctx, passwordreset.ResetInput{
		Token:       sender.messages[0].Token,
		NewPassword: "new password",
	}); !errors.Is(err, passwordreset.ErrInvalidToken) {
		t.Fatalf("use expired token: got %v, want invalid token", err)
	}
}

func TestResetTokenCannotChangePasswordAfterTheEmailChanges(t *testing.T) {
	store := newMemoryStore(passwordreset.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManagerWithPasswords(t, store, sender, &stubPasswords{}, time.Now())
	ctx := context.Background()
	if err := manager.Request(ctx, passwordreset.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request password reset: %v", err)
	}
	store.changeEmail("new@example.com")

	if _, err := manager.Reset(ctx, passwordreset.ResetInput{
		Token:       sender.messages[0].Token,
		NewPassword: "new password",
	}); !errors.Is(err, passwordreset.ErrInvalidToken) {
		t.Fatalf("use old-email token: got %v, want invalid token", err)
	}
}

func TestPasswordPolicyRunsBeforeHashingOrStorage(t *testing.T) {
	store := newMemoryStore(passwordreset.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	passwords := &stubPasswords{}
	manager, err := passwordreset.NewManager(store, passwordreset.Config{
		Lifetime:  time.Hour,
		Sender:    sender,
		Passwords: passwords,
		ValidatePassword: func(string) error {
			return errors.New("password policy rejected input")
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	_, err = manager.Reset(context.Background(), passwordreset.ResetInput{
		Token:       "invalid",
		NewPassword: "weak",
	})
	if !errors.Is(err, passwordreset.ErrInvalidPassword) {
		t.Fatalf("reset weak password: got %v, want invalid password", err)
	}
	if passwords.hashCount() != 0 || store.resetCalls != 0 {
		t.Fatal("rejected password reached hashing or storage")
	}
}

func newManager(
	t *testing.T,
	store passwordreset.Store,
	sender passwordreset.Sender,
	now time.Time,
) *passwordreset.Manager {
	t.Helper()
	manager, err := passwordreset.NewManager(store, passwordreset.Config{
		Lifetime: time.Hour,
		Sender:   sender,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return manager
}

func newManagerWithPasswords(
	t *testing.T,
	store passwordreset.Store,
	sender passwordreset.Sender,
	passwords passwordreset.Passwords,
	now time.Time,
) *passwordreset.Manager {
	t.Helper()
	manager, err := passwordreset.NewManager(store, passwordreset.Config{
		Lifetime:  time.Hour,
		Sender:    sender,
		Passwords: passwords,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return manager
}

type stubPasswords struct {
	mu     sync.Mutex
	hashed []string
}

func (passwords *stubPasswords) Hash(plainPassword string) (string, error) {
	passwords.mu.Lock()
	defer passwords.mu.Unlock()
	passwords.hashed = append(passwords.hashed, plainPassword)
	return "hashed:" + plainPassword, nil
}

func (passwords *stubPasswords) hashCount() int {
	passwords.mu.Lock()
	defer passwords.mu.Unlock()
	return len(passwords.hashed)
}

type messageSender struct {
	messages []passwordreset.Message
}

func (sender *messageSender) SendPasswordReset(
	_ context.Context,
	message passwordreset.Message,
) error {
	sender.messages = append(sender.messages, message)
	return nil
}

type memoryStore struct {
	mu           sync.Mutex
	user         passwordreset.User
	record       *passwordreset.Record
	passwordHash string
	resetCalls   int
}

func newMemoryStore(user passwordreset.User) *memoryStore {
	return &memoryStore{user: user, passwordHash: "hashed:old password"}
}

func (store *memoryStore) FindUserByEmail(
	_ context.Context,
	normalizedEmail string,
) (passwordreset.User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.user.ID == "" || store.user.Email != normalizedEmail {
		return passwordreset.User{}, passwordreset.ErrNotFound
	}
	return store.user, nil
}

func (store *memoryStore) Issue(_ context.Context, record passwordreset.Record) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	copy := record
	store.record = &copy
	return nil
}

func (store *memoryStore) ResetPassword(
	_ context.Context,
	tokenHash passwordreset.TokenHash,
	passwordHash string,
	resetAt time.Time,
) (passwordreset.User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.resetCalls++
	if store.record == nil || store.record.TokenHash != tokenHash ||
		!resetAt.Before(store.record.ExpiresAt) || store.user.Email != store.record.Email {
		return passwordreset.User{}, passwordreset.ErrInactiveToken
	}
	store.passwordHash = passwordHash
	store.record = nil
	return store.user, nil
}

func (store *memoryStore) currentRecord() passwordreset.Record {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.record == nil {
		return passwordreset.Record{}
	}
	return *store.record
}

func (store *memoryStore) currentPasswordHash() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.passwordHash
}

func (store *memoryStore) expireCurrent() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.record.ExpiresAt = store.record.CreatedAt
}

func (store *memoryStore) changeEmail(email string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.user.Email = email
}
