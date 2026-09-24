package emailverification_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/token"
)

func TestRequestStoresOnlyTheTokenHashAndSendsTheRawToken(t *testing.T) {
	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore(emailverification.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManager(t, store, sender, now)

	err := manager.Request(context.Background(), emailverification.RequestInput{
		Email: " OWNER@Example.COM ",
	})
	if err != nil {
		t.Fatalf("request verification: %v", err)
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
	if record.TokenHash != emailverification.TokenHash(hash) {
		t.Fatal("stored hash does not match delivered token")
	}
	if record.Email != "owner@example.com" || !record.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected verification record: %+v", record)
	}
}

func TestRequestDoesNotDiscloseUnknownOrAlreadyVerifiedEmails(t *testing.T) {
	tests := map[string]*memoryStore{
		"unknown": newMemoryStore(emailverification.User{}),
		"verified": newMemoryStore(emailverification.User{
			ID: "user_123", Email: "owner@example.com", Verified: true,
		}),
	}
	for name, store := range tests {
		t.Run(name, func(t *testing.T) {
			sender := &messageSender{}
			manager := newManager(t, store, sender, time.Now())
			if err := manager.Request(context.Background(), emailverification.RequestInput{
				Email: "owner@example.com",
			}); err != nil {
				t.Fatalf("request verification: %v", err)
			}
			if len(sender.messages) != 0 {
				t.Fatal("request sent a message")
			}
		})
	}
}

func TestResendInvalidatesTheEarlierToken(t *testing.T) {
	store := newMemoryStore(emailverification.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManager(t, store, sender, time.Now())
	ctx := context.Background()

	if err := manager.Request(ctx, emailverification.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request first token: %v", err)
	}
	if err := manager.Request(ctx, emailverification.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request replacement token: %v", err)
	}
	if _, err := manager.Verify(ctx, emailverification.VerifyInput{
		Token: sender.messages[0].Token,
	}); !errors.Is(err, emailverification.ErrInvalidToken) {
		t.Fatalf("verify replaced token: got %v, want invalid token", err)
	}
	if _, err := manager.Verify(ctx, emailverification.VerifyInput{
		Token: sender.messages[1].Token,
	}); err != nil {
		t.Fatalf("verify current token: %v", err)
	}
}

func TestVerificationTokenIsSingleUseUnderConcurrency(t *testing.T) {
	store := newMemoryStore(emailverification.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManager(t, store, sender, time.Now())
	ctx := context.Background()
	if err := manager.Request(ctx, emailverification.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request verification: %v", err)
	}

	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := manager.Verify(ctx, emailverification.VerifyInput{Token: sender.messages[0].Token})
			results <- err
		}()
	}
	var successes, invalid int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, emailverification.ErrInvalidToken):
			invalid++
		default:
			t.Fatalf("unexpected verification result: %v", err)
		}
	}
	if successes != 1 || invalid != 1 {
		t.Fatalf("successes = %d, invalid = %d", successes, invalid)
	}
}

func TestVerificationTokenCannotVerifyAChangedEmail(t *testing.T) {
	store := newMemoryStore(emailverification.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManager(t, store, sender, time.Now())
	ctx := context.Background()
	if err := manager.Request(ctx, emailverification.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request verification: %v", err)
	}
	store.changeEmail("new@example.com")

	if _, err := manager.Verify(ctx, emailverification.VerifyInput{
		Token: sender.messages[0].Token,
	}); !errors.Is(err, emailverification.ErrInvalidToken) {
		t.Fatalf("verify old email: got %v, want invalid token", err)
	}
}

func TestExpiredVerificationTokenIsRejected(t *testing.T) {
	store := newMemoryStore(emailverification.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager := newManager(t, store, sender, time.Now())
	ctx := context.Background()
	if err := manager.Request(ctx, emailverification.RequestInput{Email: "owner@example.com"}); err != nil {
		t.Fatalf("request verification: %v", err)
	}
	store.expireCurrent()

	if _, err := manager.Verify(ctx, emailverification.VerifyInput{
		Token: sender.messages[0].Token,
	}); !errors.Is(err, emailverification.ErrInvalidToken) {
		t.Fatalf("verify expired token: got %v, want invalid token", err)
	}
}

func TestOTPIsSixDigitsAndBoundToTheNormalizedEmail(t *testing.T) {
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore(emailverification.User{ID: "user_123", Email: "owner@example.com"})
	sender := &messageSender{}
	manager, err := emailverification.NewManager(store, emailverification.Config{
		Delivery:     emailverification.DeliveryMethodOTP,
		OTPSecret:    []byte("0123456789abcdef0123456789abcdef"),
		Lifetime:     10 * time.Minute,
		Sender:       sender,
		AttemptGuard: allowAttempts{},
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create OTP manager: %v", err)
	}

	if err := manager.Request(context.Background(), emailverification.RequestInput{
		Email: " OWNER@Example.COM ",
	}); err != nil {
		t.Fatalf("request OTP: %v", err)
	}
	if len(sender.messages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(sender.messages))
	}
	message := sender.messages[0]
	if len(message.Code) != 6 || message.Token != "" {
		t.Fatalf("unexpected OTP delivery: code=%q token=%q", message.Code, message.Token)
	}
	for _, character := range message.Code {
		if character < '0' || character > '9' {
			t.Fatalf("OTP contains non-digit: %q", message.Code)
		}
	}

	if _, err := manager.Verify(context.Background(), emailverification.VerifyInput{
		Email: "other@example.com", Code: message.Code,
	}); !errors.Is(err, emailverification.ErrInvalidToken) {
		t.Fatalf("verify OTP for another email: got %v, want invalid token", err)
	}
	managerWithWrongSecret, err := emailverification.NewManager(store, emailverification.Config{
		Delivery:     emailverification.DeliveryMethodOTP,
		OTPSecret:    []byte("abcdef0123456789abcdef0123456789"),
		Lifetime:     10 * time.Minute,
		Sender:       sender,
		AttemptGuard: allowAttempts{},
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create OTP manager with another secret: %v", err)
	}
	if _, err := managerWithWrongSecret.Verify(context.Background(), emailverification.VerifyInput{
		Email: "owner@example.com", Code: message.Code,
	}); !errors.Is(err, emailverification.ErrInvalidToken) {
		t.Fatalf("verify OTP with another secret: got %v, want invalid token", err)
	}
	if _, err := manager.Verify(context.Background(), emailverification.VerifyInput{
		Email: " OWNER@Example.COM ", Code: message.Code,
	}); err != nil {
		t.Fatalf("verify OTP: %v", err)
	}
}

func TestOTPRequiresAttemptGuard(t *testing.T) {
	_, err := emailverification.NewManager(
		newMemoryStore(emailverification.User{}),
		emailverification.Config{
			Delivery:  emailverification.DeliveryMethodOTP,
			OTPSecret: []byte("0123456789abcdef0123456789abcdef"),
			Lifetime:  10 * time.Minute,
			Sender:    &messageSender{},
		},
	)
	if !errors.Is(err, emailverification.ErrInvalidConfig) {
		t.Fatalf("create OTP manager without attempt guard: got %v, want invalid config", err)
	}
}

func TestOTPRequiresSecret(t *testing.T) {
	_, err := emailverification.NewManager(
		newMemoryStore(emailverification.User{}),
		emailverification.Config{
			Delivery:     emailverification.DeliveryMethodOTP,
			Lifetime:     10 * time.Minute,
			Sender:       &messageSender{},
			AttemptGuard: allowAttempts{},
		},
	)
	if !errors.Is(err, emailverification.ErrInvalidConfig) {
		t.Fatalf("create OTP manager without secret: got %v, want invalid config", err)
	}
}

func TestOTPVerificationChecksNormalizedEmailAndSourceBeforeValidation(t *testing.T) {
	guard := &blockingAttemptGuard{}
	manager, err := emailverification.NewManager(
		newMemoryStore(emailverification.User{}),
		emailverification.Config{
			Delivery:     emailverification.DeliveryMethodOTP,
			OTPSecret:    []byte("0123456789abcdef0123456789abcdef"),
			Lifetime:     10 * time.Minute,
			Sender:       &messageSender{},
			AttemptGuard: guard,
		},
	)
	if err != nil {
		t.Fatalf("create OTP manager: %v", err)
	}

	_, err = manager.Verify(context.Background(), emailverification.VerifyInput{
		Email: " OWNER@Example.COM ", Code: "invalid", SourceKey: "203.0.113.10",
	})
	if !errors.Is(err, emailverification.ErrAttemptBlocked) {
		t.Fatalf("verify blocked OTP: got %v, want attempt blocked", err)
	}
	if guard.attempt.Operation != emailverification.OperationVerify ||
		guard.attempt.Email != "owner@example.com" ||
		guard.attempt.SourceKey != "203.0.113.10" {
		t.Fatalf("unexpected guarded attempt: %+v", guard.attempt)
	}
}

type allowAttempts struct{}

func (allowAttempts) Check(context.Context, emailverification.Attempt) error { return nil }

type blockingAttemptGuard struct {
	attempt emailverification.Attempt
}

func (guard *blockingAttemptGuard) Check(
	_ context.Context,
	attempt emailverification.Attempt,
) error {
	guard.attempt = attempt
	return emailverification.ErrAttemptBlocked
}

func newManager(
	t *testing.T,
	store emailverification.Store,
	sender emailverification.Sender,
	now time.Time,
) *emailverification.Manager {
	t.Helper()
	manager, err := emailverification.NewManager(store, emailverification.Config{
		Lifetime: time.Hour,
		Sender:   sender,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return manager
}

type messageSender struct {
	messages []emailverification.Message
}

func (sender *messageSender) SendVerification(
	_ context.Context,
	message emailverification.Message,
) error {
	sender.messages = append(sender.messages, message)
	return nil
}

type memoryStore struct {
	mu     sync.Mutex
	user   emailverification.User
	record *emailverification.Record
}

func newMemoryStore(user emailverification.User) *memoryStore {
	return &memoryStore{user: user}
}

func (store *memoryStore) FindUserByEmail(
	_ context.Context,
	normalizedEmail string,
) (emailverification.User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.user.ID == "" || store.user.Email != normalizedEmail {
		return emailverification.User{}, emailverification.ErrNotFound
	}
	return store.user, nil
}

func (store *memoryStore) Issue(_ context.Context, record emailverification.Record) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.user.Verified {
		return emailverification.ErrAlreadyVerified
	}
	copy := record
	store.record = &copy
	return nil
}

func (store *memoryStore) Verify(
	_ context.Context,
	tokenHash emailverification.TokenHash,
	verifiedAt time.Time,
) (emailverification.User, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.record == nil || store.record.TokenHash != tokenHash ||
		!verifiedAt.Before(store.record.ExpiresAt) || store.user.Email != store.record.Email {
		return emailverification.User{}, emailverification.ErrInactiveToken
	}
	store.user.Verified = true
	store.record = nil
	return store.user, nil
}

func (store *memoryStore) currentRecord() emailverification.Record {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.record == nil {
		return emailverification.Record{}
	}
	return *store.record
}

func (store *memoryStore) changeEmail(email string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.user.Email = email
}

func (store *memoryStore) expireCurrent() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.record.ExpiresAt = store.record.CreatedAt
}
