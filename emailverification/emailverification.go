// Package emailverification manages email ownership verification.
package emailverification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
	"github.com/Rahmannugar/authlier/token"
)

const issueAttempts = 3

var (
	ErrAlreadyVerified = errors.New("email already verified")
	ErrAttemptBlocked  = errors.New("email verification attempt blocked")
	ErrConflict        = errors.New("email verification conflict")
	ErrInactiveToken   = errors.New("email verification token is inactive")
	ErrInvalidConfig   = errors.New("invalid email verification configuration")
	ErrInvalidRecord   = errors.New("invalid email verification record")
	ErrInvalidToken    = token.ErrInvalidToken
	ErrNotFound        = errors.New("email verification record not found")
)

type TokenHash token.Hash

type User struct {
	ID       string
	Email    string
	Verified bool
}

type Record struct {
	UserID    string
	Email     string
	TokenHash TokenHash
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Issue replaces the user's earlier token. Verify accepts the current token
// once before expiry and marks the same email as verified in one storage operation.
type Store interface {
	FindUserByEmail(ctx context.Context, normalizedEmail string) (User, error)
	Issue(ctx context.Context, record Record) error
	Verify(ctx context.Context, tokenHash TokenHash, verifiedAt time.Time) (User, error)
}

type Message struct {
	UserID    string
	Email     string
	Token     string
	ExpiresAt time.Time
}

type Sender interface {
	SendVerification(ctx context.Context, message Message) error
}

type Operation string

const (
	OperationRequest Operation = "request"
	OperationVerify  Operation = "verify"
)

type Attempt struct {
	Operation Operation
	Email     string
	SourceKey string
}

type AttemptGuard interface {
	Check(ctx context.Context, attempt Attempt) error
}

type EventType string

const (
	EventMessageSent  EventType = "verification_message_sent"
	EventVerified     EventType = "email_verified"
	EventVerifyFailed EventType = "email_verification_failed"
)

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
	Lifetime       time.Duration
	Sender         Sender
	AttemptGuard   AttemptGuard
	SecurityEvents SecurityEventSink
	NormalizeEmail emailaddress.Normalizer
	Now            func() time.Time
}

type Manager struct {
	store          Store
	sender         Sender
	attemptGuard   AttemptGuard
	securityEvents SecurityEventSink
	normalizeEmail emailaddress.Normalizer
	lifetime       time.Duration
	now            func() time.Time
}

type RequestInput struct {
	Email     string
	SourceKey string
}

type VerifyInput struct {
	Token     string
	SourceKey string
}

func NewManager(store Store, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if config.Sender == nil {
		return nil, fmt.Errorf("%w: sender is required", ErrInvalidConfig)
	}
	if config.Lifetime <= 0 {
		return nil, fmt.Errorf("%w: lifetime must be positive", ErrInvalidConfig)
	}
	normalizeEmail := config.NormalizeEmail
	if normalizeEmail == nil {
		normalizeEmail = emailaddress.Normalize
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		store:          store,
		sender:         config.Sender,
		attemptGuard:   config.AttemptGuard,
		securityEvents: config.SecurityEvents,
		normalizeEmail: normalizeEmail,
		lifetime:       config.Lifetime,
		now:            now,
	}, nil
}

func (manager *Manager) Request(ctx context.Context, input RequestInput) error {
	normalizedEmail, normalizationErr := manager.normalizeEmail(input.Email)
	if normalizationErr != nil || !emailaddress.Valid(normalizedEmail) {
		normalizedEmail = ""
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationRequest,
		Email:     normalizedEmail,
		SourceKey: input.SourceKey,
	}); err != nil {
		return err
	}
	if normalizedEmail == "" {
		return nil
	}

	user, err := manager.store.FindUserByEmail(ctx, normalizedEmail)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find user for email verification: %w", err)
	}
	if err := validUser(user, normalizedEmail); err != nil {
		return err
	}
	if user.Verified {
		return nil
	}

	for range issueAttempts {
		rawToken, tokenHash, err := token.Generate()
		if err != nil {
			return fmt.Errorf("generate email verification token: %w", err)
		}
		now := manager.now().UTC()
		record := Record{
			UserID:    user.ID,
			Email:     user.Email,
			TokenHash: TokenHash(tokenHash),
			CreatedAt: now,
			ExpiresAt: now.Add(manager.lifetime),
		}
		err = manager.store.Issue(ctx, record)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if errors.Is(err, ErrAlreadyVerified) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("store email verification token: %w", err)
		}
		if err := manager.sender.SendVerification(ctx, Message{
			UserID:    user.ID,
			Email:     user.Email,
			Token:     rawToken,
			ExpiresAt: record.ExpiresAt,
		}); err != nil {
			return fmt.Errorf("send email verification message: %w", err)
		}
		manager.record(ctx, EventMessageSent, user.ID, input.SourceKey)
		return nil
	}
	return fmt.Errorf("create unique email verification token: %w", ErrConflict)
}

func (manager *Manager) Verify(ctx context.Context, input VerifyInput) (User, error) {
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationVerify,
		SourceKey: input.SourceKey,
	}); err != nil {
		return User{}, err
	}
	tokenHash, err := token.HashToken(input.Token)
	if err != nil {
		manager.record(ctx, EventVerifyFailed, "", input.SourceKey)
		return User{}, ErrInvalidToken
	}
	user, err := manager.store.Verify(ctx, TokenHash(tokenHash), manager.now().UTC())
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveToken) {
		manager.record(ctx, EventVerifyFailed, "", input.SourceKey)
		return User{}, ErrInvalidToken
	}
	if err != nil {
		return User{}, fmt.Errorf("verify email: %w", err)
	}
	if strings.TrimSpace(user.ID) == "" || !emailaddress.Valid(user.Email) || !user.Verified {
		return User{}, ErrInvalidRecord
	}
	manager.record(ctx, EventVerified, user.ID, input.SourceKey)
	return user, nil
}

func (manager *Manager) IsVerified(ctx context.Context, email string) (bool, error) {
	normalizedEmail, err := manager.normalizeEmail(email)
	if err != nil || !emailaddress.Valid(normalizedEmail) {
		return false, nil
	}
	user, err := manager.store.FindUserByEmail(ctx, normalizedEmail)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find email verification status: %w", err)
	}
	if err := validUser(user, normalizedEmail); err != nil {
		return false, err
	}
	return user.Verified, nil
}

func (manager *Manager) checkAttempt(ctx context.Context, attempt Attempt) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, attempt); err != nil {
		return fmt.Errorf("check email verification attempt: %w", err)
	}
	return nil
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

func validUser(user User, expectedEmail string) error {
	if strings.TrimSpace(user.ID) == "" || user.Email != expectedEmail || !emailaddress.Valid(user.Email) {
		return ErrInvalidRecord
	}
	return nil
}
