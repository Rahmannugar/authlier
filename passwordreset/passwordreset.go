// Package passwordreset manages password recovery with emailed tokens.
package passwordreset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
	passwordhash "github.com/Rahmannugar/authlier/password"
	"github.com/Rahmannugar/authlier/token"
)

const issueAttempts = 3

var (
	ErrAttemptBlocked  = errors.New("password reset attempt blocked")
	ErrConflict        = errors.New("password reset conflict")
	ErrInactiveToken   = errors.New("password reset token is inactive")
	ErrInvalidConfig   = errors.New("invalid password reset configuration")
	ErrInvalidPassword = errors.New("invalid replacement password")
	ErrInvalidRecord   = errors.New("invalid password reset record")
	ErrInvalidToken    = token.ErrInvalidToken
	ErrNotFound        = errors.New("password reset record not found")
)

type TokenHash token.Hash

type User struct {
	ID    string
	Email string
}

type Record struct {
	UserID    string
	Email     string
	TokenHash TokenHash
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Issue replaces the user's earlier token. ResetPassword accepts the current
// token once before expiry, changes the password, and invalidates the user's
// other reset tokens in one storage operation.
type Store interface {
	FindUserByEmail(ctx context.Context, normalizedEmail string) (User, error)
	Issue(ctx context.Context, record Record) error
	ResetPassword(
		ctx context.Context,
		tokenHash TokenHash,
		passwordHash string,
		resetAt time.Time,
	) (User, error)
}

type Passwords interface {
	Hash(plainPassword string) (string, error)
}

type Message struct {
	UserID    string
	Email     string
	Token     string
	URL       string
	ExpiresAt time.Time
}

type Sender interface {
	SendPasswordReset(ctx context.Context, message Message) error
}

type Operation string

const (
	OperationRequest Operation = "request"
	OperationReset   Operation = "reset"
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
	EventMessageSent EventType = "password_reset_message_sent"
	EventResetFailed EventType = "password_reset_failed"
	EventReset       EventType = "password_reset"
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

type PasswordValidator func(plainPassword string) error

type Config struct {
	Lifetime         time.Duration
	Sender           Sender
	Passwords        Passwords
	ValidatePassword PasswordValidator
	AttemptGuard     AttemptGuard
	SecurityEvents   SecurityEventSink
	NormalizeEmail   emailaddress.Normalizer
	Now              func() time.Time
}

type Manager struct {
	store            Store
	sender           Sender
	passwords        Passwords
	validatePassword PasswordValidator
	attemptGuard     AttemptGuard
	securityEvents   SecurityEventSink
	normalizeEmail   emailaddress.Normalizer
	lifetime         time.Duration
	now              func() time.Time
}

type RequestInput struct {
	Email     string
	SourceKey string
}

type ResetInput struct {
	Token       string
	NewPassword string
	SourceKey   string
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
	passwords := config.Passwords
	if passwords == nil {
		passwords = defaultPasswords{}
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
		store:            store,
		sender:           config.Sender,
		passwords:        passwords,
		validatePassword: config.ValidatePassword,
		attemptGuard:     config.AttemptGuard,
		securityEvents:   config.SecurityEvents,
		normalizeEmail:   normalizeEmail,
		lifetime:         config.Lifetime,
		now:              now,
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
		return fmt.Errorf("find user for password reset: %w", err)
	}
	if err := validUser(user, normalizedEmail); err != nil {
		return err
	}

	for range issueAttempts {
		rawToken, tokenHash, err := token.Generate()
		if err != nil {
			return fmt.Errorf("generate password reset token: %w", err)
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
		if err != nil {
			return fmt.Errorf("store password reset token: %w", err)
		}
		if err := manager.sender.SendPasswordReset(ctx, Message{
			UserID:    user.ID,
			Email:     user.Email,
			Token:     rawToken,
			ExpiresAt: record.ExpiresAt,
		}); err != nil {
			return fmt.Errorf("send password reset message: %w", err)
		}
		manager.record(ctx, EventMessageSent, user.ID, input.SourceKey)
		return nil
	}
	return fmt.Errorf("create unique password reset token: %w", ErrConflict)
}

func (manager *Manager) Reset(ctx context.Context, input ResetInput) (User, error) {
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationReset,
		SourceKey: input.SourceKey,
	}); err != nil {
		return User{}, err
	}
	if input.NewPassword == "" {
		return User{}, ErrInvalidPassword
	}
	if manager.validatePassword != nil {
		if err := manager.validatePassword(input.NewPassword); err != nil {
			return User{}, fmt.Errorf("%w: %w", ErrInvalidPassword, err)
		}
	}
	tokenHash, err := token.HashToken(input.Token)
	if err != nil {
		manager.record(ctx, EventResetFailed, "", input.SourceKey)
		return User{}, ErrInvalidToken
	}
	encodedHash, err := manager.passwords.Hash(input.NewPassword)
	if err != nil {
		return User{}, fmt.Errorf("hash replacement password: %w", err)
	}
	user, err := manager.store.ResetPassword(
		ctx,
		TokenHash(tokenHash),
		encodedHash,
		manager.now().UTC(),
	)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveToken) {
		manager.record(ctx, EventResetFailed, "", input.SourceKey)
		return User{}, ErrInvalidToken
	}
	if err != nil {
		return User{}, fmt.Errorf("reset password: %w", err)
	}
	if strings.TrimSpace(user.ID) == "" || !emailaddress.Valid(user.Email) {
		return User{}, ErrInvalidRecord
	}
	manager.record(ctx, EventReset, user.ID, input.SourceKey)
	return user, nil
}

func (manager *Manager) checkAttempt(ctx context.Context, attempt Attempt) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, attempt); err != nil {
		return fmt.Errorf("check password reset attempt: %w", err)
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

type defaultPasswords struct{}

func (defaultPasswords) Hash(plainPassword string) (string, error) {
	return passwordhash.Hash(plainPassword)
}
