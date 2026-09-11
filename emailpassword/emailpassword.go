// Package emailpassword orchestrates email and password registration and login.
package emailpassword

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	passwordhash "github.com/Rahmannugar/authlier/password"
)

const maximumEmailLength = 254

var (
	ErrAttemptBlocked          = errors.New("authentication attempt blocked")
	ErrConflict                = errors.New("email/password conflict")
	ErrInvalidConfig           = errors.New("invalid email/password configuration")
	ErrInvalidCredentials      = errors.New("invalid email or password")
	ErrInvalidInput            = errors.New("invalid email/password input")
	ErrInvalidRecord           = errors.New("invalid email/password record")
	ErrNotFound                = errors.New("email identity not found")
	ErrRegistrationUnavailable = errors.New("registration unavailable")
)

type User struct {
	ID    string
	Email string
}

type PasswordCredential struct {
	UserID       string
	PasswordHash string
}

type Registration struct {
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// Store registers users and credentials atomically and replaces hashes with compare-and-swap.
type Store interface {
	Register(ctx context.Context, registration Registration) (User, error)
	FindByEmail(ctx context.Context, normalizedEmail string) (User, PasswordCredential, error)
	ReplacePasswordHash(
		ctx context.Context,
		userID string,
		currentHash string,
		replacementHash string,
		updatedAt time.Time,
	) error
}

type Passwords interface {
	Hash(plainPassword string) (string, error)
	Verify(plainPassword, encodedHash string) (passwordhash.Verification, error)
}

type Operation string

const (
	OperationRegister Operation = "register"
	OperationLogin    Operation = "login"
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
	EventRegistrationRejected  EventType = "registration_rejected"
	EventRegistrationSucceeded EventType = "registration_succeeded"
	EventLoginFailed           EventType = "login_failed"
	EventLoginSucceeded        EventType = "login_succeeded"
	EventPasswordRehashed      EventType = "password_rehashed"
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

type EmailNormalizer func(rawEmail string) (string, error)

type Config struct {
	Passwords      Passwords
	AttemptGuard   AttemptGuard
	SecurityEvents SecurityEventSink
	NormalizeEmail EmailNormalizer
	Now            func() time.Time
}

type Manager struct {
	store          Store
	passwords      Passwords
	attemptGuard   AttemptGuard
	securityEvents SecurityEventSink
	normalizeEmail EmailNormalizer
	dummyHash      string
	now            func() time.Time
}

type RegisterInput struct {
	Email     string
	Password  string
	SourceKey string
}

type LoginInput struct {
	Email     string
	Password  string
	SourceKey string
}

type LoginResult struct {
	User             User
	PasswordRehashed bool
}

func NewManager(store Store, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}

	passwords := config.Passwords
	if passwords == nil {
		passwords = defaultPasswords{}
	}
	normalizeEmail := config.NormalizeEmail
	if normalizeEmail == nil {
		normalizeEmail = NormalizeEmail
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}

	// Keep unknown-identity failures on the real password-verification path.
	dummyHash, err := passwords.Hash("authlier dummy password for unknown identities")
	if err != nil {
		return nil, fmt.Errorf("%w: create dummy password hash: %w", ErrInvalidConfig, err)
	}
	if strings.TrimSpace(dummyHash) == "" {
		return nil, fmt.Errorf("%w: password hasher returned an empty dummy hash", ErrInvalidConfig)
	}

	return &Manager{
		store:          store,
		passwords:      passwords,
		attemptGuard:   config.AttemptGuard,
		securityEvents: config.SecurityEvents,
		normalizeEmail: normalizeEmail,
		dummyHash:      dummyHash,
		now:            now,
	}, nil
}

// Register hashes before checking durable identity uniqueness.
func (manager *Manager) Register(ctx context.Context, input RegisterInput) (User, error) {
	normalizedEmail, err := manager.normalizeAndValidateEmail(input.Email)
	if err != nil || input.Password == "" {
		return User{}, ErrInvalidInput
	}
	attempt := Attempt{Operation: OperationRegister, Email: normalizedEmail, SourceKey: input.SourceKey}
	if err := manager.checkAttempt(ctx, attempt); err != nil {
		return User{}, err
	}

	encodedHash, err := manager.passwords.Hash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("hash registration password: %w", err)
	}
	user, err := manager.store.Register(ctx, Registration{
		Email:        normalizedEmail,
		PasswordHash: encodedHash,
		CreatedAt:    manager.now().UTC(),
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			manager.record(ctx, EventRegistrationRejected, "", input.SourceKey)
			return User{}, ErrRegistrationUnavailable
		}
		return User{}, fmt.Errorf("register email identity: %w", err)
	}
	if !validUser(user) || user.Email != normalizedEmail {
		return User{}, ErrInvalidRecord
	}

	manager.record(ctx, EventRegistrationSucceeded, user.ID, input.SourceKey)
	return user, nil
}

// Login returns the same credential error for unknown emails and wrong passwords.
func (manager *Manager) Login(ctx context.Context, input LoginInput) (LoginResult, error) {
	normalizedEmail, normalizationErr := manager.normalizeAndValidateEmail(input.Email)
	attempt := Attempt{Operation: OperationLogin, Email: normalizedEmail, SourceKey: input.SourceKey}
	if err := manager.checkAttempt(ctx, attempt); err != nil {
		return LoginResult{}, err
	}

	var user User
	var credential PasswordCredential
	lookupErr := error(ErrNotFound)
	if normalizationErr == nil {
		user, credential, lookupErr = manager.store.FindByEmail(ctx, normalizedEmail)
	}
	encodedHash := manager.dummyHash
	identityExists := lookupErr == nil && normalizationErr == nil
	if identityExists {
		if !validUser(user) || user.Email != normalizedEmail || !validCredential(user, credential) {
			return LoginResult{}, ErrInvalidRecord
		}
		encodedHash = credential.PasswordHash
	} else if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return LoginResult{}, fmt.Errorf("find email identity: %w", lookupErr)
	}

	verification, err := manager.passwords.Verify(input.Password, encodedHash)
	if err != nil {
		if identityExists {
			manager.record(ctx, EventLoginFailed, user.ID, input.SourceKey)
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, ErrInvalidCredentials
	}
	if !identityExists || !verification.Matches {
		subjectID := ""
		if identityExists {
			subjectID = user.ID
		}
		manager.record(ctx, EventLoginFailed, subjectID, input.SourceKey)
		return LoginResult{}, ErrInvalidCredentials
	}

	result := LoginResult{User: user}
	if verification.NeedsRehash {
		replacementHash, err := manager.passwords.Hash(input.Password)
		if err != nil {
			return LoginResult{}, fmt.Errorf("rehash login password: %w", err)
		}
		err = manager.store.ReplacePasswordHash(
			ctx,
			user.ID,
			credential.PasswordHash,
			replacementHash,
			manager.now().UTC(),
		)
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			manager.record(ctx, EventLoginFailed, user.ID, input.SourceKey)
			return LoginResult{}, ErrInvalidCredentials
		}
		if err != nil {
			return LoginResult{}, fmt.Errorf("replace password hash: %w", err)
		}
		result.PasswordRehashed = true
		manager.record(ctx, EventPasswordRehashed, user.ID, input.SourceKey)
	}

	manager.record(ctx, EventLoginSucceeded, user.ID, input.SourceKey)
	return result, nil
}

func NormalizeEmail(rawEmail string) (string, error) {
	trimmed := strings.TrimSpace(rawEmail)
	normalizedEmail := strings.ToLower(trimmed)
	if !validNormalizedEmail(normalizedEmail) {
		return "", ErrInvalidInput
	}
	return normalizedEmail, nil
}

func (manager *Manager) normalizeAndValidateEmail(rawEmail string) (string, error) {
	normalizedEmail, err := manager.normalizeEmail(rawEmail)
	if err != nil {
		return "", ErrInvalidInput
	}
	if !validNormalizedEmail(normalizedEmail) {
		return "", ErrInvalidInput
	}
	return normalizedEmail, nil
}

func validNormalizedEmail(normalizedEmail string) bool {
	if normalizedEmail == "" || normalizedEmail != strings.TrimSpace(normalizedEmail) ||
		len(normalizedEmail) > maximumEmailLength || !utf8.ValidString(normalizedEmail) {
		return false
	}
	parsed, err := mail.ParseAddress(normalizedEmail)
	return err == nil && parsed.Address == normalizedEmail
}

func (manager *Manager) checkAttempt(ctx context.Context, attempt Attempt) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, attempt); err != nil {
		return fmt.Errorf("check %s attempt: %w", attempt.Operation, err)
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

func validUser(user User) bool {
	return strings.TrimSpace(user.ID) != "" && strings.TrimSpace(user.Email) != ""
}

func validCredential(user User, credential PasswordCredential) bool {
	return credential.UserID == user.ID && strings.TrimSpace(credential.PasswordHash) != ""
}

type defaultPasswords struct{}

func (defaultPasswords) Hash(plainPassword string) (string, error) {
	return passwordhash.Hash(plainPassword)
}

func (defaultPasswords) Verify(
	plainPassword string,
	encodedHash string,
) (passwordhash.Verification, error) {
	return passwordhash.Verify(plainPassword, encodedHash)
}
