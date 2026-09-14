// Package emailpassword orchestrates email and password authentication.
package emailpassword

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
	passwordhash "github.com/Rahmannugar/authlier/password"
)

var (
	ErrAttemptBlocked          = errors.New("authentication attempt blocked")
	ErrConflict                = errors.New("email/password conflict")
	ErrInvalidConfig           = errors.New("invalid email/password configuration")
	ErrInvalidCredentials      = errors.New("invalid email or password")
	ErrInvalidInput            = errors.New("invalid email/password input")
	ErrInvalidPassword         = errors.New("invalid password")
	ErrInvalidRecord           = errors.New("invalid email/password record")
	ErrLastCredential          = errors.New("cannot remove the last sign-in method")
	ErrNotFound                = errors.New("email identity not found")
	ErrPasswordUnchanged       = errors.New("new password matches current password")
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

// CredentialStore makes account credential writes atomic and preserves another
// sign-in method on removal.
type CredentialStore interface {
	FindBySubject(ctx context.Context, subjectID string) (User, PasswordCredential, error)
	AddPassword(ctx context.Context, subjectID, passwordHash string, addedAt time.Time) (User, error)
	ReplacePasswordHash(
		ctx context.Context,
		userID string,
		currentHash string,
		replacementHash string,
		updatedAt time.Time,
	) error
	RemovePassword(ctx context.Context, subjectID, currentHash string, removedAt time.Time) error
}

type Passwords interface {
	Hash(plainPassword string) (string, error)
	Verify(plainPassword, encodedHash string) (passwordhash.Verification, error)
}

type Operation string

const (
	OperationRegister       Operation = "register"
	OperationLogin          Operation = "login"
	OperationAddPassword    Operation = "add_password"
	OperationChangePassword Operation = "change_password"
	OperationRemovePassword Operation = "remove_password"
)

type Attempt struct {
	Operation Operation
	Email     string
	SubjectID string
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
	EventPasswordAdded         EventType = "password_added"
	EventPasswordChangeFailed  EventType = "password_change_failed"
	EventPasswordChanged       EventType = "password_changed"
	EventPasswordRemovalFailed EventType = "password_removal_failed"
	EventPasswordRemoved       EventType = "password_removed"
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

type EmailNormalizer = emailaddress.Normalizer
type PasswordValidator func(plainPassword string) error

type Config struct {
	Passwords        Passwords
	Credentials      CredentialStore
	ValidatePassword PasswordValidator
	AttemptGuard     AttemptGuard
	SecurityEvents   SecurityEventSink
	NormalizeEmail   EmailNormalizer
	Now              func() time.Time
}

type Manager struct {
	store            Store
	credentials      CredentialStore
	passwords        Passwords
	validatePassword PasswordValidator
	attemptGuard     AttemptGuard
	securityEvents   SecurityEventSink
	normalizeEmail   EmailNormalizer
	dummyHash        string
	now              func() time.Time
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

type ChangePasswordInput struct {
	SubjectID       string
	CurrentPassword string
	NewPassword     string
	SourceKey       string
}

type AddPasswordInput struct {
	SubjectID string
	Password  string
	SourceKey string
}

type RemovePasswordInput struct {
	SubjectID       string
	CurrentPassword string
	SourceKey       string
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
		normalizeEmail = emailaddress.Normalize
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	credentials := config.Credentials
	if credentials == nil {
		credentials, _ = store.(CredentialStore)
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
		store:            store,
		credentials:      credentials,
		passwords:        passwords,
		validatePassword: config.ValidatePassword,
		attemptGuard:     config.AttemptGuard,
		securityEvents:   config.SecurityEvents,
		normalizeEmail:   normalizeEmail,
		dummyHash:        dummyHash,
		now:              now,
	}, nil
}

func (manager *Manager) AddPassword(ctx context.Context, input AddPasswordInput) (User, error) {
	if manager.credentials == nil {
		return User{}, fmt.Errorf("%w: credential store is required", ErrInvalidConfig)
	}
	subjectID := strings.TrimSpace(input.SubjectID)
	if subjectID == "" || input.Password == "" {
		return User{}, ErrInvalidInput
	}
	if err := manager.validate(input.Password); err != nil {
		return User{}, err
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationAddPassword,
		SubjectID: subjectID,
		SourceKey: input.SourceKey,
	}); err != nil {
		return User{}, err
	}
	encodedHash, err := manager.passwords.Hash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("hash added password: %w", err)
	}
	user, err := manager.credentials.AddPassword(ctx, subjectID, encodedHash, manager.now().UTC())
	if err != nil {
		return User{}, fmt.Errorf("add password: %w", err)
	}
	if !validUser(user) || user.ID != subjectID {
		return User{}, ErrInvalidRecord
	}
	manager.record(ctx, EventPasswordAdded, subjectID, input.SourceKey)
	return user, nil
}

// Register hashes before checking durable identity uniqueness.
func (manager *Manager) Register(ctx context.Context, input RegisterInput) (User, error) {
	normalizedEmail, err := manager.normalizeAndValidateEmail(input.Email)
	if err != nil || input.Password == "" {
		return User{}, ErrInvalidInput
	}
	if err := manager.validate(input.Password); err != nil {
		return User{}, err
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

func (manager *Manager) ChangePassword(
	ctx context.Context,
	input ChangePasswordInput,
) (User, error) {
	if manager.credentials == nil {
		return User{}, fmt.Errorf("%w: credential store is required", ErrInvalidConfig)
	}
	subjectID := strings.TrimSpace(input.SubjectID)
	if subjectID == "" || input.CurrentPassword == "" || input.NewPassword == "" {
		return User{}, ErrInvalidInput
	}
	if err := manager.validate(input.NewPassword); err != nil {
		return User{}, err
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationChangePassword,
		SubjectID: subjectID,
		SourceKey: input.SourceKey,
	}); err != nil {
		return User{}, err
	}

	user, credential, err := manager.credentials.FindBySubject(ctx, subjectID)
	if errors.Is(err, ErrNotFound) {
		manager.record(ctx, EventPasswordChangeFailed, subjectID, input.SourceKey)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("find password credential: %w", err)
	}
	if !validUser(user) || user.ID != subjectID || !validCredential(user, credential) {
		return User{}, ErrInvalidRecord
	}

	current, err := manager.passwords.Verify(input.CurrentPassword, credential.PasswordHash)
	if err != nil || !current.Matches {
		manager.record(ctx, EventPasswordChangeFailed, subjectID, input.SourceKey)
		return User{}, ErrInvalidCredentials
	}
	unchanged, err := manager.passwords.Verify(input.NewPassword, credential.PasswordHash)
	if err != nil {
		return User{}, fmt.Errorf("compare replacement password: %w", err)
	}
	if unchanged.Matches {
		return User{}, ErrPasswordUnchanged
	}

	replacementHash, err := manager.passwords.Hash(input.NewPassword)
	if err != nil {
		return User{}, fmt.Errorf("hash replacement password: %w", err)
	}
	if err := manager.credentials.ReplacePasswordHash(
		ctx,
		subjectID,
		credential.PasswordHash,
		replacementHash,
		manager.now().UTC(),
	); err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			manager.record(ctx, EventPasswordChangeFailed, subjectID, input.SourceKey)
			return User{}, ErrInvalidCredentials
		}
		return User{}, fmt.Errorf("replace password: %w", err)
	}

	manager.record(ctx, EventPasswordChanged, subjectID, input.SourceKey)
	return user, nil
}

func (manager *Manager) RemovePassword(ctx context.Context, input RemovePasswordInput) error {
	if manager.credentials == nil {
		return fmt.Errorf("%w: credential store is required", ErrInvalidConfig)
	}
	subjectID := strings.TrimSpace(input.SubjectID)
	if subjectID == "" || input.CurrentPassword == "" {
		return ErrInvalidInput
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationRemovePassword,
		SubjectID: subjectID,
		SourceKey: input.SourceKey,
	}); err != nil {
		return err
	}
	user, credential, err := manager.credentials.FindBySubject(ctx, subjectID)
	if errors.Is(err, ErrNotFound) {
		manager.record(ctx, EventPasswordRemovalFailed, subjectID, input.SourceKey)
		return ErrInvalidCredentials
	}
	if err != nil {
		return fmt.Errorf("find password credential: %w", err)
	}
	if !validUser(user) || user.ID != subjectID || !validCredential(user, credential) {
		return ErrInvalidRecord
	}
	verification, err := manager.passwords.Verify(input.CurrentPassword, credential.PasswordHash)
	if err != nil || !verification.Matches {
		manager.record(ctx, EventPasswordRemovalFailed, subjectID, input.SourceKey)
		return ErrInvalidCredentials
	}
	if err := manager.credentials.RemovePassword(
		ctx,
		subjectID,
		credential.PasswordHash,
		manager.now().UTC(),
	); err != nil {
		if errors.Is(err, ErrLastCredential) {
			return err
		}
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			manager.record(ctx, EventPasswordRemovalFailed, subjectID, input.SourceKey)
			return ErrInvalidCredentials
		}
		return fmt.Errorf("remove password: %w", err)
	}
	manager.record(ctx, EventPasswordRemoved, subjectID, input.SourceKey)
	return nil
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
	normalizedEmail, err := emailaddress.Normalize(rawEmail)
	if err != nil {
		return "", ErrInvalidInput
	}
	return normalizedEmail, nil
}

func (manager *Manager) normalizeAndValidateEmail(rawEmail string) (string, error) {
	normalizedEmail, err := manager.normalizeEmail(rawEmail)
	if err != nil {
		return "", ErrInvalidInput
	}
	if !emailaddress.Valid(normalizedEmail) {
		return "", ErrInvalidInput
	}
	return normalizedEmail, nil
}

func (manager *Manager) validate(plainPassword string) error {
	if manager.validatePassword == nil {
		return nil
	}
	if err := manager.validatePassword(plainPassword); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPassword, err)
	}
	return nil
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
