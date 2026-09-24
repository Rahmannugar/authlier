// Package emailverification manages email ownership verification.
package emailverification

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
	"github.com/Rahmannugar/authlier/token"
)

const (
	issueAttempts        = 3
	otpDigits            = 6
	minimumOTPSecretSize = 32
)

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

type DeliveryMethod string

const (
	DeliveryMethodLink DeliveryMethod = "link"
	DeliveryMethodOTP  DeliveryMethod = "otp"
)

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

// Issue replaces the user's earlier credential. Verify accepts its current
// hash once before expiry and marks the same email as verified in one storage operation.
type Store interface {
	FindUserByEmail(ctx context.Context, normalizedEmail string) (User, error)
	Issue(ctx context.Context, record Record) error
	Verify(ctx context.Context, tokenHash TokenHash, verifiedAt time.Time) (User, error)
}

type Message struct {
	UserID    string
	Email     string
	Token     string
	Code      string
	URL       string
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
	Delivery       DeliveryMethod
	OTPSecret      []byte
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
	delivery       DeliveryMethod
	otpSecret      []byte
	lifetime       time.Duration
	now            func() time.Time
}

type RequestInput struct {
	Email     string
	SourceKey string
}

type VerifyInput struct {
	Token     string
	Email     string
	Code      string
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
	if config.Delivery == "" {
		config.Delivery = DeliveryMethodLink
	}
	if config.Delivery != DeliveryMethodLink && config.Delivery != DeliveryMethodOTP {
		return nil, fmt.Errorf("%w: delivery method must be link or otp", ErrInvalidConfig)
	}
	if config.Delivery == DeliveryMethodOTP && config.AttemptGuard == nil {
		return nil, fmt.Errorf("%w: attempt guard is required for OTP delivery", ErrInvalidConfig)
	}
	if config.Delivery == DeliveryMethodOTP && len(config.OTPSecret) < minimumOTPSecretSize {
		return nil, fmt.Errorf(
			"%w: OTP secret must contain at least %d bytes",
			ErrInvalidConfig,
			minimumOTPSecretSize,
		)
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
		delivery:       config.Delivery,
		otpSecret:      append([]byte(nil), config.OTPSecret...),
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
		credential, tokenHash, err := manager.generateCredential(normalizedEmail)
		if err != nil {
			return fmt.Errorf("generate email verification credential: %w", err)
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
			Token:     credential.token,
			Code:      credential.code,
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
	normalizedEmail := ""
	if manager.delivery == DeliveryMethodOTP {
		var err error
		normalizedEmail, err = manager.normalizeEmail(input.Email)
		if err != nil || !emailaddress.Valid(normalizedEmail) {
			normalizedEmail = ""
		}
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationVerify,
		Email:     normalizedEmail,
		SourceKey: input.SourceKey,
	}); err != nil {
		return User{}, err
	}
	tokenHash, err := manager.hashVerificationInput(input, normalizedEmail)
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

type credential struct {
	token string
	code  string
}

func (manager *Manager) generateCredential(email string) (credential, token.Hash, error) {
	if manager.delivery == DeliveryMethodOTP {
		code, err := generateOTP()
		if err != nil {
			return credential{}, token.Hash{}, err
		}
		return credential{code: code}, manager.hashOTP(email, code), nil
	}
	rawToken, hash, err := token.Generate()
	return credential{token: rawToken}, hash, err
}

func (manager *Manager) hashVerificationInput(
	input VerifyInput,
	normalizedEmail string,
) (token.Hash, error) {
	if manager.delivery == DeliveryMethodOTP {
		if normalizedEmail == "" || !validOTP(input.Code) {
			return token.Hash{}, ErrInvalidToken
		}
		return manager.hashOTP(normalizedEmail, input.Code), nil
	}
	return token.HashToken(input.Token)
}

func generateOTP() (string, error) {
	maximum := new(big.Int).Exp(big.NewInt(10), big.NewInt(otpDigits), nil)
	value, err := rand.Int(rand.Reader, maximum)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", otpDigits, value.Int64()), nil
}

func validOTP(code string) bool {
	if len(code) != otpDigits {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (manager *Manager) hashOTP(email, code string) token.Hash {
	hash := hmac.New(sha256.New, manager.otpSecret)
	_, _ = hash.Write([]byte(email))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(code))
	var proof token.Hash
	copy(proof[:], hash.Sum(nil))
	return proof
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
