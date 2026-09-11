// Package totp manages authenticator-app MFA and recovery codes.
package totp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/token"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	otplibrary "github.com/pquerna/otp/totp"
)

const (
	challengeAttempts = 3
	periodSeconds     = 30
	recoveryCodeBytes = 16
)

var (
	ErrAlreadyEnabled     = errors.New("TOTP is already enabled")
	ErrAttemptBlocked     = errors.New("TOTP attempt blocked")
	ErrConflict           = errors.New("TOTP record conflict")
	ErrInactiveChallenge  = errors.New("TOTP challenge is inactive")
	ErrInactiveEnrollment = errors.New("TOTP enrollment is inactive")
	ErrInvalidChallenge   = errors.New("invalid or expired TOTP challenge")
	ErrInvalidCode        = errors.New("invalid TOTP or recovery code")
	ErrInvalidConfig      = errors.New("invalid TOTP configuration")
	ErrInvalidInput       = errors.New("invalid TOTP input")
	ErrInvalidRecord      = errors.New("invalid TOTP record")
	ErrNotFound           = errors.New("TOTP record not found")
)

type ChallengeHash token.Hash
type RecoveryCodeHash [32]byte

type Enrollment struct {
	SubjectID string
	Secret    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Credential struct {
	SubjectID          string
	Secret             string
	EnabledAt          time.Time
	LastUsedCounter    uint64
	HasLastUsedCounter bool
}

type Challenge struct {
	SubjectID string
	TokenHash ChallengeHash
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store encrypts TOTP secrets at rest. Enable consumes the enrollment;
// challenge completion and replay protection are atomic.
type Store interface {
	BeginEnrollment(ctx context.Context, enrollment Enrollment) error
	FindEnrollment(ctx context.Context, subjectID string) (Enrollment, error)
	Enable(ctx context.Context, subjectID string, confirmedCounter uint64, recoveryCodes []RecoveryCodeHash, enabledAt time.Time) error
	Disable(ctx context.Context, subjectID string, disabledAt time.Time) error
	CreateChallenge(ctx context.Context, challenge Challenge) error
	FindChallenge(ctx context.Context, challengeHash ChallengeHash) (Challenge, Credential, error)
	CompleteCode(ctx context.Context, challengeHash ChallengeHash, counter uint64, completedAt time.Time) (string, error)
	CompleteRecovery(ctx context.Context, challengeHash ChallengeHash, recoveryCode RecoveryCodeHash, completedAt time.Time) (string, error)
}

type Operation string

const (
	OperationConfirmEnrollment Operation = "confirm_enrollment"
	OperationVerifyCode        Operation = "verify_code"
	OperationUseRecovery       Operation = "use_recovery"
)

type Attempt struct {
	Operation Operation
	SubjectID string
	SourceKey string
}

type AttemptGuard interface {
	Check(ctx context.Context, attempt Attempt) error
}

type EventType string

const (
	EventEnabled      EventType = "totp_enabled"
	EventDisabled     EventType = "totp_disabled"
	EventFailed       EventType = "totp_failed"
	EventVerified     EventType = "totp_verified"
	EventRecoveryUsed EventType = "totp_recovery_used"
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
	Issuer             string
	EnrollmentLifetime time.Duration
	ChallengeLifetime  time.Duration
	RecoveryCodeCount  int
	AttemptGuard       AttemptGuard
	SecurityEvents     SecurityEventSink
	Now                func() time.Time
}

type Manager struct {
	store              Store
	issuer             string
	enrollmentLifetime time.Duration
	challengeLifetime  time.Duration
	recoveryCodeCount  int
	attemptGuard       AttemptGuard
	securityEvents     SecurityEventSink
	now                func() time.Time
}

type EnrollmentStarted struct {
	Secret    string
	URI       string
	ExpiresAt time.Time
}

type EnrollmentConfirmed struct {
	RecoveryCodes []string
}

type ChallengeStarted struct {
	Token     string
	ExpiresAt time.Time
}

type VerifyInput struct {
	ChallengeToken string
	Code           string
	SourceKey      string
}

type Authentication struct {
	SubjectID        string
	UsedRecoveryCode bool
}

func NewManager(store Store, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	issuer := strings.TrimSpace(config.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidConfig)
	}
	if config.EnrollmentLifetime <= 0 || config.ChallengeLifetime <= 0 {
		return nil, fmt.Errorf("%w: lifetimes must be positive", ErrInvalidConfig)
	}
	if config.RecoveryCodeCount <= 0 {
		return nil, fmt.Errorf("%w: recovery code count must be positive", ErrInvalidConfig)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		store:              store,
		issuer:             issuer,
		enrollmentLifetime: config.EnrollmentLifetime,
		challengeLifetime:  config.ChallengeLifetime,
		recoveryCodeCount:  config.RecoveryCodeCount,
		attemptGuard:       config.AttemptGuard,
		securityEvents:     config.SecurityEvents,
		now:                now,
	}, nil
}

func (manager *Manager) BeginEnrollment(
	ctx context.Context,
	subjectID string,
	accountName string,
) (EnrollmentStarted, error) {
	subjectID = strings.TrimSpace(subjectID)
	accountName = strings.TrimSpace(accountName)
	if subjectID == "" || accountName == "" {
		return EnrollmentStarted{}, ErrInvalidInput
	}
	key, err := otplibrary.Generate(otplibrary.GenerateOpts{
		Issuer:      manager.issuer,
		AccountName: accountName,
		SecretSize:  20,
	})
	if err != nil {
		return EnrollmentStarted{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	now := manager.now().UTC()
	enrollment := Enrollment{
		SubjectID: subjectID,
		Secret:    key.Secret(),
		CreatedAt: now,
		ExpiresAt: now.Add(manager.enrollmentLifetime),
	}
	if err := manager.store.BeginEnrollment(ctx, enrollment); err != nil {
		return EnrollmentStarted{}, fmt.Errorf("begin TOTP enrollment: %w", err)
	}
	return EnrollmentStarted{
		Secret:    key.Secret(),
		URI:       key.URL(),
		ExpiresAt: enrollment.ExpiresAt,
	}, nil
}

func (manager *Manager) ConfirmEnrollment(
	ctx context.Context,
	subjectID string,
	code string,
	sourceKey string,
) (EnrollmentConfirmed, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return EnrollmentConfirmed{}, ErrInvalidInput
	}
	if err := manager.checkAttempt(ctx, OperationConfirmEnrollment, subjectID, sourceKey); err != nil {
		return EnrollmentConfirmed{}, err
	}
	enrollment, err := manager.store.FindEnrollment(ctx, subjectID)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveEnrollment) {
		manager.record(ctx, EventFailed, subjectID, sourceKey)
		return EnrollmentConfirmed{}, ErrInvalidCode
	}
	if err != nil {
		return EnrollmentConfirmed{}, fmt.Errorf("find TOTP enrollment: %w", err)
	}
	now := manager.now().UTC()
	if !validEnrollment(enrollment, subjectID) {
		return EnrollmentConfirmed{}, ErrInvalidRecord
	}
	if !now.Before(enrollment.ExpiresAt) {
		manager.record(ctx, EventFailed, subjectID, sourceKey)
		return EnrollmentConfirmed{}, ErrInvalidCode
	}
	confirmedCounter, matched, matchErr := matchCounter(enrollment.Secret, code, now)
	if matchErr != nil {
		return EnrollmentConfirmed{}, ErrInvalidRecord
	}
	if !matched {
		manager.record(ctx, EventFailed, subjectID, sourceKey)
		return EnrollmentConfirmed{}, ErrInvalidCode
	}
	codes, hashes, err := generateRecoveryCodes(manager.recoveryCodeCount)
	if err != nil {
		return EnrollmentConfirmed{}, fmt.Errorf("generate recovery codes: %w", err)
	}
	if err := manager.store.Enable(ctx, subjectID, confirmedCounter, hashes, now); err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveEnrollment) {
			return EnrollmentConfirmed{}, ErrInvalidCode
		}
		return EnrollmentConfirmed{}, fmt.Errorf("enable TOTP: %w", err)
	}
	manager.record(ctx, EventEnabled, subjectID, sourceKey)
	return EnrollmentConfirmed{RecoveryCodes: codes}, nil
}

func (manager *Manager) BeginChallenge(ctx context.Context, subjectID string) (ChallengeStarted, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return ChallengeStarted{}, ErrInvalidInput
	}
	for range challengeAttempts {
		rawToken, tokenHash, err := token.Generate()
		if err != nil {
			return ChallengeStarted{}, fmt.Errorf("generate TOTP challenge: %w", err)
		}
		now := manager.now().UTC()
		challenge := Challenge{
			SubjectID: subjectID,
			TokenHash: ChallengeHash(tokenHash),
			CreatedAt: now,
			ExpiresAt: now.Add(manager.challengeLifetime),
		}
		if err := manager.store.CreateChallenge(ctx, challenge); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return ChallengeStarted{}, fmt.Errorf("store TOTP challenge: %w", err)
		}
		return ChallengeStarted{Token: rawToken, ExpiresAt: challenge.ExpiresAt}, nil
	}
	return ChallengeStarted{}, fmt.Errorf("create unique TOTP challenge: %w", ErrConflict)
}

func (manager *Manager) Verify(ctx context.Context, input VerifyInput) (Authentication, error) {
	challenge, credential, challengeHash, err := manager.findChallenge(ctx, input.ChallengeToken)
	if err != nil {
		return Authentication{}, err
	}
	if err := manager.checkAttempt(ctx, OperationVerifyCode, challenge.SubjectID, input.SourceKey); err != nil {
		return Authentication{}, err
	}
	now := manager.now().UTC()
	counter, matched, err := matchCounter(credential.Secret, input.Code, now)
	if err != nil {
		return Authentication{}, ErrInvalidRecord
	}
	if !matched || credential.HasLastUsedCounter && counter <= credential.LastUsedCounter {
		manager.record(ctx, EventFailed, challenge.SubjectID, input.SourceKey)
		return Authentication{}, ErrInvalidCode
	}
	subjectID, err := manager.store.CompleteCode(ctx, challengeHash, counter, now)
	if err != nil {
		completionErr := manager.completionError(err)
		if errors.Is(completionErr, ErrInvalidCode) {
			manager.record(ctx, EventFailed, challenge.SubjectID, input.SourceKey)
		}
		return Authentication{}, completionErr
	}
	if subjectID != challenge.SubjectID {
		return Authentication{}, ErrInvalidRecord
	}
	manager.record(ctx, EventVerified, subjectID, input.SourceKey)
	return Authentication{SubjectID: subjectID}, nil
}

func (manager *Manager) Recover(ctx context.Context, input VerifyInput) (Authentication, error) {
	challenge, _, challengeHash, err := manager.findChallenge(ctx, input.ChallengeToken)
	if err != nil {
		return Authentication{}, err
	}
	if err := manager.checkAttempt(ctx, OperationUseRecovery, challenge.SubjectID, input.SourceKey); err != nil {
		return Authentication{}, err
	}
	recoveryHash, err := HashRecoveryCode(input.Code)
	if err != nil {
		manager.record(ctx, EventFailed, challenge.SubjectID, input.SourceKey)
		return Authentication{}, ErrInvalidCode
	}
	subjectID, err := manager.store.CompleteRecovery(
		ctx,
		challengeHash,
		recoveryHash,
		manager.now().UTC(),
	)
	if err != nil {
		completionErr := manager.completionError(err)
		if errors.Is(completionErr, ErrInvalidCode) {
			manager.record(ctx, EventFailed, challenge.SubjectID, input.SourceKey)
		}
		return Authentication{}, completionErr
	}
	if subjectID != challenge.SubjectID {
		return Authentication{}, ErrInvalidRecord
	}
	manager.record(ctx, EventRecoveryUsed, subjectID, input.SourceKey)
	return Authentication{SubjectID: subjectID, UsedRecoveryCode: true}, nil
}

func (manager *Manager) Disable(ctx context.Context, subjectID, sourceKey string) error {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return ErrInvalidInput
	}
	if err := manager.store.Disable(ctx, subjectID, manager.now().UTC()); err != nil {
		return fmt.Errorf("disable TOTP: %w", err)
	}
	manager.record(ctx, EventDisabled, subjectID, sourceKey)
	return nil
}

func HashRecoveryCode(rawCode string) (RecoveryCodeHash, error) {
	rawCode = strings.TrimSpace(rawCode)
	if rawCode == "" {
		return RecoveryCodeHash{}, ErrInvalidCode
	}
	return sha256.Sum256([]byte(rawCode)), nil
}

func (manager *Manager) findChallenge(
	ctx context.Context,
	rawToken string,
) (Challenge, Credential, ChallengeHash, error) {
	tokenHash, err := token.HashToken(rawToken)
	if err != nil {
		return Challenge{}, Credential{}, ChallengeHash{}, ErrInvalidChallenge
	}
	challengeHash := ChallengeHash(tokenHash)
	challenge, credential, err := manager.store.FindChallenge(ctx, challengeHash)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveChallenge) {
		return Challenge{}, Credential{}, ChallengeHash{}, ErrInvalidChallenge
	}
	if err != nil {
		return Challenge{}, Credential{}, ChallengeHash{}, fmt.Errorf("find TOTP challenge: %w", err)
	}
	now := manager.now().UTC()
	if !validChallenge(challenge, challengeHash) || !validCredential(credential, challenge.SubjectID) {
		return Challenge{}, Credential{}, ChallengeHash{}, ErrInvalidRecord
	}
	if !now.Before(challenge.ExpiresAt) {
		return Challenge{}, Credential{}, ChallengeHash{}, ErrInvalidChallenge
	}
	return challenge, credential, challengeHash, nil
}

func (manager *Manager) completionError(err error) error {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveChallenge) {
		return ErrInvalidChallenge
	}
	if errors.Is(err, ErrInvalidCode) {
		return ErrInvalidCode
	}
	return fmt.Errorf("complete TOTP challenge: %w", err)
}

func (manager *Manager) checkAttempt(
	ctx context.Context,
	operation Operation,
	subjectID string,
	sourceKey string,
) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, Attempt{
		Operation: operation,
		SubjectID: subjectID,
		SourceKey: sourceKey,
	}); err != nil {
		return fmt.Errorf("check TOTP attempt: %w", err)
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

func validEnrollment(enrollment Enrollment, subjectID string) bool {
	return enrollment.SubjectID == subjectID &&
		strings.TrimSpace(enrollment.Secret) != "" &&
		!enrollment.CreatedAt.IsZero() &&
		enrollment.ExpiresAt.After(enrollment.CreatedAt)
}

func validChallenge(challenge Challenge, expectedHash ChallengeHash) bool {
	return strings.TrimSpace(challenge.SubjectID) != "" &&
		challenge.TokenHash == expectedHash &&
		!challenge.CreatedAt.IsZero() &&
		challenge.ExpiresAt.After(challenge.CreatedAt)
}

func validCredential(credential Credential, subjectID string) bool {
	return credential.SubjectID == subjectID &&
		strings.TrimSpace(credential.Secret) != "" &&
		!credential.EnabledAt.IsZero()
}

func matchCounter(secret, code string, at time.Time) (uint64, bool, error) {
	if len(code) != 6 {
		return 0, false, nil
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return 0, false, nil
		}
	}
	currentCounter := at.Unix() / periodSeconds
	if currentCounter < 1 {
		return 0, false, nil
	}
	options := hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, counter := range []uint64{
		uint64(currentCounter),
		uint64(currentCounter - 1),
		uint64(currentCounter + 1),
	} {
		matched, err := hotp.ValidateCustom(code, counter, secret, options)
		if err != nil {
			return 0, false, err
		}
		if matched {
			return counter, true, nil
		}
	}
	return 0, false, nil
}

func generateRecoveryCodes(count int) ([]string, []RecoveryCodeHash, error) {
	codes := make([]string, 0, count)
	hashes := make([]RecoveryCodeHash, 0, count)
	seen := make(map[RecoveryCodeHash]struct{}, count)
	for len(codes) < count {
		random := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(random); err != nil {
			return nil, nil, err
		}
		code := base64.RawURLEncoding.EncodeToString(random)
		hash, _ := HashRecoveryCode(code)
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		codes = append(codes, code)
		hashes = append(hashes, hash)
	}
	return codes, hashes, nil
}
