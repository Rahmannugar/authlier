package totp_test

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/totp"
	otplibrary "github.com/pquerna/otp/totp"
)

var testTime = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func TestEnrollmentRequiresAValidCodeBeforeEnabling(t *testing.T) {
	store := newStore()
	manager := newManager(t, store, func() time.Time { return testTime })

	started, err := manager.BeginEnrollment(context.Background(), "user-1", "owner@example.com")
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	uri, err := url.Parse(started.URI)
	if err != nil {
		t.Fatalf("parse enrollment URI: %v", err)
	}
	if uri.Scheme != "otpauth" || uri.Query().Get("secret") != started.Secret {
		t.Fatalf("invalid enrollment URI: %s", started.URI)
	}
	if _, err := manager.ConfirmEnrollment(context.Background(), "user-1", "000000", "source"); !errors.Is(err, totp.ErrInvalidCode) {
		t.Fatalf("confirm wrong code: got %v, want invalid code", err)
	}
	if store.enabled("user-1") {
		t.Fatal("wrong code enabled TOTP")
	}

	code, err := otplibrary.GenerateCode(started.Secret, testTime)
	if err != nil {
		t.Fatalf("generate enrollment code: %v", err)
	}
	confirmed, err := manager.ConfirmEnrollment(context.Background(), "user-1", code, "source")
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	if len(confirmed.RecoveryCodes) != 8 || !store.hasOnlyRecoveryHashes(confirmed.RecoveryCodes) {
		t.Fatal("recovery codes were not returned once and stored as hashes")
	}
}

func TestTOTPCodeCannotBeReused(t *testing.T) {
	store := newStore()
	now := testTime
	manager := newManager(t, store, func() time.Time { return now })
	secret := enableTOTP(t, manager)
	code, err := otplibrary.GenerateCode(secret, testTime)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	enrollmentChallenge := beginChallenge(t, manager)
	if _, err := manager.Verify(context.Background(), totp.VerifyInput{
		ChallengeToken: enrollmentChallenge.Token,
		Code:           code,
	}); !errors.Is(err, totp.ErrInvalidCode) {
		t.Fatalf("reuse enrollment code: got %v, want invalid code", err)
	}
	now = now.Add(30 * time.Second)
	code, err = otplibrary.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("generate next code: %v", err)
	}
	first := beginChallenge(t, manager)
	authentication, err := manager.Verify(context.Background(), totp.VerifyInput{
		ChallengeToken: first.Token,
		Code:           code,
	})
	if err != nil || authentication.SubjectID != "user-1" {
		t.Fatalf("verify code: authentication=%+v error=%v", authentication, err)
	}
	second := beginChallenge(t, manager)
	if _, err := manager.Verify(context.Background(), totp.VerifyInput{
		ChallengeToken: second.Token,
		Code:           code,
	}); !errors.Is(err, totp.ErrInvalidCode) {
		t.Fatalf("reuse code: got %v, want invalid code", err)
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	store := newStore()
	manager := newManager(t, store, func() time.Time { return testTime })
	recoveryCodes := enroll(t, manager)

	first := beginChallenge(t, manager)
	authentication, err := manager.Recover(context.Background(), totp.VerifyInput{
		ChallengeToken: first.Token,
		Code:           recoveryCodes[0],
	})
	if err != nil || !authentication.UsedRecoveryCode || authentication.SubjectID != "user-1" {
		t.Fatalf("use recovery code: authentication=%+v error=%v", authentication, err)
	}
	second := beginChallenge(t, manager)
	if _, err := manager.Recover(context.Background(), totp.VerifyInput{
		ChallengeToken: second.Token,
		Code:           recoveryCodes[0],
	}); !errors.Is(err, totp.ErrInvalidCode) {
		t.Fatalf("reuse recovery code: got %v, want invalid code", err)
	}
}

func TestConcurrentChallengesAcceptATOTPCodeOnce(t *testing.T) {
	store := newStore()
	now := testTime
	manager := newManager(t, store, func() time.Time { return now })
	secret := enableTOTP(t, manager)
	now = now.Add(30 * time.Second)
	code, err := otplibrary.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	challenges := []totp.ChallengeStarted{beginChallenge(t, manager), beginChallenge(t, manager)}

	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	for _, challenge := range challenges {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, verifyErr := manager.Verify(context.Background(), totp.VerifyInput{
				ChallengeToken: challenge.Token,
				Code:           code,
			})
			if verifyErr == nil {
				successes.Add(1)
			} else if !errors.Is(verifyErr, totp.ErrInvalidCode) {
				t.Errorf("unexpected verification error: %v", verifyErr)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful verifications = %d, want 1", successes.Load())
	}
}

func TestExpiredChallengeCannotAuthenticate(t *testing.T) {
	store := newStore()
	now := testTime
	manager := newManager(t, store, func() time.Time { return now })
	secret := enableTOTP(t, manager)
	challenge := beginChallenge(t, manager)
	now = now.Add(3 * time.Minute)
	code, err := otplibrary.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if _, err := manager.Verify(context.Background(), totp.VerifyInput{
		ChallengeToken: challenge.Token,
		Code:           code,
	}); !errors.Is(err, totp.ErrInvalidChallenge) {
		t.Fatalf("verify expired challenge: got %v, want invalid challenge", err)
	}
}

func TestExpiredEnrollmentCannotEnableTOTP(t *testing.T) {
	store := newStore()
	now := testTime
	manager := newManager(t, store, func() time.Time { return now })
	started, err := manager.BeginEnrollment(context.Background(), "user-1", "owner@example.com")
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	now = now.Add(11 * time.Minute)
	code, err := otplibrary.GenerateCode(started.Secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if _, err := manager.ConfirmEnrollment(context.Background(), "user-1", code, "source"); !errors.Is(err, totp.ErrInvalidCode) {
		t.Fatalf("confirm expired enrollment: got %v, want invalid code", err)
	}
	if store.enabled("user-1") {
		t.Fatal("expired enrollment enabled TOTP")
	}
}

func newManager(t *testing.T, store totp.Store, now func() time.Time) *totp.Manager {
	t.Helper()
	manager, err := totp.NewManager(store, totp.Config{
		Issuer:             "Consumel",
		EnrollmentLifetime: 10 * time.Minute,
		ChallengeLifetime:  2 * time.Minute,
		RecoveryCodeCount:  8,
		Now:                now,
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return manager
}

func enroll(t *testing.T, manager *totp.Manager) []string {
	t.Helper()
	started, err := manager.BeginEnrollment(context.Background(), "user-1", "owner@example.com")
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	code, err := otplibrary.GenerateCode(started.Secret, testTime)
	if err != nil {
		t.Fatalf("generate enrollment code: %v", err)
	}
	confirmed, err := manager.ConfirmEnrollment(context.Background(), "user-1", code, "source")
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	return confirmed.RecoveryCodes
}

func enableTOTP(t *testing.T, manager *totp.Manager) string {
	t.Helper()
	started, err := manager.BeginEnrollment(context.Background(), "user-1", "owner@example.com")
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	code, err := otplibrary.GenerateCode(started.Secret, testTime)
	if err != nil {
		t.Fatalf("generate enrollment code: %v", err)
	}
	if _, err := manager.ConfirmEnrollment(context.Background(), "user-1", code, "source"); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	return started.Secret
}

func beginChallenge(t *testing.T, manager *totp.Manager) totp.ChallengeStarted {
	t.Helper()
	challenge, err := manager.BeginChallenge(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("begin challenge: %v", err)
	}
	return challenge
}

type memoryStore struct {
	mu          sync.Mutex
	enrollments map[string]totp.Enrollment
	credentials map[string]totp.Credential
	challenges  map[totp.ChallengeHash]totp.Challenge
	recovery    map[string]map[totp.RecoveryCodeHash]struct{}
}

func newStore() *memoryStore {
	return &memoryStore{
		enrollments: make(map[string]totp.Enrollment),
		credentials: make(map[string]totp.Credential),
		challenges:  make(map[totp.ChallengeHash]totp.Challenge),
		recovery:    make(map[string]map[totp.RecoveryCodeHash]struct{}),
	}
}

func (store *memoryStore) IsEnabled(_ context.Context, subjectID string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, exists := store.credentials[subjectID]
	return exists, nil
}

func (store *memoryStore) BeginEnrollment(_ context.Context, enrollment totp.Enrollment) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.credentials[enrollment.SubjectID]; exists {
		return totp.ErrAlreadyEnabled
	}
	store.enrollments[enrollment.SubjectID] = enrollment
	return nil
}

func (store *memoryStore) FindEnrollment(_ context.Context, subjectID string) (totp.Enrollment, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	enrollment, exists := store.enrollments[subjectID]
	if !exists {
		return totp.Enrollment{}, totp.ErrNotFound
	}
	return enrollment, nil
}

func (store *memoryStore) Enable(
	_ context.Context,
	subjectID string,
	confirmedCounter uint64,
	recoveryCodes []totp.RecoveryCodeHash,
	enabledAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	enrollment, exists := store.enrollments[subjectID]
	if !exists || !enabledAt.Before(enrollment.ExpiresAt) {
		return totp.ErrInactiveEnrollment
	}
	if _, exists := store.credentials[subjectID]; exists {
		return totp.ErrAlreadyEnabled
	}
	store.credentials[subjectID] = totp.Credential{
		SubjectID:          subjectID,
		Secret:             enrollment.Secret,
		EnabledAt:          enabledAt,
		LastUsedCounter:    confirmedCounter,
		HasLastUsedCounter: true,
	}
	store.recovery[subjectID] = make(map[totp.RecoveryCodeHash]struct{}, len(recoveryCodes))
	for _, codeHash := range recoveryCodes {
		store.recovery[subjectID][codeHash] = struct{}{}
	}
	delete(store.enrollments, subjectID)
	return nil
}

func (store *memoryStore) Disable(_ context.Context, subjectID string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.credentials[subjectID]; !exists {
		return totp.ErrNotFound
	}
	delete(store.credentials, subjectID)
	delete(store.recovery, subjectID)
	for hash, challenge := range store.challenges {
		if challenge.SubjectID == subjectID {
			delete(store.challenges, hash)
		}
	}
	return nil
}

func (store *memoryStore) CreateChallenge(_ context.Context, challenge totp.Challenge) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.credentials[challenge.SubjectID]; !exists {
		return totp.ErrNotFound
	}
	if _, exists := store.challenges[challenge.TokenHash]; exists {
		return totp.ErrConflict
	}
	store.challenges[challenge.TokenHash] = challenge
	return nil
}

func (store *memoryStore) FindChallenge(
	_ context.Context,
	challengeHash totp.ChallengeHash,
) (totp.Challenge, totp.Credential, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, exists := store.challenges[challengeHash]
	if !exists {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	}
	credential, exists := store.credentials[challenge.SubjectID]
	if !exists {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	}
	return challenge, credential, nil
}

func (store *memoryStore) CompleteCode(
	_ context.Context,
	challengeHash totp.ChallengeHash,
	counter uint64,
	completedAt time.Time,
) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, exists := store.challenges[challengeHash]
	if !exists || !completedAt.Before(challenge.ExpiresAt) {
		return "", totp.ErrInactiveChallenge
	}
	credential, exists := store.credentials[challenge.SubjectID]
	if !exists {
		return "", totp.ErrNotFound
	}
	if credential.HasLastUsedCounter && counter <= credential.LastUsedCounter {
		return "", totp.ErrInvalidCode
	}
	credential.LastUsedCounter = counter
	credential.HasLastUsedCounter = true
	store.credentials[challenge.SubjectID] = credential
	delete(store.challenges, challengeHash)
	return challenge.SubjectID, nil
}

func (store *memoryStore) CompleteRecovery(
	_ context.Context,
	challengeHash totp.ChallengeHash,
	recoveryCode totp.RecoveryCodeHash,
	completedAt time.Time,
) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, exists := store.challenges[challengeHash]
	if !exists || !completedAt.Before(challenge.ExpiresAt) {
		return "", totp.ErrInactiveChallenge
	}
	if _, exists := store.credentials[challenge.SubjectID]; !exists {
		return "", totp.ErrNotFound
	}
	codes := store.recovery[challenge.SubjectID]
	if _, exists := codes[recoveryCode]; !exists {
		return "", totp.ErrInvalidCode
	}
	delete(codes, recoveryCode)
	delete(store.challenges, challengeHash)
	return challenge.SubjectID, nil
}

func (store *memoryStore) enabled(subjectID string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, exists := store.credentials[subjectID]
	return exists
}

func (store *memoryStore) hasOnlyRecoveryHashes(rawCodes []string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.recovery["user-1"]) != len(rawCodes) {
		return false
	}
	for _, rawCode := range rawCodes {
		hash, err := totp.HashRecoveryCode(rawCode)
		if err != nil {
			return false
		}
		if _, exists := store.recovery["user-1"][hash]; !exists {
			return false
		}
	}
	return true
}
