package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Rahmannugar/authlier/totp"
	redislibrary "github.com/redis/go-redis/v9"
)

type TOTPStore struct{ adapter *Adapter }

func (adapter *Adapter) TOTP() *TOTPStore { return &TOTPStore{adapter} }

type storedEnrollment struct {
	SubjectID string
	Secret    []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

type storedTOTPCredential struct {
	SubjectID          string
	Secret             []byte
	EnabledAt          time.Time
	LastUsedCounter    uint64
	HasLastUsedCounter bool
	DisabledAt         *time.Time
}

type storedTOTPChallenge struct {
	SubjectID string
	TokenHash totp.ChallengeHash
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (store *TOTPStore) BeginEnrollment(ctx context.Context, enrollment totp.Enrollment) error {
	secret, err := store.encrypt(ctx, enrollment.Secret)
	if err != nil {
		return err
	}
	encoded, _ := encodeJSON(storedEnrollment{enrollment.SubjectID, secret, enrollment.CreatedAt, enrollment.ExpiresAt})
	return store.adapter.client.HSet(ctx, store.adapter.key("totp-enrollments"), enrollment.SubjectID, encoded).Err()
}

func (store *TOTPStore) FindEnrollment(ctx context.Context, subjectID string) (totp.Enrollment, error) {
	var stored storedEnrollment
	err := readJSON(ctx, store.adapter.client, store.adapter.key("totp-enrollments"), subjectID, &stored)
	if errors.Is(err, redislibrary.Nil) {
		return totp.Enrollment{}, totp.ErrNotFound
	}
	if err != nil {
		return totp.Enrollment{}, err
	}
	secret, err := store.decrypt(ctx, stored.Secret)
	return totp.Enrollment{SubjectID: stored.SubjectID, Secret: string(secret), CreatedAt: stored.CreatedAt, ExpiresAt: stored.ExpiresAt}, err
}

func (store *TOTPStore) Enable(ctx context.Context, subjectID string, confirmedCounter uint64, recoveryCodes []totp.RecoveryCodeHash, enabledAt time.Time) error {
	enrollments, credentials := store.adapter.key("totp-enrollments"), store.adapter.key("totp-credentials")
	recovery, recoverySet := store.adapter.key("totp-recovery-codes"), store.adapter.key("totp:recovery:"+subjectID)
	return store.adapter.watch(ctx, []string{enrollments, credentials, recovery, recoverySet}, func(tx *redislibrary.Tx) error {
		var enrollment storedEnrollment
		if err := readJSON(ctx, tx, enrollments, subjectID, &enrollment); errors.Is(err, redislibrary.Nil) {
			return totp.ErrNotFound
		} else if err != nil {
			return err
		}
		if !enabledAt.Before(enrollment.ExpiresAt) {
			return totp.ErrInactiveEnrollment
		}
		oldFields, err := tx.SMembers(ctx, recoverySet).Result()
		if err != nil {
			return err
		}
		credentialJSON, _ := encodeJSON(storedTOTPCredential{SubjectID: subjectID, Secret: enrollment.Secret, EnabledAt: enabledAt, LastUsedCounter: confirmedCounter, HasLastUsedCounter: true})
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, credentials, subjectID, credentialJSON)
			pipe.HDel(ctx, enrollments, subjectID)
			if len(oldFields) > 0 {
				pipe.HDel(ctx, recovery, oldFields...)
			}
			pipe.Del(ctx, recoverySet)
			for index := range recoveryCodes {
				field := recoveryField(subjectID, recoveryCodes[index])
				pipe.HSet(ctx, recovery, field, "unused")
				pipe.SAdd(ctx, recoverySet, field)
			}
			return nil
		})
		return err
	})
}

func (store *TOTPStore) Disable(ctx context.Context, subjectID string, disabledAt time.Time) error {
	credentials, recovery := store.adapter.key("totp-credentials"), store.adapter.key("totp-recovery-codes")
	recoverySet := store.adapter.key("totp:recovery:" + subjectID)
	return store.adapter.watch(ctx, []string{credentials, recovery, recoverySet}, func(tx *redislibrary.Tx) error {
		var credential storedTOTPCredential
		if err := readJSON(ctx, tx, credentials, subjectID, &credential); errors.Is(err, redislibrary.Nil) {
			return totp.ErrNotFound
		} else if err != nil {
			return err
		}
		if credential.DisabledAt == nil {
			credential.DisabledAt = &disabledAt
		}
		fields, err := tx.SMembers(ctx, recoverySet).Result()
		if err != nil {
			return err
		}
		encoded, _ := encodeJSON(credential)
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, credentials, subjectID, encoded)
			if len(fields) > 0 {
				pipe.HDel(ctx, recovery, fields...)
			}
			pipe.Del(ctx, recoverySet)
			return nil
		})
		return err
	})
}

func (store *TOTPStore) CreateChallenge(ctx context.Context, challenge totp.Challenge) error {
	key, field := store.adapter.key("totp-challenges"), hashKey(challenge.TokenHash[:])
	encoded, _ := encodeJSON(storedTOTPChallenge{challenge.SubjectID, challenge.TokenHash, challenge.CreatedAt, challenge.ExpiresAt})
	created, err := store.adapter.client.HSetNX(ctx, key, field, encoded).Result()
	if err == nil && !created {
		return totp.ErrConflict
	}
	return err
}

func (store *TOTPStore) FindChallenge(ctx context.Context, challengeHash totp.ChallengeHash) (totp.Challenge, totp.Credential, error) {
	var challenge storedTOTPChallenge
	if err := readJSON(ctx, store.adapter.client, store.adapter.key("totp-challenges"), hashKey(challengeHash[:]), &challenge); errors.Is(err, redislibrary.Nil) {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	} else if err != nil {
		return totp.Challenge{}, totp.Credential{}, err
	}
	var credential storedTOTPCredential
	if err := readJSON(ctx, store.adapter.client, store.adapter.key("totp-credentials"), challenge.SubjectID, &credential); errors.Is(err, redislibrary.Nil) || credential.DisabledAt != nil {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	} else if err != nil {
		return totp.Challenge{}, totp.Credential{}, err
	}
	secret, err := store.decrypt(ctx, credential.Secret)
	return totp.Challenge{SubjectID: challenge.SubjectID, TokenHash: challenge.TokenHash, CreatedAt: challenge.CreatedAt, ExpiresAt: challenge.ExpiresAt}, totp.Credential{
		SubjectID: credential.SubjectID, Secret: string(secret), EnabledAt: credential.EnabledAt,
		LastUsedCounter: credential.LastUsedCounter, HasLastUsedCounter: credential.HasLastUsedCounter,
	}, err
}

func (store *TOTPStore) CompleteCode(ctx context.Context, challengeHash totp.ChallengeHash, counter uint64, completedAt time.Time) (string, error) {
	challenges, credentials := store.adapter.key("totp-challenges"), store.adapter.key("totp-credentials")
	field := hashKey(challengeHash[:])
	var subjectID string
	err := store.adapter.watch(ctx, []string{challenges, credentials}, func(tx *redislibrary.Tx) error {
		var challenge storedTOTPChallenge
		if err := readJSON(ctx, tx, challenges, field, &challenge); errors.Is(err, redislibrary.Nil) || !completedAt.Before(challenge.ExpiresAt) {
			return totp.ErrInactiveChallenge
		} else if err != nil {
			return err
		}
		var credential storedTOTPCredential
		if err := readJSON(ctx, tx, credentials, challenge.SubjectID, &credential); errors.Is(err, redislibrary.Nil) {
			return totp.ErrInvalidCode
		} else if err != nil {
			return err
		} else if credential.DisabledAt != nil {
			return totp.ErrInvalidCode
		}
		if credential.HasLastUsedCounter && counter <= credential.LastUsedCounter {
			return totp.ErrInvalidCode
		}
		credential.LastUsedCounter, credential.HasLastUsedCounter = counter, true
		encoded, _ := encodeJSON(credential)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, challenges, field)
			pipe.HSet(ctx, credentials, challenge.SubjectID, encoded)
			return nil
		})
		subjectID = challenge.SubjectID
		return err
	})
	return subjectID, err
}

func (store *TOTPStore) CompleteRecovery(ctx context.Context, challengeHash totp.ChallengeHash, recoveryCode totp.RecoveryCodeHash, completedAt time.Time) (string, error) {
	challenges, recovery := store.adapter.key("totp-challenges"), store.adapter.key("totp-recovery-codes")
	challengeField := hashKey(challengeHash[:])
	var subjectID string
	err := store.adapter.watch(ctx, []string{challenges, recovery}, func(tx *redislibrary.Tx) error {
		var challenge storedTOTPChallenge
		if err := readJSON(ctx, tx, challenges, challengeField, &challenge); errors.Is(err, redislibrary.Nil) || !completedAt.Before(challenge.ExpiresAt) {
			return totp.ErrInactiveChallenge
		} else if err != nil {
			return err
		}
		field := recoveryField(challenge.SubjectID, recoveryCode)
		status, err := tx.HGet(ctx, recovery, field).Result()
		if errors.Is(err, redislibrary.Nil) {
			return totp.ErrInvalidCode
		} else if err != nil {
			return err
		} else if status != "unused" {
			return totp.ErrInvalidCode
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, challenges, challengeField)
			pipe.HSet(ctx, recovery, field, completedAt.Format(time.RFC3339Nano))
			return nil
		})
		subjectID = challenge.SubjectID
		return err
	})
	return subjectID, err
}

func recoveryField(subjectID string, code totp.RecoveryCodeHash) string {
	return subjectID + ":" + hashKey(code[:])
}

func (store *TOTPStore) encrypt(ctx context.Context, secret string) ([]byte, error) {
	if store.adapter.secrets == nil {
		return nil, fmt.Errorf("%w: secret codec is required for TOTP", ErrInvalidConfig)
	}
	return store.adapter.secrets.Encrypt(ctx, []byte(secret))
}

func (store *TOTPStore) decrypt(ctx context.Context, secret []byte) ([]byte, error) {
	if store.adapter.secrets == nil {
		return nil, fmt.Errorf("%w: secret codec is required for TOTP", ErrInvalidConfig)
	}
	return store.adapter.secrets.Decrypt(ctx, secret)
}

var _ totp.Store = (*TOTPStore)(nil)
