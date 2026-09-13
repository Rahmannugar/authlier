package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Rahmannugar/authlier/totp"
)

type TOTPStore struct{ adapter *Adapter }

func (adapter *Adapter) TOTP() *TOTPStore { return &TOTPStore{adapter: adapter} }

func (store *TOTPStore) IsEnabled(ctx context.Context, subjectID string) (bool, error) {
	var enabled bool
	err := store.adapter.database.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM authlier_totp_credentials
		WHERE subject_id = ? AND disabled_at IS NULL
	)`, subjectID).Scan(&enabled)
	return enabled, err
}

func (store *TOTPStore) BeginEnrollment(ctx context.Context, enrollment totp.Enrollment) error {
	secret, err := store.encrypt(ctx, enrollment.Secret)
	if err != nil {
		return err
	}
	_, err = store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_totp_enrollments
		(subject_id, encrypted_secret, created_at, expires_at) VALUES (?, ?, ?, ?)
		AS new ON DUPLICATE KEY UPDATE encrypted_secret = new.encrypted_secret,
		created_at = new.created_at, expires_at = new.expires_at`,
		enrollment.SubjectID, secret, enrollment.CreatedAt, enrollment.ExpiresAt)
	return err
}

func (store *TOTPStore) FindEnrollment(
	ctx context.Context,
	subjectID string,
) (totp.Enrollment, error) {
	var enrollment totp.Enrollment
	var encrypted []byte
	err := store.adapter.database.QueryRowContext(ctx, `SELECT subject_id, encrypted_secret,
		created_at, expires_at FROM authlier_totp_enrollments WHERE subject_id = ?`, subjectID,
	).Scan(&enrollment.SubjectID, &encrypted, &enrollment.CreatedAt, &enrollment.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return enrollment, totp.ErrNotFound
	}
	if err != nil {
		return enrollment, err
	}
	secret, err := store.decrypt(ctx, encrypted)
	enrollment.Secret = string(secret)
	return enrollment, err
}

func (store *TOTPStore) Enable(
	ctx context.Context,
	subjectID string,
	confirmedCounter uint64,
	recoveryCodes []totp.RecoveryCodeHash,
	enabledAt time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var encrypted []byte
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT encrypted_secret, expires_at
		FROM authlier_totp_enrollments WHERE subject_id = ? FOR UPDATE`, subjectID,
	).Scan(&encrypted, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return totp.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enabledAt.Before(expiresAt) {
		return totp.ErrInactiveEnrollment
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_totp_credentials
		(subject_id, encrypted_secret, enabled_at, last_used_counter)
		VALUES (?, ?, ?, ?)
		AS new ON DUPLICATE KEY UPDATE encrypted_secret = new.encrypted_secret,
		enabled_at = new.enabled_at, last_used_counter = new.last_used_counter,
		disabled_at = NULL`, subjectID, encrypted, enabledAt, int64(confirmedCounter)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM authlier_totp_recovery_codes WHERE subject_id = ?", subjectID); err != nil {
		return err
	}
	for _, code := range recoveryCodes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_totp_recovery_codes
			(subject_id, code_hash) VALUES (?, ?)`, subjectID, code[:]); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM authlier_totp_enrollments WHERE subject_id = ?", subjectID); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *TOTPStore) Disable(ctx context.Context, subjectID string, disabledAt time.Time) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tag, err := tx.ExecContext(ctx, `UPDATE authlier_totp_credentials
		SET disabled_at = COALESCE(disabled_at, ?) WHERE subject_id = ?`, disabledAt, subjectID)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return totp.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM authlier_totp_recovery_codes WHERE subject_id = ?", subjectID); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *TOTPStore) CreateChallenge(ctx context.Context, challenge totp.Challenge) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_totp_challenges
		(token_hash, subject_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		challenge.TokenHash[:], challenge.SubjectID, challenge.CreatedAt, challenge.ExpiresAt)
	if uniqueViolation(err) {
		return totp.ErrConflict
	}
	return err
}

func (store *TOTPStore) FindChallenge(
	ctx context.Context,
	challengeHash totp.ChallengeHash,
) (totp.Challenge, totp.Credential, error) {
	var challenge totp.Challenge
	var credential totp.Credential
	var hash, encrypted []byte
	var counter *int64
	err := store.adapter.database.QueryRowContext(ctx, `SELECT c.token_hash, c.subject_id,
		c.created_at, c.expires_at, t.encrypted_secret, t.enabled_at, t.last_used_counter
		FROM authlier_totp_challenges c JOIN authlier_totp_credentials t
		ON t.subject_id = c.subject_id
		WHERE c.token_hash = ? AND c.consumed_at IS NULL AND t.disabled_at IS NULL`,
		challengeHash[:],
	).Scan(&hash, &challenge.SubjectID, &challenge.CreatedAt, &challenge.ExpiresAt,
		&encrypted, &credential.EnabledAt, &counter)
	if errors.Is(err, sql.ErrNoRows) {
		return challenge, credential, totp.ErrNotFound
	}
	if err != nil {
		return challenge, credential, err
	}
	copy(challenge.TokenHash[:], hash)
	credential.SubjectID = challenge.SubjectID
	if counter != nil {
		credential.LastUsedCounter = uint64(*counter)
		credential.HasLastUsedCounter = true
	}
	secret, err := store.decrypt(ctx, encrypted)
	credential.Secret = string(secret)
	return challenge, credential, err
}

func (store *TOTPStore) CompleteCode(
	ctx context.Context,
	challengeHash totp.ChallengeHash,
	counter uint64,
	completedAt time.Time,
) (string, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	subjectID, err := consumeTOTPChallenge(ctx, tx, challengeHash, completedAt)
	if err != nil {
		return "", err
	}
	tag, err := tx.ExecContext(ctx, `UPDATE authlier_totp_credentials
		SET last_used_counter = ? WHERE subject_id = ? AND disabled_at IS NULL
		AND (last_used_counter IS NULL OR last_used_counter < ?)`, int64(counter), subjectID, int64(counter))
	if err != nil {
		return "", err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", totp.ErrInvalidCode
	}
	return subjectID, tx.Commit()
}

func (store *TOTPStore) CompleteRecovery(
	ctx context.Context,
	challengeHash totp.ChallengeHash,
	recoveryCode totp.RecoveryCodeHash,
	completedAt time.Time,
) (string, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	subjectID, err := consumeTOTPChallenge(ctx, tx, challengeHash, completedAt)
	if err != nil {
		return "", err
	}
	tag, err := tx.ExecContext(ctx, `UPDATE authlier_totp_recovery_codes SET used_at = ?
		WHERE subject_id = ? AND code_hash = ? AND used_at IS NULL`,
		completedAt, subjectID, recoveryCode[:])
	if err != nil {
		return "", err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", totp.ErrInvalidCode
	}
	return subjectID, tx.Commit()
}

func consumeTOTPChallenge(
	ctx context.Context,
	tx *sql.Tx,
	hash totp.ChallengeHash,
	at time.Time,
) (string, error) {
	var subjectID string
	err := tx.QueryRowContext(ctx, `SELECT subject_id FROM authlier_totp_challenges
		WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? FOR UPDATE`, hash[:], at,
	).Scan(&subjectID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", totp.ErrInactiveChallenge
	}
	if err != nil {
		return "", err
	}
	result, err := tx.ExecContext(ctx, `UPDATE authlier_totp_challenges SET consumed_at = ?
		WHERE token_hash = ? AND consumed_at IS NULL`, at, hash[:])
	if err != nil {
		return "", err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", totp.ErrInactiveChallenge
	}
	return subjectID, nil
}

func (store *TOTPStore) encrypt(ctx context.Context, secret string) ([]byte, error) {
	if store.adapter.secrets == nil {
		return nil, fmt.Errorf("%w: secret codec is required for TOTP", ErrInvalidConfig)
	}
	return store.adapter.secrets.Encrypt(ctx, []byte(secret))
}

func (store *TOTPStore) decrypt(ctx context.Context, encrypted []byte) ([]byte, error) {
	if store.adapter.secrets == nil {
		return nil, fmt.Errorf("%w: secret codec is required for TOTP", ErrInvalidConfig)
	}
	return store.adapter.secrets.Decrypt(ctx, encrypted)
}

var _ totp.Store = (*TOTPStore)(nil)
