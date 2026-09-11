package mysql

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/google/uuid"
)

type EmailPasswordStore struct{ adapter *Adapter }
type EmailVerificationStore struct{ adapter *Adapter }
type PasswordResetStore struct{ adapter *Adapter }
type GoogleStore struct{ adapter *Adapter }

func (adapter *Adapter) EmailPassword() *EmailPasswordStore {
	return &EmailPasswordStore{adapter: adapter}
}

func (adapter *Adapter) EmailVerification() *EmailVerificationStore {
	return &EmailVerificationStore{adapter: adapter}
}

func (adapter *Adapter) PasswordReset() *PasswordResetStore {
	return &PasswordResetStore{adapter: adapter}
}

func (adapter *Adapter) Google() *GoogleStore { return &GoogleStore{adapter: adapter} }

func (store *EmailPasswordStore) Register(
	ctx context.Context,
	registration emailpassword.Registration,
) (emailpassword.User, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return emailpassword.User{}, err
	}
	defer tx.Rollback()
	userUUID, err := uuid.NewV7()
	if err != nil {
		return emailpassword.User{}, fmt.Errorf("generate user ID: %w", err)
	}
	userID := userUUID.String()
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return emailpassword.User{}, fmt.Errorf("generate WebAuthn handle: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_users
		(id, email, webauthn_handle, created_at) VALUES (?, ?, ?, ?)`,
		userID, registration.Email, handle, registration.CreatedAt,
	); err != nil {
		if uniqueViolation(err) {
			return emailpassword.User{}, emailpassword.ErrConflict
		}
		return emailpassword.User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_password_credentials
		(user_id, password_hash, updated_at) VALUES (?, ?, ?)`,
		userID, registration.PasswordHash, registration.CreatedAt,
	); err != nil {
		return emailpassword.User{}, err
	}
	if err := tx.Commit(); err != nil {
		if uniqueViolation(err) {
			return emailpassword.User{}, emailpassword.ErrConflict
		}
		return emailpassword.User{}, err
	}
	return emailpassword.User{ID: userID, Email: registration.Email}, nil
}

func (store *EmailPasswordStore) FindByEmail(
	ctx context.Context,
	email string,
) (emailpassword.User, emailpassword.PasswordCredential, error) {
	var user emailpassword.User
	var credential emailpassword.PasswordCredential
	err := store.adapter.database.QueryRowContext(ctx, `SELECT u.id, u.email, p.password_hash
		FROM authlier_users u
		JOIN authlier_password_credentials p ON p.user_id = u.id
		WHERE u.email = ?`, email,
	).Scan(&user.ID, &user.Email, &credential.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return user, credential, emailpassword.ErrNotFound
	}
	credential.UserID = user.ID
	return user, credential, err
}

func (store *EmailPasswordStore) FindBySubject(
	ctx context.Context,
	subjectID string,
) (emailpassword.User, emailpassword.PasswordCredential, error) {
	var user emailpassword.User
	var credential emailpassword.PasswordCredential
	err := store.adapter.database.QueryRowContext(ctx, `SELECT u.id, u.email, p.password_hash
		FROM authlier_users u
		JOIN authlier_password_credentials p ON p.user_id = u.id
		WHERE u.id = ?`, subjectID,
	).Scan(&user.ID, &user.Email, &credential.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return user, credential, emailpassword.ErrNotFound
	}
	credential.UserID = user.ID
	return user, credential, err
}

func (store *EmailPasswordStore) AddPassword(
	ctx context.Context,
	subjectID, passwordHash string,
	addedAt time.Time,
) (emailpassword.User, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return emailpassword.User{}, err
	}
	defer tx.Rollback()
	var user emailpassword.User
	if err := tx.QueryRowContext(ctx,
		"SELECT id, email FROM authlier_users WHERE id = ? FOR UPDATE", subjectID,
	).Scan(&user.ID, &user.Email); errors.Is(err, sql.ErrNoRows) {
		return user, emailpassword.ErrNotFound
	} else if err != nil {
		return user, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_password_credentials
		(user_id, password_hash, updated_at) VALUES (?, ?, ?)`,
		subjectID, passwordHash, addedAt,
	); err != nil {
		if uniqueViolation(err) {
			return user, emailpassword.ErrConflict
		}
		return user, err
	}
	return user, tx.Commit()
}

func (store *EmailPasswordStore) ReplacePasswordHash(
	ctx context.Context,
	userID, currentHash, replacementHash string,
	updatedAt time.Time,
) error {
	tag, err := store.adapter.database.ExecContext(ctx, `UPDATE authlier_password_credentials
		SET password_hash = ?, updated_at = ?
		WHERE user_id = ? AND password_hash = ?`,
		replacementHash, updatedAt, userID, currentHash,
	)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return emailpassword.ErrConflict
	}
	return nil
}

func (store *EmailPasswordStore) RemovePassword(
	ctx context.Context,
	subjectID, currentHash string,
	_ time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockUser(ctx, tx, subjectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return emailpassword.ErrNotFound
		}
		return err
	}
	var storedHash string
	if err := tx.QueryRowContext(ctx,
		"SELECT password_hash FROM authlier_password_credentials WHERE user_id = ?", subjectID,
	).Scan(&storedHash); errors.Is(err, sql.ErrNoRows) {
		return emailpassword.ErrNotFound
	} else if err != nil {
		return err
	}
	if storedHash != currentHash {
		return emailpassword.ErrConflict
	}
	methods, err := otherCredentialCount(ctx, tx, subjectID)
	if err != nil {
		return err
	}
	if methods == 0 {
		return emailpassword.ErrLastCredential
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM authlier_password_credentials WHERE user_id = ?", subjectID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *EmailVerificationStore) FindUserByEmail(
	ctx context.Context,
	email string,
) (emailverification.User, error) {
	var user emailverification.User
	err := store.adapter.database.QueryRowContext(ctx,
		"SELECT id, email, email_verified FROM authlier_users WHERE email = ?", email,
	).Scan(&user.ID, &user.Email, &user.Verified)
	if errors.Is(err, sql.ErrNoRows) {
		return user, emailverification.ErrNotFound
	}
	return user, err
}

func (store *EmailVerificationStore) Issue(ctx context.Context, record emailverification.Record) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_email_verifications
		(user_id, email, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)
		AS new ON DUPLICATE KEY UPDATE email = new.email,
		token_hash = new.token_hash, created_at = new.created_at,
		expires_at = new.expires_at`,
		record.UserID, record.Email, record.TokenHash[:], record.CreatedAt, record.ExpiresAt,
	)
	if uniqueViolation(err) {
		return emailverification.ErrConflict
	}
	return err
}

func (store *EmailVerificationStore) Verify(
	ctx context.Context,
	tokenHash emailverification.TokenHash,
	verifiedAt time.Time,
) (emailverification.User, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return emailverification.User{}, err
	}
	defer tx.Rollback()
	var user emailverification.User
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT u.id, u.email, u.email_verified, v.expires_at
		FROM authlier_email_verifications v
		JOIN authlier_users u ON u.id = v.user_id
		WHERE v.token_hash = ? FOR UPDATE`, tokenHash[:],
	).Scan(&user.ID, &user.Email, &user.Verified, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return user, emailverification.ErrNotFound
	}
	if err != nil {
		return user, err
	}
	if user.Verified || !verifiedAt.Before(expiresAt) {
		return user, emailverification.ErrInactiveToken
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE authlier_users SET email_verified = true WHERE id = ?", user.ID,
	); err != nil {
		return user, err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM authlier_email_verifications WHERE user_id = ?", user.ID,
	); err != nil {
		return user, err
	}
	user.Verified = true
	return user, tx.Commit()
}

func (store *PasswordResetStore) FindUserByEmail(
	ctx context.Context,
	email string,
) (passwordreset.User, error) {
	var user passwordreset.User
	err := store.adapter.database.QueryRowContext(ctx,
		"SELECT id, email FROM authlier_users WHERE email = ?", email,
	).Scan(&user.ID, &user.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return user, passwordreset.ErrNotFound
	}
	return user, err
}

func (store *PasswordResetStore) Issue(ctx context.Context, record passwordreset.Record) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_password_resets
		(user_id, email, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)
		AS new ON DUPLICATE KEY UPDATE email = new.email,
		token_hash = new.token_hash, created_at = new.created_at,
		expires_at = new.expires_at`,
		record.UserID, record.Email, record.TokenHash[:], record.CreatedAt, record.ExpiresAt,
	)
	if uniqueViolation(err) {
		return passwordreset.ErrConflict
	}
	return err
}

func (store *PasswordResetStore) ResetPassword(
	ctx context.Context,
	tokenHash passwordreset.TokenHash,
	passwordHash string,
	resetAt time.Time,
) (passwordreset.User, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return passwordreset.User{}, err
	}
	defer tx.Rollback()
	var user passwordreset.User
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT u.id, u.email, r.expires_at
		FROM authlier_password_resets r
		JOIN authlier_users u ON u.id = r.user_id
		WHERE r.token_hash = ? FOR UPDATE`, tokenHash[:],
	).Scan(&user.ID, &user.Email, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return user, passwordreset.ErrNotFound
	}
	if err != nil {
		return user, err
	}
	if !resetAt.Before(expiresAt) {
		return user, passwordreset.ErrInactiveToken
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_password_credentials
		(user_id, password_hash, updated_at) VALUES (?, ?, ?)
		AS new ON DUPLICATE KEY UPDATE password_hash = new.password_hash,
		updated_at = new.updated_at`, user.ID, passwordHash, resetAt,
	); err != nil {
		return user, err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM authlier_password_resets WHERE user_id = ?", user.ID,
	); err != nil {
		return user, err
	}
	return user, tx.Commit()
}

func (store *GoogleStore) CreateChallenge(ctx context.Context, challenge googleoauth.Challenge) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_google_challenges
		(state_hash, nonce, code_verifier, subject_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		challenge.StateHash[:], challenge.Nonce, challenge.CodeVerifier,
		challenge.SubjectID, challenge.CreatedAt, challenge.ExpiresAt,
	)
	if uniqueViolation(err) {
		return googleoauth.ErrConflict
	}
	return err
}

func (store *GoogleStore) ConsumeChallenge(
	ctx context.Context,
	stateHash [32]byte,
	consumedAt time.Time,
) (googleoauth.Challenge, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return googleoauth.Challenge{}, err
	}
	defer tx.Rollback()
	var challenge googleoauth.Challenge
	var storedHash []byte
	err = tx.QueryRowContext(ctx, `SELECT state_hash, nonce, code_verifier, subject_id,
		created_at, expires_at FROM authlier_google_challenges
		WHERE state_hash = ? FOR UPDATE`,
		stateHash[:],
	).Scan(&storedHash, &challenge.Nonce, &challenge.CodeVerifier, &challenge.SubjectID,
		&challenge.CreatedAt, &challenge.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return challenge, googleoauth.ErrNotFound
	}
	if err != nil {
		return challenge, err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM authlier_google_challenges WHERE state_hash = ?", stateHash[:]); err != nil {
		return challenge, err
	}
	if err := tx.Commit(); err != nil {
		return challenge, err
	}
	copy(challenge.StateHash[:], storedHash)
	if !consumedAt.Before(challenge.ExpiresAt) {
		return challenge, googleoauth.ErrInvalidState
	}
	return challenge, nil
}

func (store *GoogleStore) ResolveIdentity(
	ctx context.Context,
	resolution googleoauth.IdentityResolution,
) (googleoauth.User, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return googleoauth.User{}, err
	}
	defer tx.Rollback()

	var linkedUserID string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM authlier_google_identities
		WHERE provider_subject = ? FOR UPDATE`, resolution.ProviderSubject,
	).Scan(&linkedUserID)
	if err == nil {
		if resolution.SubjectID != "" && linkedUserID != resolution.SubjectID {
			return googleoauth.User{}, googleoauth.ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authlier_google_identities
			SET email = ? WHERE provider_subject = ?`,
			resolution.Email, resolution.ProviderSubject,
		); err != nil {
			return googleoauth.User{}, err
		}
		if err := tx.Commit(); err != nil {
			return googleoauth.User{}, err
		}
		return googleoauth.User{ID: linkedUserID}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return googleoauth.User{}, err
	}

	userID := resolution.SubjectID
	if userID != "" {
		if err := lockUser(ctx, tx, userID); errors.Is(err, sql.ErrNoRows) {
			return googleoauth.User{}, googleoauth.ErrNotFound
		} else if err != nil {
			return googleoauth.User{}, err
		}
	} else {
		err := tx.QueryRowContext(ctx,
			"SELECT id FROM authlier_users WHERE email = ? FOR UPDATE", resolution.Email,
		).Scan(&userID)
		if err == nil {
			return googleoauth.User{}, googleoauth.ErrLinkRequired
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return googleoauth.User{}, err
		}
		userID, err = insertUser(ctx, tx, resolution.Email, true, time.Now().UTC())
		if err != nil {
			if uniqueViolation(err) {
				return googleoauth.User{}, googleoauth.ErrLinkRequired
			}
			return googleoauth.User{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_google_identities
		(provider_subject, user_id, email, linked_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		resolution.ProviderSubject, userID, resolution.Email,
	); err != nil {
		if uniqueViolation(err) {
			return googleoauth.User{}, googleoauth.ErrConflict
		}
		return googleoauth.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return googleoauth.User{}, err
	}
	return googleoauth.User{ID: userID}, nil
}

func (store *GoogleStore) UnlinkIdentity(
	ctx context.Context,
	subjectID, providerSubject string,
	_ time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockUser(ctx, tx, subjectID); errors.Is(err, sql.ErrNoRows) {
		return googleoauth.ErrNotFound
	} else if err != nil {
		return err
	}
	var linkedUserID string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM authlier_google_identities
		WHERE provider_subject = ? FOR UPDATE`, providerSubject,
	).Scan(&linkedUserID)
	if errors.Is(err, sql.ErrNoRows) || linkedUserID != subjectID {
		return googleoauth.ErrNotFound
	}
	if err != nil {
		return err
	}
	var passwordCount, passkeyCount int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM authlier_password_credentials WHERE user_id = ?),
		(SELECT COUNT(*) FROM authlier_passkey_credentials WHERE subject_id = ?)`, subjectID, subjectID,
	).Scan(&passwordCount, &passkeyCount); err != nil {
		return err
	}
	if passwordCount+passkeyCount == 0 {
		return googleoauth.ErrLastCredential
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM authlier_google_identities
		WHERE provider_subject = ? AND user_id = ?`, providerSubject, subjectID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func insertUser(
	ctx context.Context,
	tx *sql.Tx,
	email string,
	verified bool,
	createdAt time.Time,
) (string, error) {
	userUUID, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate user ID: %w", err)
	}
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return "", fmt.Errorf("generate WebAuthn handle: %w", err)
	}
	userID := userUUID.String()
	_, err = tx.ExecContext(ctx, `INSERT INTO authlier_users
		(id, email, email_verified, webauthn_handle, created_at)
		VALUES (?, ?, ?, ?, ?)`, userID, email, verified, handle, createdAt)
	return userID, err
}

func lockUser(ctx context.Context, tx *sql.Tx, subjectID string) error {
	var ignored string
	return tx.QueryRowContext(ctx,
		"SELECT id FROM authlier_users WHERE id = ? FOR UPDATE", subjectID,
	).Scan(&ignored)
}

func otherCredentialCount(ctx context.Context, tx *sql.Tx, subjectID string) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM authlier_google_identities WHERE user_id = ?) +
		(SELECT COUNT(*) FROM authlier_passkey_credentials WHERE subject_id = ?)`, subjectID, subjectID,
	).Scan(&count)
	return count, err
}

var _ emailpassword.Store = (*EmailPasswordStore)(nil)
var _ emailpassword.CredentialStore = (*EmailPasswordStore)(nil)
var _ emailverification.Store = (*EmailVerificationStore)(nil)
var _ passwordreset.Store = (*PasswordResetStore)(nil)
var _ googleoauth.Store = (*GoogleStore)(nil)
var _ googleoauth.IdentityStore = (*GoogleStore)(nil)
