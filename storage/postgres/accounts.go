package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return emailpassword.User{}, err
	}
	defer tx.Rollback(ctx)
	userUUID, err := uuid.NewV7()
	if err != nil {
		return emailpassword.User{}, fmt.Errorf("generate user ID: %w", err)
	}
	userID := userUUID.String()
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return emailpassword.User{}, fmt.Errorf("generate WebAuthn handle: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_users
		(id, email, webauthn_handle, created_at) VALUES ($1, $2, $3, $4)`,
		userID, registration.Email, handle, registration.CreatedAt,
	); err != nil {
		if uniqueViolation(err) {
			return emailpassword.User{}, emailpassword.ErrConflict
		}
		return emailpassword.User{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_password_credentials
		(user_id, password_hash, updated_at) VALUES ($1, $2, $3)`,
		userID, registration.PasswordHash, registration.CreatedAt,
	); err != nil {
		return emailpassword.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
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
	err := store.adapter.pool.QueryRow(ctx, `SELECT u.id, u.email, p.password_hash
		FROM authlier_users u
		JOIN authlier_password_credentials p ON p.user_id = u.id
		WHERE u.email = $1`, email,
	).Scan(&user.ID, &user.Email, &credential.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
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
	err := store.adapter.pool.QueryRow(ctx, `SELECT u.id, u.email, p.password_hash
		FROM authlier_users u
		JOIN authlier_password_credentials p ON p.user_id = u.id
		WHERE u.id = $1`, subjectID,
	).Scan(&user.ID, &user.Email, &credential.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
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
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return emailpassword.User{}, err
	}
	defer tx.Rollback(ctx)
	var user emailpassword.User
	if err := tx.QueryRow(ctx,
		"SELECT id, email FROM authlier_users WHERE id = $1 FOR UPDATE", subjectID,
	).Scan(&user.ID, &user.Email); errors.Is(err, pgx.ErrNoRows) {
		return user, emailpassword.ErrNotFound
	} else if err != nil {
		return user, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_password_credentials
		(user_id, password_hash, updated_at) VALUES ($1, $2, $3)`,
		subjectID, passwordHash, addedAt,
	); err != nil {
		if uniqueViolation(err) {
			return user, emailpassword.ErrConflict
		}
		return user, err
	}
	return user, tx.Commit(ctx)
}

func (store *EmailPasswordStore) ReplacePasswordHash(
	ctx context.Context,
	userID, currentHash, replacementHash string,
	updatedAt time.Time,
) error {
	tag, err := store.adapter.pool.Exec(ctx, `UPDATE authlier_password_credentials
		SET password_hash = $1, updated_at = $2
		WHERE user_id = $3 AND password_hash = $4`,
		replacementHash, updatedAt, userID, currentHash,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return emailpassword.ErrConflict
	}
	return nil
}

func (store *EmailPasswordStore) RemovePassword(
	ctx context.Context,
	subjectID, currentHash string,
	_ time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockUser(ctx, tx, subjectID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return emailpassword.ErrNotFound
		}
		return err
	}
	var storedHash string
	if err := tx.QueryRow(ctx,
		"SELECT password_hash FROM authlier_password_credentials WHERE user_id = $1", subjectID,
	).Scan(&storedHash); errors.Is(err, pgx.ErrNoRows) {
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
	if _, err := tx.Exec(ctx,
		"DELETE FROM authlier_password_credentials WHERE user_id = $1", subjectID,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *EmailVerificationStore) FindUserByEmail(
	ctx context.Context,
	email string,
) (emailverification.User, error) {
	var user emailverification.User
	err := store.adapter.pool.QueryRow(ctx,
		"SELECT id, email, email_verified FROM authlier_users WHERE email = $1", email,
	).Scan(&user.ID, &user.Email, &user.Verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, emailverification.ErrNotFound
	}
	return user, err
}

func (store *EmailVerificationStore) Issue(ctx context.Context, record emailverification.Record) error {
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_email_verifications
		(user_id, email, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email,
		token_hash = EXCLUDED.token_hash, created_at = EXCLUDED.created_at,
		expires_at = EXCLUDED.expires_at`,
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
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return emailverification.User{}, err
	}
	defer tx.Rollback(ctx)
	var user emailverification.User
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `SELECT u.id, u.email, u.email_verified, v.expires_at
		FROM authlier_email_verifications v
		JOIN authlier_users u ON u.id = v.user_id
		WHERE v.token_hash = $1 FOR UPDATE OF v, u`, tokenHash[:],
	).Scan(&user.ID, &user.Email, &user.Verified, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, emailverification.ErrNotFound
	}
	if err != nil {
		return user, err
	}
	if user.Verified || !verifiedAt.Before(expiresAt) {
		return user, emailverification.ErrInactiveToken
	}
	if _, err := tx.Exec(ctx,
		"UPDATE authlier_users SET email_verified = true WHERE id = $1", user.ID,
	); err != nil {
		return user, err
	}
	if _, err := tx.Exec(ctx,
		"DELETE FROM authlier_email_verifications WHERE user_id = $1", user.ID,
	); err != nil {
		return user, err
	}
	user.Verified = true
	return user, tx.Commit(ctx)
}

func (store *PasswordResetStore) FindUserByEmail(
	ctx context.Context,
	email string,
) (passwordreset.User, error) {
	var user passwordreset.User
	err := store.adapter.pool.QueryRow(ctx,
		"SELECT id, email FROM authlier_users WHERE email = $1", email,
	).Scan(&user.ID, &user.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, passwordreset.ErrNotFound
	}
	return user, err
}

func (store *PasswordResetStore) Issue(ctx context.Context, record passwordreset.Record) error {
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_password_resets
		(user_id, email, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email,
		token_hash = EXCLUDED.token_hash, created_at = EXCLUDED.created_at,
		expires_at = EXCLUDED.expires_at`,
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
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return passwordreset.User{}, err
	}
	defer tx.Rollback(ctx)
	var user passwordreset.User
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `SELECT u.id, u.email, r.expires_at
		FROM authlier_password_resets r
		JOIN authlier_users u ON u.id = r.user_id
		WHERE r.token_hash = $1 FOR UPDATE OF r, u`, tokenHash[:],
	).Scan(&user.ID, &user.Email, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, passwordreset.ErrNotFound
	}
	if err != nil {
		return user, err
	}
	if !resetAt.Before(expiresAt) {
		return user, passwordreset.ErrInactiveToken
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_password_credentials
		(user_id, password_hash, updated_at) VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash,
		updated_at = EXCLUDED.updated_at`, user.ID, passwordHash, resetAt,
	); err != nil {
		return user, err
	}
	if _, err := tx.Exec(ctx,
		"DELETE FROM authlier_password_resets WHERE user_id = $1", user.ID,
	); err != nil {
		return user, err
	}
	return user, tx.Commit(ctx)
}

func (store *GoogleStore) CreateChallenge(ctx context.Context, challenge googleoauth.Challenge) error {
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_google_challenges
		(state_hash, nonce, code_verifier, subject_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
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
	var challenge googleoauth.Challenge
	var storedHash []byte
	err := store.adapter.pool.QueryRow(ctx, `DELETE FROM authlier_google_challenges
		WHERE state_hash = $1
		RETURNING state_hash, nonce, code_verifier, subject_id, created_at, expires_at`,
		stateHash[:],
	).Scan(&storedHash, &challenge.Nonce, &challenge.CodeVerifier, &challenge.SubjectID,
		&challenge.CreatedAt, &challenge.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return challenge, googleoauth.ErrNotFound
	}
	if err != nil {
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
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return googleoauth.User{}, err
	}
	defer tx.Rollback(ctx)

	var linkedUserID string
	err = tx.QueryRow(ctx, `SELECT user_id FROM authlier_google_identities
		WHERE provider_subject = $1 FOR UPDATE`, resolution.ProviderSubject,
	).Scan(&linkedUserID)
	if err == nil {
		if resolution.SubjectID != "" && linkedUserID != resolution.SubjectID {
			return googleoauth.User{}, googleoauth.ErrConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE authlier_google_identities
			SET email = $1 WHERE provider_subject = $2`,
			resolution.Email, resolution.ProviderSubject,
		); err != nil {
			return googleoauth.User{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return googleoauth.User{}, err
		}
		return googleoauth.User{ID: linkedUserID}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return googleoauth.User{}, err
	}

	userID := resolution.SubjectID
	if userID != "" {
		if err := lockUser(ctx, tx, userID); errors.Is(err, pgx.ErrNoRows) {
			return googleoauth.User{}, googleoauth.ErrNotFound
		} else if err != nil {
			return googleoauth.User{}, err
		}
	} else {
		err := tx.QueryRow(ctx,
			"SELECT id FROM authlier_users WHERE email = $1 FOR UPDATE", resolution.Email,
		).Scan(&userID)
		if err == nil {
			return googleoauth.User{}, googleoauth.ErrLinkRequired
		}
		if !errors.Is(err, pgx.ErrNoRows) {
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
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_google_identities
		(provider_subject, user_id, email, linked_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)`,
		resolution.ProviderSubject, userID, resolution.Email,
	); err != nil {
		if uniqueViolation(err) {
			return googleoauth.User{}, googleoauth.ErrConflict
		}
		return googleoauth.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return googleoauth.User{}, err
	}
	return googleoauth.User{ID: userID}, nil
}

func (store *GoogleStore) UnlinkIdentity(
	ctx context.Context,
	subjectID, providerSubject string,
	_ time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockUser(ctx, tx, subjectID); errors.Is(err, pgx.ErrNoRows) {
		return googleoauth.ErrNotFound
	} else if err != nil {
		return err
	}
	var linkedUserID string
	err = tx.QueryRow(ctx, `SELECT user_id FROM authlier_google_identities
		WHERE provider_subject = $1 FOR UPDATE`, providerSubject,
	).Scan(&linkedUserID)
	if errors.Is(err, pgx.ErrNoRows) || linkedUserID != subjectID {
		return googleoauth.ErrNotFound
	}
	if err != nil {
		return err
	}
	var passwordCount, passkeyCount int
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT COUNT(*) FROM authlier_password_credentials WHERE user_id = $1),
		(SELECT COUNT(*) FROM authlier_passkey_credentials WHERE subject_id = $1)`, subjectID,
	).Scan(&passwordCount, &passkeyCount); err != nil {
		return err
	}
	if passwordCount+passkeyCount == 0 {
		return googleoauth.ErrLastCredential
	}
	if _, err := tx.Exec(ctx, `DELETE FROM authlier_google_identities
		WHERE provider_subject = $1 AND user_id = $2`, providerSubject, subjectID,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *GoogleStore) ListIdentities(
	ctx context.Context,
	subjectID string,
) ([]googleoauth.LinkedIdentity, error) {
	rows, err := store.adapter.pool.Query(ctx, `SELECT provider_subject, email, linked_at
		FROM authlier_google_identities WHERE user_id = $1 ORDER BY linked_at`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	identities := make([]googleoauth.LinkedIdentity, 0)
	for rows.Next() {
		var identity googleoauth.LinkedIdentity
		if err := rows.Scan(&identity.ProviderSubject, &identity.Email, &identity.LinkedAt); err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func insertUser(
	ctx context.Context,
	tx pgx.Tx,
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
	_, err = tx.Exec(ctx, `INSERT INTO authlier_users
		(id, email, email_verified, webauthn_handle, created_at)
		VALUES ($1, $2, $3, $4, $5)`, userID, email, verified, handle, createdAt)
	return userID, err
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func lockUser(ctx context.Context, tx pgx.Tx, subjectID string) error {
	var ignored string
	return tx.QueryRow(ctx,
		"SELECT id FROM authlier_users WHERE id = $1 FOR UPDATE", subjectID,
	).Scan(&ignored)
}

func otherCredentialCount(ctx context.Context, tx pgx.Tx, subjectID string) (int, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT
		(SELECT COUNT(*) FROM authlier_google_identities WHERE user_id = $1) +
		(SELECT COUNT(*) FROM authlier_passkey_credentials WHERE subject_id = $1)`, subjectID,
	).Scan(&count)
	return count, err
}

var _ emailpassword.Store = (*EmailPasswordStore)(nil)
var _ emailpassword.CredentialStore = (*EmailPasswordStore)(nil)
var _ emailverification.Store = (*EmailVerificationStore)(nil)
var _ passwordreset.Store = (*PasswordResetStore)(nil)
var _ googleoauth.Store = (*GoogleStore)(nil)
var _ googleoauth.IdentityStore = (*GoogleStore)(nil)
