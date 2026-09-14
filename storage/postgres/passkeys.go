package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/passkey"
	"github.com/jackc/pgx/v5"
)

type PasskeyStore struct{ adapter *Adapter }

func (adapter *Adapter) Passkeys() *PasskeyStore { return &PasskeyStore{adapter: adapter} }

func (store *PasskeyStore) FindUserBySubject(ctx context.Context, subjectID string) (passkey.User, error) {
	return store.findUser(ctx, "u.id = $1", subjectID)
}

func (store *PasskeyStore) FindUserByCredential(
	ctx context.Context,
	credentialID, userHandle []byte,
) (passkey.User, error) {
	return store.findUser(ctx, `u.webauthn_handle = $1 AND EXISTS (
		SELECT 1 FROM authlier_passkey_credentials c
		WHERE c.subject_id = u.id AND c.credential_id = $2
	)`, userHandle, credentialID)
}

func (store *PasskeyStore) findUser(
	ctx context.Context,
	predicate string,
	arguments ...any,
) (passkey.User, error) {
	var user passkey.User
	err := store.adapter.pool.QueryRow(ctx, `SELECT u.id, u.webauthn_handle, u.email
		FROM authlier_users u WHERE `+predicate, arguments...,
	).Scan(&user.SubjectID, &user.Handle, &user.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return user, passkey.ErrNotFound
	}
	if err != nil {
		return user, err
	}
	user.DisplayName = user.Name
	rows, err := store.adapter.pool.Query(ctx,
		"SELECT credential FROM authlier_passkey_credentials WHERE subject_id = $1", user.SubjectID)
	if err != nil {
		return user, err
	}
	defer rows.Close()
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return user, err
		}
		var credential passkey.Credential
		if err := json.Unmarshal(encoded, &credential); err != nil {
			return user, err
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, rows.Err()
}

func (store *PasskeyStore) CreateCeremony(ctx context.Context, ceremony passkey.Ceremony) error {
	sessionData, err := json.Marshal(ceremony.Session)
	if err != nil {
		return err
	}
	_, err = store.adapter.pool.Exec(ctx, `INSERT INTO authlier_passkey_ceremonies
		(token_hash, ceremony_type, subject_id, session_data, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, ceremony.TokenHash[:], ceremony.Type,
		ceremony.SubjectID, sessionData, ceremony.CreatedAt, ceremony.ExpiresAt)
	if uniqueViolation(err) {
		return passkey.ErrConflict
	}
	return err
}

func (store *PasskeyStore) FindCeremony(
	ctx context.Context,
	ceremonyHash passkey.CeremonyHash,
) (passkey.Ceremony, error) {
	var ceremony passkey.Ceremony
	var hash, sessionData []byte
	err := store.adapter.pool.QueryRow(ctx, `SELECT token_hash, ceremony_type, subject_id,
		session_data, created_at, expires_at FROM authlier_passkey_ceremonies
		WHERE token_hash = $1 AND consumed_at IS NULL`, ceremonyHash[:],
	).Scan(&hash, &ceremony.Type, &ceremony.SubjectID, &sessionData,
		&ceremony.CreatedAt, &ceremony.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony, passkey.ErrNotFound
	}
	if err != nil {
		return ceremony, err
	}
	copy(ceremony.TokenHash[:], hash)
	if err := json.Unmarshal(sessionData, &ceremony.Session); err != nil {
		return ceremony, err
	}
	return ceremony, nil
}

func (store *PasskeyStore) CompleteRegistration(
	ctx context.Context,
	ceremonyHash passkey.CeremonyHash,
	subjectID string,
	credential passkey.Credential,
	completedAt time.Time,
) error {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := consumePasskeyCeremony(ctx, tx, ceremonyHash, subjectID,
		passkey.CeremonyRegistration, completedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_passkey_credentials
		(credential_id, subject_id, credential, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $4)`, credential.ID, subjectID, encoded, completedAt); err != nil {
		if uniqueViolation(err) {
			return passkey.ErrConflict
		}
		return err
	}
	return tx.Commit(ctx)
}

func (store *PasskeyStore) CompleteAuthentication(
	ctx context.Context,
	ceremonyHash passkey.CeremonyHash,
	subjectID string,
	previous, updated passkey.Credential,
	completedAt time.Time,
) error {
	previousJSON, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	updatedJSON, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := consumePasskeyCeremony(ctx, tx, ceremonyHash, subjectID,
		passkey.CeremonyAuthentication, completedAt); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE authlier_passkey_credentials
		SET credential = $1, updated_at = $2
		WHERE credential_id = $3 AND subject_id = $4 AND credential = $5::jsonb`,
		updatedJSON, completedAt, previous.ID, subjectID, previousJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrConflict
	}
	return tx.Commit(ctx)
}

func (store *PasskeyStore) DeleteCredential(
	ctx context.Context,
	subjectID string,
	credentialID []byte,
	_ time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockUser(ctx, tx, subjectID); errors.Is(err, pgx.ErrNoRows) {
		return passkey.ErrNotFound
	} else if err != nil {
		return err
	}
	var passkeys, passwords, googleIdentities int
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT COUNT(*) FROM authlier_passkey_credentials WHERE subject_id = $1),
		(SELECT COUNT(*) FROM authlier_password_credentials WHERE user_id = $1),
		(SELECT COUNT(*) FROM authlier_google_identities WHERE user_id = $1)`, subjectID,
	).Scan(&passkeys, &passwords, &googleIdentities); err != nil {
		return err
	}
	if passkeys == 1 && passwords+googleIdentities == 0 {
		return passkey.ErrLastCredential
	}
	tag, err := tx.Exec(ctx, `DELETE FROM authlier_passkey_credentials
		WHERE subject_id = $1 AND credential_id = $2`, subjectID, credentialID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrNotFound
	}
	return tx.Commit(ctx)
}

func consumePasskeyCeremony(
	ctx context.Context,
	tx pgx.Tx,
	hash passkey.CeremonyHash,
	subjectID string,
	ceremonyType passkey.CeremonyType,
	at time.Time,
) error {
	tag, err := tx.Exec(ctx, `UPDATE authlier_passkey_ceremonies SET consumed_at = $1
		WHERE token_hash = $2 AND ceremony_type = $3 AND subject_id = $4
		AND consumed_at IS NULL AND expires_at > $1`, at, hash[:], ceremonyType, subjectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrInactiveCeremony
	}
	return nil
}

var _ passkey.Store = (*PasskeyStore)(nil)
