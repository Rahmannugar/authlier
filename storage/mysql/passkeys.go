package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/passkey"
)

type PasskeyStore struct{ adapter *Adapter }

func (adapter *Adapter) Passkeys() *PasskeyStore { return &PasskeyStore{adapter: adapter} }

func (store *PasskeyStore) FindUserBySubject(ctx context.Context, subjectID string) (passkey.User, error) {
	return store.findUser(ctx, "u.id = ?", subjectID)
}

func (store *PasskeyStore) FindUserByCredential(
	ctx context.Context,
	credentialID, userHandle []byte,
) (passkey.User, error) {
	return store.findUser(ctx, `u.webauthn_handle = ? AND EXISTS (
		SELECT 1 FROM authlier_passkey_credentials c
		WHERE c.subject_id = u.id AND c.credential_id = ?
	)`, userHandle, credentialID)
}

func (store *PasskeyStore) findUser(
	ctx context.Context,
	predicate string,
	arguments ...interface{},
) (passkey.User, error) {
	var user passkey.User
	err := store.adapter.database.QueryRowContext(ctx, `SELECT u.id, u.webauthn_handle, u.email
		FROM authlier_users u WHERE `+predicate, arguments...,
	).Scan(&user.SubjectID, &user.Handle, &user.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return user, passkey.ErrNotFound
	}
	if err != nil {
		return user, err
	}
	user.DisplayName = user.Name
	rows, err := store.adapter.database.QueryContext(ctx,
		"SELECT credential FROM authlier_passkey_credentials WHERE subject_id = ?", user.SubjectID)
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
	_, err = store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_passkey_ceremonies
		(token_hash, ceremony_type, subject_id, session_data, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ceremony.TokenHash[:], ceremony.Type,
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
	err := store.adapter.database.QueryRowContext(ctx, `SELECT token_hash, ceremony_type, subject_id,
		session_data, created_at, expires_at FROM authlier_passkey_ceremonies
		WHERE token_hash = ? AND consumed_at IS NULL`, ceremonyHash[:],
	).Scan(&hash, &ceremony.Type, &ceremony.SubjectID, &sessionData,
		&ceremony.CreatedAt, &ceremony.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
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
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := consumePasskeyCeremony(ctx, tx, ceremonyHash, subjectID,
		passkey.CeremonyRegistration, completedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_passkey_credentials
		(credential_id, subject_id, credential, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`, credential.ID, subjectID, encoded, completedAt, completedAt); err != nil {
		if uniqueViolation(err) {
			return passkey.ErrConflict
		}
		return err
	}
	return tx.Commit()
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
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := consumePasskeyCeremony(ctx, tx, ceremonyHash, subjectID,
		passkey.CeremonyAuthentication, completedAt); err != nil {
		return err
	}
	tag, err := tx.ExecContext(ctx, `UPDATE authlier_passkey_credentials
		SET credential = ?, updated_at = ?
		WHERE credential_id = ? AND subject_id = ? AND credential = CAST(? AS JSON)`,
		updatedJSON, completedAt, previous.ID, subjectID, previousJSON)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return passkey.ErrConflict
	}
	return tx.Commit()
}

func (store *PasskeyStore) DeleteCredential(
	ctx context.Context,
	subjectID string,
	credentialID []byte,
	_ time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockUser(ctx, tx, subjectID); errors.Is(err, sql.ErrNoRows) {
		return passkey.ErrNotFound
	} else if err != nil {
		return err
	}
	var passkeys, passwords, googleIdentities int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM authlier_passkey_credentials WHERE subject_id = ?),
		(SELECT COUNT(*) FROM authlier_password_credentials WHERE user_id = ?),
		(SELECT COUNT(*) FROM authlier_google_identities WHERE user_id = ?)`, subjectID, subjectID, subjectID,
	).Scan(&passkeys, &passwords, &googleIdentities); err != nil {
		return err
	}
	if passkeys == 1 && passwords+googleIdentities == 0 {
		return passkey.ErrLastCredential
	}
	tag, err := tx.ExecContext(ctx, `DELETE FROM authlier_passkey_credentials
		WHERE subject_id = ? AND credential_id = ?`, subjectID, credentialID)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return passkey.ErrNotFound
	}
	return tx.Commit()
}

func consumePasskeyCeremony(
	ctx context.Context,
	tx *sql.Tx,
	hash passkey.CeremonyHash,
	subjectID string,
	ceremonyType passkey.CeremonyType,
	at time.Time,
) error {
	tag, err := tx.ExecContext(ctx, `UPDATE authlier_passkey_ceremonies SET consumed_at = ?
		WHERE token_hash = ? AND ceremony_type = ? AND subject_id = ?
		AND consumed_at IS NULL AND expires_at > ?`, at, hash[:], ceremonyType, subjectID, at)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return passkey.ErrInactiveCeremony
	}
	return nil
}

var _ passkey.Store = (*PasskeyStore)(nil)
