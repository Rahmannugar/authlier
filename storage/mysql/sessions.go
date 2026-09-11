package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/sessiontoken"
)

type SessionStore struct{ adapter *Adapter }
type RefreshTokenStore struct{ adapter *Adapter }
type AccessSessionStore struct{ adapter *Adapter }

func (adapter *Adapter) Sessions() *SessionStore { return &SessionStore{adapter: adapter} }
func (adapter *Adapter) RefreshTokens() *RefreshTokenStore {
	return &RefreshTokenStore{adapter: adapter}
}
func (adapter *Adapter) AccessSessions() *AccessSessionStore {
	return &AccessSessionStore{adapter: adapter}
}

func (store *SessionStore) Create(ctx context.Context, record sessiontoken.Record) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_sessions
		(token_hash, subject_id, created_at, expires_at, extended_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?)`, record.TokenHash[:], record.SubjectID,
		record.CreatedAt, record.ExpiresAt, record.ExtendedAt, record.RevokedAt)
	if uniqueViolation(err) {
		return sessiontoken.ErrConflict
	}
	return err
}

func (store *SessionStore) FindByTokenHash(
	ctx context.Context,
	tokenHash sessiontoken.TokenHash,
) (sessiontoken.Record, error) {
	return scanSession(store.adapter.database.QueryRowContext(ctx, `SELECT token_hash, subject_id,
		created_at, expires_at, extended_at, revoked_at FROM authlier_sessions
		WHERE token_hash = ?`, tokenHash[:]))
}

func (store *SessionStore) ListBySubject(
	ctx context.Context,
	subjectID string,
) ([]sessiontoken.Record, error) {
	rows, err := store.adapter.database.QueryContext(ctx, `SELECT token_hash, subject_id,
		created_at, expires_at, extended_at, revoked_at FROM authlier_sessions
		WHERE subject_id = ? ORDER BY created_at DESC`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]sessiontoken.Record, 0)
	for rows.Next() {
		record, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *SessionStore) Extend(
	ctx context.Context,
	tokenHash sessiontoken.TokenHash,
	extendedAt, expiresAt time.Time,
) (sessiontoken.Record, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return sessiontoken.Record{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE authlier_sessions
		SET extended_at = ?, expires_at = ?
		WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? AND expires_at < ?
		`, extendedAt, expiresAt, tokenHash[:], extendedAt, expiresAt)
	if err != nil {
		return sessiontoken.Record{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return sessiontoken.Record{}, err
	}
	if affected == 0 {
		return sessiontoken.Record{}, sessiontoken.ErrInactive
	}
	record, err := scanSession(tx.QueryRowContext(ctx, `SELECT token_hash, subject_id,
		created_at, expires_at, extended_at, revoked_at FROM authlier_sessions
		WHERE token_hash = ?`, tokenHash[:]))
	if err != nil {
		return record, err
	}
	return record, tx.Commit()
}

func (store *SessionStore) Rotate(
	ctx context.Context,
	current sessiontoken.TokenHash,
	replacement sessiontoken.Record,
	rotatedAt time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expiresAt time.Time
	var revokedAt *time.Time
	if err := tx.QueryRowContext(ctx, `SELECT expires_at, revoked_at FROM authlier_sessions
		WHERE token_hash = ? FOR UPDATE`, current[:]).Scan(&expiresAt, &revokedAt); errors.Is(err, sql.ErrNoRows) {
		return sessiontoken.ErrNotFound
	} else if err != nil {
		return err
	}
	if revokedAt != nil || !rotatedAt.Before(expiresAt) {
		return sessiontoken.ErrInactive
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_sessions
		(token_hash, subject_id, created_at, expires_at, extended_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?)`, replacement.TokenHash[:], replacement.SubjectID,
		replacement.CreatedAt, replacement.ExpiresAt, replacement.ExtendedAt, replacement.RevokedAt); err != nil {
		if uniqueViolation(err) {
			return sessiontoken.ErrConflict
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authlier_sessions SET revoked_at = ?
		WHERE token_hash = ?`, rotatedAt, current[:]); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *SessionStore) Revoke(
	ctx context.Context,
	tokenHash sessiontoken.TokenHash,
	revokedAt time.Time,
) error {
	tag, err := store.adapter.database.ExecContext(ctx, `UPDATE authlier_sessions
		SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?`, revokedAt, tokenHash[:])
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sessiontoken.ErrNotFound
	}
	return nil
}

func (store *SessionStore) RevokeAll(
	ctx context.Context,
	subjectID string,
	revokedAt time.Time,
) ([]sessiontoken.Record, error) {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT token_hash, subject_id, created_at,
		expires_at, extended_at, revoked_at FROM authlier_sessions
		WHERE subject_id = ? FOR UPDATE`, subjectID)
	if err != nil {
		return nil, err
	}
	records := make([]sessiontoken.Record, 0)
	for rows.Next() {
		record, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		if record.RevokedAt == nil {
			revoked := revokedAt
			record.RevokedAt = &revoked
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `UPDATE authlier_sessions
		SET revoked_at = COALESCE(revoked_at, ?) WHERE subject_id = ?`, revokedAt, subjectID); err != nil {
		return nil, err
	}
	return records, tx.Commit()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSession(row rowScanner) (sessiontoken.Record, error) {
	var record sessiontoken.Record
	var hash []byte
	if err := row.Scan(&hash, &record.SubjectID, &record.CreatedAt, &record.ExpiresAt,
		&record.ExtendedAt, &record.RevokedAt); errors.Is(err, sql.ErrNoRows) {
		return record, sessiontoken.ErrNotFound
	} else if err != nil {
		return record, err
	}
	copy(record.TokenHash[:], hash)
	return record, nil
}

func (store *AccessSessionStore) Create(ctx context.Context, session authlier.AccessSession) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_access_sessions
		(id, subject_id, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?)`,
		session.ID, session.SubjectID, session.CreatedAt, session.ExpiresAt, session.RevokedAt)
	return err
}

func (store *AccessSessionStore) ResolveSession(
	ctx context.Context,
	sessionID string,
) (accesstoken.Session, error) {
	var session accesstoken.Session
	err := store.adapter.database.QueryRowContext(ctx, `SELECT id, subject_id FROM authlier_access_sessions
		WHERE id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP`, sessionID,
	).Scan(&session.ID, &session.SubjectID)
	return session, err
}

func (store *AccessSessionStore) Revoke(
	ctx context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	_, err := store.adapter.database.ExecContext(ctx, `UPDATE authlier_access_sessions
		SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, revokedAt, sessionID)
	return err
}

func (store *RefreshTokenStore) Create(ctx context.Context, record refreshtoken.Record) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_refresh_tokens
		(token_hash, session_id, created_at, expires_at, rotated_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?)`, record.TokenHash[:], record.SessionID,
		record.CreatedAt, record.ExpiresAt, record.RotatedAt, record.RevokedAt)
	if uniqueViolation(err) {
		return refreshtoken.ErrConflict
	}
	return err
}

func (store *RefreshTokenStore) FindByTokenHash(
	ctx context.Context,
	tokenHash refreshtoken.TokenHash,
) (refreshtoken.Record, error) {
	var record refreshtoken.Record
	var hash []byte
	err := store.adapter.database.QueryRowContext(ctx, `SELECT token_hash, session_id, created_at,
		expires_at, rotated_at, revoked_at FROM authlier_refresh_tokens WHERE token_hash = ?`,
		tokenHash[:]).Scan(&hash, &record.SessionID, &record.CreatedAt, &record.ExpiresAt,
		&record.RotatedAt, &record.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return record, refreshtoken.ErrNotFound
	}
	copy(record.TokenHash[:], hash)
	return record, err
}

func (store *RefreshTokenStore) Rotate(
	ctx context.Context,
	current refreshtoken.TokenHash,
	replacement refreshtoken.Record,
	rotatedAt time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sessionID string
	var expiresAt time.Time
	var previousRotation, revokedAt *time.Time
	err = tx.QueryRowContext(ctx, `SELECT session_id, expires_at, rotated_at, revoked_at
		FROM authlier_refresh_tokens WHERE token_hash = ? FOR UPDATE`, current[:],
	).Scan(&sessionID, &expiresAt, &previousRotation, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return refreshtoken.ErrNotFound
	}
	if err != nil {
		return err
	}
	if previousRotation != nil || revokedAt != nil || !rotatedAt.Before(expiresAt) {
		if err := revokeAccessSession(ctx, tx, sessionID, rotatedAt); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return refreshtoken.ErrReuseDetected
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authlier_refresh_tokens
		(token_hash, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		replacement.TokenHash[:], replacement.SessionID, replacement.CreatedAt, replacement.ExpiresAt,
	); err != nil {
		if uniqueViolation(err) {
			return refreshtoken.ErrConflict
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authlier_refresh_tokens SET rotated_at = ?
		WHERE token_hash = ?`, rotatedAt, current[:]); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *RefreshTokenStore) RevokeSession(
	ctx context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := revokeAccessSession(ctx, tx, sessionID, revokedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeAccessSession(ctx context.Context, tx *sql.Tx, sessionID string, revokedAt time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE authlier_access_sessions
		SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, revokedAt, sessionID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE authlier_refresh_tokens
		SET revoked_at = COALESCE(revoked_at, ?) WHERE session_id = ?`, revokedAt, sessionID)
	return err
}

var _ sessiontoken.Store = (*SessionStore)(nil)
var _ refreshtoken.Store = (*RefreshTokenStore)(nil)
var _ accesstoken.SessionResolver = (*AccessSessionStore)(nil)
