package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/sessiontoken"
	"github.com/jackc/pgx/v5"
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
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_sessions
		(id, token_hash, subject_id, created_at, expires_at, extended_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, record.ID, record.TokenHash[:], record.SubjectID,
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
	return scanSession(store.adapter.pool.QueryRow(ctx, `SELECT id, token_hash, subject_id,
		created_at, expires_at, extended_at, revoked_at FROM authlier_sessions
		WHERE token_hash = $1`, tokenHash[:]))
}

func (store *SessionStore) ListBySubject(
	ctx context.Context,
	subjectID string,
) ([]sessiontoken.Record, error) {
	rows, err := store.adapter.pool.Query(ctx, `SELECT id, token_hash, subject_id,
		created_at, expires_at, extended_at, revoked_at FROM authlier_sessions
		WHERE subject_id = $1 ORDER BY created_at DESC`, subjectID)
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
	row := store.adapter.pool.QueryRow(ctx, `UPDATE authlier_sessions
		SET extended_at = $1, expires_at = $2
		WHERE token_hash = $3 AND revoked_at IS NULL AND expires_at > $1 AND expires_at < $2
		RETURNING id, token_hash, subject_id, created_at, expires_at, extended_at, revoked_at`,
		extendedAt, expiresAt, tokenHash[:])
	record, err := scanSession(row)
	if errors.Is(err, sessiontoken.ErrNotFound) {
		return record, sessiontoken.ErrInactive
	}
	return record, err
}

func (store *SessionStore) Rotate(
	ctx context.Context,
	current sessiontoken.TokenHash,
	replacement sessiontoken.Record,
	rotatedAt time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var expiresAt time.Time
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT expires_at, revoked_at FROM authlier_sessions
		WHERE token_hash = $1 FOR UPDATE`, current[:]).Scan(&expiresAt, &revokedAt); errors.Is(err, pgx.ErrNoRows) {
		return sessiontoken.ErrNotFound
	} else if err != nil {
		return err
	}
	if revokedAt != nil || !rotatedAt.Before(expiresAt) {
		return sessiontoken.ErrInactive
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_sessions
		(id, token_hash, subject_id, created_at, expires_at, extended_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, replacement.ID, replacement.TokenHash[:], replacement.SubjectID,
		replacement.CreatedAt, replacement.ExpiresAt, replacement.ExtendedAt, replacement.RevokedAt); err != nil {
		if uniqueViolation(err) {
			return sessiontoken.ErrConflict
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authlier_sessions SET revoked_at = $1
		WHERE token_hash = $2`, rotatedAt, current[:]); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *SessionStore) Revoke(
	ctx context.Context,
	tokenHash sessiontoken.TokenHash,
	revokedAt time.Time,
) error {
	tag, err := store.adapter.pool.Exec(ctx, `UPDATE authlier_sessions
		SET revoked_at = COALESCE(revoked_at, $1) WHERE token_hash = $2`, revokedAt, tokenHash[:])
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return sessiontoken.ErrNotFound
	}
	return nil
}

func (store *SessionStore) RevokeAll(
	ctx context.Context,
	subjectID string,
	revokedAt time.Time,
) ([]sessiontoken.Record, error) {
	rows, err := store.adapter.pool.Query(ctx, `UPDATE authlier_sessions
		SET revoked_at = COALESCE(revoked_at, $1) WHERE subject_id = $2
		RETURNING id, token_hash, subject_id, created_at, expires_at, extended_at, revoked_at`,
		revokedAt, subjectID)
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

type rowScanner interface{ Scan(dest ...any) error }

func scanSession(row rowScanner) (sessiontoken.Record, error) {
	var record sessiontoken.Record
	var hash []byte
	if err := row.Scan(&record.ID, &hash, &record.SubjectID, &record.CreatedAt, &record.ExpiresAt,
		&record.ExtendedAt, &record.RevokedAt); errors.Is(err, pgx.ErrNoRows) {
		return record, sessiontoken.ErrNotFound
	} else if err != nil {
		return record, err
	}
	copy(record.TokenHash[:], hash)
	return record, nil
}

func (store *AccessSessionStore) CreateSession(
	ctx context.Context,
	session authlier.AccessSession,
	refreshToken refreshtoken.Record,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_access_sessions
		(id, subject_id, created_at, expires_at, revoked_at) VALUES ($1, $2, $3, $4, $5)`,
		session.ID, session.SubjectID, session.CreatedAt, session.ExpiresAt, session.RevokedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_refresh_tokens
		(token_hash, session_id, created_at, expires_at, rotated_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, refreshToken.TokenHash[:], refreshToken.SessionID,
		refreshToken.CreatedAt, refreshToken.ExpiresAt, refreshToken.RotatedAt,
		refreshToken.RevokedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *AccessSessionStore) ResolveSession(
	ctx context.Context,
	sessionID string,
) (accesstoken.Session, error) {
	var session accesstoken.Session
	err := store.adapter.pool.QueryRow(ctx, `SELECT id, subject_id, created_at, expires_at FROM authlier_access_sessions
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP`, sessionID,
	).Scan(&session.ID, &session.SubjectID, &session.CreatedAt, &session.ExpiresAt)
	return session, err
}

func (store *AccessSessionStore) ListBySubject(
	ctx context.Context,
	subjectID string,
) ([]authlier.AccessSession, error) {
	rows, err := store.adapter.pool.Query(ctx, `SELECT id, subject_id, created_at, expires_at, revoked_at
		FROM authlier_access_sessions WHERE subject_id = $1 ORDER BY created_at DESC`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]authlier.AccessSession, 0)
	for rows.Next() {
		var record authlier.AccessSession
		if err := rows.Scan(
			&record.ID, &record.SubjectID, &record.CreatedAt, &record.ExpiresAt, &record.RevokedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *AccessSessionStore) Revoke(
	ctx context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := revokeAccessSession(ctx, tx, sessionID, revokedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *AccessSessionStore) RevokeAll(
	ctx context.Context,
	subjectID string,
	revokedAt time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE authlier_refresh_tokens SET revoked_at = COALESCE(revoked_at, $1)
		WHERE session_id IN (SELECT id FROM authlier_access_sessions WHERE subject_id = $2)`,
		revokedAt, subjectID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authlier_access_sessions SET revoked_at = COALESCE(revoked_at, $1)
		WHERE subject_id = $2`, revokedAt, subjectID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *RefreshTokenStore) Create(ctx context.Context, record refreshtoken.Record) error {
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_refresh_tokens
		(token_hash, session_id, created_at, expires_at, rotated_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, record.TokenHash[:], record.SessionID,
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
	err := store.adapter.pool.QueryRow(ctx, `SELECT token_hash, session_id, created_at,
		expires_at, rotated_at, revoked_at FROM authlier_refresh_tokens WHERE token_hash = $1`,
		tokenHash[:]).Scan(&hash, &record.SessionID, &record.CreatedAt, &record.ExpiresAt,
		&record.RotatedAt, &record.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
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
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var sessionID string
	var expiresAt time.Time
	var previousRotation, revokedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT session_id, expires_at, rotated_at, revoked_at
		FROM authlier_refresh_tokens WHERE token_hash = $1 FOR UPDATE`, current[:],
	).Scan(&sessionID, &expiresAt, &previousRotation, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return refreshtoken.ErrNotFound
	}
	if err != nil {
		return err
	}
	if previousRotation != nil || revokedAt != nil || !rotatedAt.Before(expiresAt) {
		if err := revokeAccessSession(ctx, tx, sessionID, rotatedAt); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return refreshtoken.ErrReuseDetected
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authlier_refresh_tokens
		(token_hash, session_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		replacement.TokenHash[:], replacement.SessionID, replacement.CreatedAt, replacement.ExpiresAt,
	); err != nil {
		if uniqueViolation(err) {
			return refreshtoken.ErrConflict
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE authlier_refresh_tokens SET rotated_at = $1
		WHERE token_hash = $2`, rotatedAt, current[:]); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *RefreshTokenStore) RevokeSession(
	ctx context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	tx, err := store.adapter.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := revokeAccessSession(ctx, tx, sessionID, revokedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func revokeAccessSession(ctx context.Context, tx pgx.Tx, sessionID string, revokedAt time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE authlier_access_sessions
		SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2`, revokedAt, sessionID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE authlier_refresh_tokens
		SET revoked_at = COALESCE(revoked_at, $1) WHERE session_id = $2`, revokedAt, sessionID)
	return err
}

var _ sessiontoken.Store = (*SessionStore)(nil)
var _ refreshtoken.Store = (*RefreshTokenStore)(nil)
var _ authlier.AccessSessionStore = (*AccessSessionStore)(nil)
