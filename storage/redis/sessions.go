package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/sessiontoken"
	redislibrary "github.com/redis/go-redis/v9"
)

type SessionStore struct{ adapter *Adapter }
type RefreshTokenStore struct{ adapter *Adapter }
type AccessSessionStore struct{ adapter *Adapter }

func (adapter *Adapter) Sessions() *SessionStore { return &SessionStore{adapter} }
func (adapter *Adapter) RefreshTokens() *RefreshTokenStore {
	return &RefreshTokenStore{adapter}
}
func (adapter *Adapter) AccessSessions() *AccessSessionStore { return &AccessSessionStore{adapter} }

func (store *SessionStore) Create(ctx context.Context, record sessiontoken.Record) error {
	sessions := store.adapter.key("sessions")
	subject := store.adapter.key("sessions:subject:" + record.SubjectID)
	field := hashKey(record.TokenHash[:])
	encoded, _ := encodeJSON(record)
	return store.adapter.watch(ctx, []string{sessions, subject}, func(tx *redislibrary.Tx) error {
		exists, err := tx.HExists(ctx, sessions, field).Result()
		if err != nil {
			return err
		}
		if exists {
			return sessiontoken.ErrConflict
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, sessions, field, encoded)
			pipe.SAdd(ctx, subject, field)
			return nil
		})
		return err
	})
}

func (store *SessionStore) FindByTokenHash(ctx context.Context, tokenHash sessiontoken.TokenHash) (sessiontoken.Record, error) {
	var record sessiontoken.Record
	err := readJSON(ctx, store.adapter.client, store.adapter.key("sessions"), hashKey(tokenHash[:]), &record)
	if errors.Is(err, redislibrary.Nil) {
		return record, sessiontoken.ErrNotFound
	}
	return record, err
}

func (store *SessionStore) ListBySubject(ctx context.Context, subjectID string) ([]sessiontoken.Record, error) {
	fields, err := store.adapter.client.SMembers(ctx, store.adapter.key("sessions:subject:"+subjectID)).Result()
	if err != nil || len(fields) == 0 {
		return []sessiontoken.Record{}, err
	}
	values, err := store.adapter.client.HMGet(ctx, store.adapter.key("sessions"), fields...).Result()
	if err != nil {
		return nil, err
	}
	records := make([]sessiontoken.Record, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		var record sessiontoken.Record
		if err := decodeRedisValue(value, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sortSessions(records)
	return records, nil
}

func (store *SessionStore) Extend(ctx context.Context, tokenHash sessiontoken.TokenHash, extendedAt, expiresAt time.Time) (sessiontoken.Record, error) {
	sessions, field := store.adapter.key("sessions"), hashKey(tokenHash[:])
	var result sessiontoken.Record
	err := store.adapter.watch(ctx, []string{sessions}, func(tx *redislibrary.Tx) error {
		if err := readJSON(ctx, tx, sessions, field, &result); errors.Is(err, redislibrary.Nil) {
			return sessiontoken.ErrInactive
		} else if err != nil {
			return err
		}
		if result.RevokedAt != nil || !extendedAt.Before(result.ExpiresAt) || !result.ExpiresAt.Before(expiresAt) {
			return sessiontoken.ErrInactive
		}
		result.ExtendedAt, result.ExpiresAt = &extendedAt, expiresAt
		encoded, _ := encodeJSON(result)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, sessions, field, encoded)
			return nil
		})
		return err
	})
	return result, err
}

func (store *SessionStore) Rotate(ctx context.Context, current sessiontoken.TokenHash, replacement sessiontoken.Record, rotatedAt time.Time) error {
	sessions := store.adapter.key("sessions")
	currentField, replacementField := hashKey(current[:]), hashKey(replacement.TokenHash[:])
	currentSet, replacementSet := "", store.adapter.key("sessions:subject:"+replacement.SubjectID)
	return store.adapter.watch(ctx, []string{sessions, replacementSet}, func(tx *redislibrary.Tx) error {
		var record sessiontoken.Record
		if err := readJSON(ctx, tx, sessions, currentField, &record); errors.Is(err, redislibrary.Nil) {
			return sessiontoken.ErrNotFound
		} else if err != nil {
			return err
		}
		if record.RevokedAt != nil || !rotatedAt.Before(record.ExpiresAt) {
			return sessiontoken.ErrInactive
		}
		if exists, err := tx.HExists(ctx, sessions, replacementField).Result(); err != nil {
			return err
		} else if exists {
			return sessiontoken.ErrConflict
		}
		currentSet = store.adapter.key("sessions:subject:" + record.SubjectID)
		record.RevokedAt = &rotatedAt
		currentJSON, _ := encodeJSON(record)
		replacementJSON, _ := encodeJSON(replacement)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, sessions, currentField, currentJSON, replacementField, replacementJSON)
			pipe.SAdd(ctx, currentSet, currentField)
			pipe.SAdd(ctx, replacementSet, replacementField)
			return nil
		})
		return err
	})
}

func (store *SessionStore) Revoke(ctx context.Context, tokenHash sessiontoken.TokenHash, revokedAt time.Time) error {
	sessions, field := store.adapter.key("sessions"), hashKey(tokenHash[:])
	return store.adapter.watch(ctx, []string{sessions}, func(tx *redislibrary.Tx) error {
		var record sessiontoken.Record
		if err := readJSON(ctx, tx, sessions, field, &record); errors.Is(err, redislibrary.Nil) {
			return sessiontoken.ErrNotFound
		} else if err != nil {
			return err
		}
		if record.RevokedAt != nil {
			return nil
		}
		record.RevokedAt = &revokedAt
		encoded, _ := encodeJSON(record)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, sessions, field, encoded)
			return nil
		})
		return err
	})
}

func (store *SessionStore) RevokeAll(ctx context.Context, subjectID string, revokedAt time.Time) ([]sessiontoken.Record, error) {
	sessions, subject := store.adapter.key("sessions"), store.adapter.key("sessions:subject:"+subjectID)
	var records []sessiontoken.Record
	err := store.adapter.watch(ctx, []string{sessions, subject}, func(tx *redislibrary.Tx) error {
		fields, err := tx.SMembers(ctx, subject).Result()
		if err != nil {
			return err
		}
		records = make([]sessiontoken.Record, 0, len(fields))
		updates := make(map[string]any, len(fields)*2)
		for _, field := range fields {
			var record sessiontoken.Record
			if err := readJSON(ctx, tx, sessions, field, &record); errors.Is(err, redislibrary.Nil) {
				continue
			} else if err != nil {
				return err
			}
			if record.RevokedAt == nil {
				record.RevokedAt = &revokedAt
			}
			encoded, _ := encodeJSON(record)
			updates[field] = encoded
			records = append(records, record)
		}
		if len(updates) == 0 {
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, sessions, updates)
			return nil
		})
		return err
	})
	return records, err
}

func sortSessions(records []sessiontoken.Record) {
	slices.SortFunc(records, func(left, right sessiontoken.Record) int {
		return right.CreatedAt.Compare(left.CreatedAt)
	})
}

func decodeRedisValue(value any, destination any) error {
	switch encoded := value.(type) {
	case string:
		return json.Unmarshal([]byte(encoded), destination)
	case []byte:
		return json.Unmarshal(encoded, destination)
	default:
		return fmt.Errorf("decode Redis value: unexpected %T", value)
	}
}

func (store *AccessSessionStore) Create(ctx context.Context, session authlier.AccessSession) error {
	key := store.adapter.key("access-sessions")
	encoded, _ := encodeJSON(session)
	created, err := store.adapter.client.HSetNX(ctx, key, session.ID, encoded).Result()
	if err == nil && !created {
		return ErrTransactionConflict
	}
	return err
}

func (store *AccessSessionStore) ResolveSession(ctx context.Context, sessionID string) (accesstoken.Session, error) {
	var session authlier.AccessSession
	err := readJSON(ctx, store.adapter.client, store.adapter.key("access-sessions"), sessionID, &session)
	if err != nil || session.RevokedAt != nil || !time.Now().UTC().Before(session.ExpiresAt) {
		if errors.Is(err, redislibrary.Nil) {
			return accesstoken.Session{}, redislibrary.Nil
		}
		if err == nil {
			return accesstoken.Session{}, accesstoken.ErrInactiveSession
		}
		return accesstoken.Session{}, err
	}
	return accesstoken.Session{ID: session.ID, SubjectID: session.SubjectID}, nil
}

func (store *AccessSessionStore) Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error {
	key := store.adapter.key("access-sessions")
	return store.adapter.watch(ctx, []string{key}, func(tx *redislibrary.Tx) error {
		var session authlier.AccessSession
		if err := readJSON(ctx, tx, key, sessionID, &session); errors.Is(err, redislibrary.Nil) {
			return nil
		} else if err != nil {
			return err
		}
		if session.RevokedAt != nil {
			return nil
		}
		session.RevokedAt = &revokedAt
		encoded, _ := encodeJSON(session)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, key, sessionID, encoded)
			return nil
		})
		return err
	})
}

func (store *RefreshTokenStore) Create(ctx context.Context, record refreshtoken.Record) error {
	refresh := store.adapter.key("refresh-tokens")
	bySession := store.adapter.key("refresh:session:" + record.SessionID)
	field := hashKey(record.TokenHash[:])
	encoded, _ := encodeJSON(record)
	return store.adapter.watch(ctx, []string{refresh, bySession}, func(tx *redislibrary.Tx) error {
		if exists, err := tx.HExists(ctx, refresh, field).Result(); err != nil {
			return err
		} else if exists {
			return refreshtoken.ErrConflict
		}
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, refresh, field, encoded)
			pipe.SAdd(ctx, bySession, field)
			return nil
		})
		return err
	})
}

func (store *RefreshTokenStore) FindByTokenHash(ctx context.Context, tokenHash refreshtoken.TokenHash) (refreshtoken.Record, error) {
	var record refreshtoken.Record
	err := readJSON(ctx, store.adapter.client, store.adapter.key("refresh-tokens"), hashKey(tokenHash[:]), &record)
	if errors.Is(err, redislibrary.Nil) {
		return record, refreshtoken.ErrNotFound
	}
	return record, err
}

func (store *RefreshTokenStore) Rotate(ctx context.Context, current refreshtoken.TokenHash, replacement refreshtoken.Record, rotatedAt time.Time) error {
	refresh, access := store.adapter.key("refresh-tokens"), store.adapter.key("access-sessions")
	currentField, replacementField := hashKey(current[:]), hashKey(replacement.TokenHash[:])
	reused := false
	err := store.adapter.watch(ctx, []string{refresh, access}, func(tx *redislibrary.Tx) error {
		var record refreshtoken.Record
		if err := readJSON(ctx, tx, refresh, currentField, &record); errors.Is(err, redislibrary.Nil) {
			return refreshtoken.ErrNotFound
		} else if err != nil {
			return err
		}
		if record.RotatedAt != nil || record.RevokedAt != nil || !rotatedAt.Before(record.ExpiresAt) {
			reused = true
			return store.revokeSessionInTransaction(ctx, tx, record.SessionID, rotatedAt)
		}
		if exists, err := tx.HExists(ctx, refresh, replacementField).Result(); err != nil {
			return err
		} else if exists {
			return refreshtoken.ErrConflict
		}
		record.RotatedAt = &rotatedAt
		currentJSON, _ := encodeJSON(record)
		replacementJSON, _ := encodeJSON(replacement)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, refresh, currentField, currentJSON, replacementField, replacementJSON)
			pipe.SAdd(ctx, store.adapter.key("refresh:session:"+replacement.SessionID), replacementField)
			return nil
		})
		return err
	})
	if err == nil && reused {
		return refreshtoken.ErrReuseDetected
	}
	return err
}

func (store *RefreshTokenStore) RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error {
	refresh, access := store.adapter.key("refresh-tokens"), store.adapter.key("access-sessions")
	set := store.adapter.key("refresh:session:" + sessionID)
	return store.adapter.watch(ctx, []string{refresh, access, set}, func(tx *redislibrary.Tx) error {
		return store.revokeSessionInTransaction(ctx, tx, sessionID, revokedAt)
	})
}

func (store *RefreshTokenStore) revokeSessionInTransaction(ctx context.Context, tx *redislibrary.Tx, sessionID string, revokedAt time.Time) error {
	refresh, access := store.adapter.key("refresh-tokens"), store.adapter.key("access-sessions")
	fields, err := tx.SMembers(ctx, store.adapter.key("refresh:session:"+sessionID)).Result()
	if err != nil {
		return err
	}
	updates := make(map[string]any, len(fields)*2)
	for _, field := range fields {
		var record refreshtoken.Record
		if err := readJSON(ctx, tx, refresh, field, &record); err != nil {
			if errors.Is(err, redislibrary.Nil) {
				continue
			}
			return err
		}
		if record.RevokedAt == nil {
			record.RevokedAt = &revokedAt
		}
		encoded, _ := encodeJSON(record)
		updates[field] = encoded
	}
	var session authlier.AccessSession
	sessionErr := readJSON(ctx, tx, access, sessionID, &session)
	if sessionErr != nil && !errors.Is(sessionErr, redislibrary.Nil) {
		return sessionErr
	}
	_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
		if len(updates) > 0 {
			pipe.HSet(ctx, refresh, updates)
		}
		if sessionErr == nil && session.RevokedAt == nil {
			session.RevokedAt = &revokedAt
			encoded, _ := encodeJSON(session)
			pipe.HSet(ctx, access, sessionID, encoded)
		}
		return nil
	})
	return err
}

var _ sessiontoken.Store = (*SessionStore)(nil)
var _ refreshtoken.Store = (*RefreshTokenStore)(nil)
var _ authlier.AccessSessionStore = (*AccessSessionStore)(nil)
