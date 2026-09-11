// Package sessiontoken manages opaque server-side sessions.
package sessiontoken

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/token"
)

const creationAttempts = 3

var (
	ErrCacheMiss     = errors.New("session cache miss")
	ErrCacheSync     = errors.New("session cache synchronization failed")
	ErrConflict      = errors.New("session credential conflict")
	ErrInactive      = errors.New("session is inactive")
	ErrInvalidConfig = errors.New("invalid session configuration")
	ErrInvalidRecord = errors.New("invalid session record")
	ErrInvalidToken  = token.ErrInvalidToken
	ErrNotFound      = errors.New("session not found")
)

// TokenHash is the durable representation of a session token.
type TokenHash = token.Hash

// Record is the server-side state associated with an opaque session token.
type Record struct {
	SubjectID  string
	TokenHash  TokenHash
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ExtendedAt *time.Time
	RevokedAt  *time.Time
}

// ActiveAt reports whether the record can authenticate at the supplied time.
// Expiry is exclusive: a record is inactive at its ExpiresAt boundary.
func (record Record) ActiveAt(at time.Time) bool {
	return record.RevokedAt == nil && at.Before(record.ExpiresAt)
}

// Issued contains a new raw token and its server-side record.
type Issued struct {
	Token  string
	Record Record
}

// Store is the durable authority for sessions.
//
// Extend only increases the expiry of an active record. Rotate atomically
// invalidates current and creates replacement. Revoke is idempotent.
type Store interface {
	Create(ctx context.Context, record Record) error
	FindByTokenHash(ctx context.Context, tokenHash TokenHash) (Record, error)
	ListBySubject(ctx context.Context, subjectID string) ([]Record, error)
	Extend(ctx context.Context, tokenHash TokenHash, extendedAt, expiresAt time.Time) (Record, error)
	Rotate(ctx context.Context, current TokenHash, replacement Record, rotatedAt time.Time) error
	Revoke(ctx context.Context, tokenHash TokenHash, revokedAt time.Time) error
	RevokeAll(ctx context.Context, subjectID string, revokedAt time.Time) ([]Record, error)
}

// Cache is an optional bounded-TTL acceleration layer.
type Cache interface {
	Get(ctx context.Context, tokenHash TokenHash) (Record, error)
	Set(ctx context.Context, record Record, ttl time.Duration) error
	Delete(ctx context.Context, tokenHash TokenHash) error
}

type ExtensionConfig struct {
	After            time.Duration
	AbsoluteLifetime time.Duration
}

type Config struct {
	Lifetime  time.Duration
	CacheTTL  time.Duration
	Extension *ExtensionConfig
	Now       func() time.Time
}

type Manager struct {
	store     Store
	cache     Cache
	lifetime  time.Duration
	cacheTTL  time.Duration
	extension *ExtensionConfig
	now       func() time.Time
}

func NewManager(store Store, cache Cache, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if config.Lifetime <= 0 {
		return nil, fmt.Errorf("%w: lifetime must be positive", ErrInvalidConfig)
	}
	if cache != nil && config.CacheTTL <= 0 {
		return nil, fmt.Errorf("%w: cache TTL must be positive when cache is configured", ErrInvalidConfig)
	}
	if config.Extension != nil && (config.Extension.After <= 0 ||
		config.Extension.After >= config.Lifetime ||
		config.Extension.AbsoluteLifetime <= config.Lifetime) {
		return nil, fmt.Errorf("%w: invalid extension settings", ErrInvalidConfig)
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}

	manager := &Manager{
		store:    store,
		cache:    cache,
		lifetime: config.Lifetime,
		cacheTTL: config.CacheTTL,
		now:      now,
	}
	if config.Extension != nil {
		extension := *config.Extension
		manager.extension = &extension
	}
	return manager, nil
}

// Create commits a new session to durable storage before returning its raw
// credential. A cache population failure does not change durable success.
func (manager *Manager) Create(ctx context.Context, subjectID string) (Issued, error) {
	if strings.TrimSpace(subjectID) == "" {
		return Issued{}, fmt.Errorf("%w: subject ID is required", ErrInvalidRecord)
	}

	for range creationAttempts {
		issued, err := manager.newIssued(subjectID)
		if err != nil {
			return Issued{}, err
		}
		if err := manager.store.Create(ctx, issued.Record); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Issued{}, fmt.Errorf("create durable session: %w", err)
		}

		manager.populateCache(ctx, issued.Record)
		return issued, nil
	}

	return Issued{}, fmt.Errorf("create unique session: %w", ErrConflict)
}

// Resolve validates a raw credential and resolves active server-side state.
// Cache failure or invalid cached state falls back to the durable authority.
func (manager *Manager) Resolve(ctx context.Context, rawToken string) (Record, error) {
	tokenHash, err := HashToken(rawToken)
	if err != nil {
		return Record{}, err
	}

	now := manager.now().UTC()
	if manager.cache != nil {
		cached, cacheErr := manager.cache.Get(ctx, tokenHash)
		if cacheErr == nil && validRecord(cached) == nil && cached.TokenHash == tokenHash {
			if cached.ActiveAt(now) {
				return manager.extendIfDue(ctx, cached, now)
			}
			_ = manager.cache.Delete(ctx, tokenHash)
		}
	}

	record, err := manager.store.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		return Record{}, fmt.Errorf("find durable session: %w", err)
	}
	if err := validRecord(record); err != nil || record.TokenHash != tokenHash {
		return Record{}, ErrInvalidRecord
	}
	if !record.ActiveAt(now) {
		if manager.cache != nil {
			_ = manager.cache.Delete(ctx, tokenHash)
		}
		return Record{}, ErrInactive
	}

	record, err = manager.extendIfDue(ctx, record, now)
	if err != nil {
		return Record{}, err
	}
	manager.populateCache(ctx, record)
	return record, nil
}

// Rotate atomically replaces an active durable credential. A returned Issued
// value remains usable when the accompanying error is ErrCacheSync; that error
// means the durable rotation succeeded but old cache state needs retryable
// invalidation.
func (manager *Manager) Rotate(ctx context.Context, rawToken string) (Issued, error) {
	current, err := HashToken(rawToken)
	if err != nil {
		return Issued{}, err
	}

	record, err := manager.store.FindByTokenHash(ctx, current)
	if err != nil {
		return Issued{}, fmt.Errorf("find session to rotate: %w", err)
	}
	if err := validRecord(record); err != nil || record.TokenHash != current {
		return Issued{}, ErrInvalidRecord
	}
	now := manager.now().UTC()
	if !record.ActiveAt(now) {
		return Issued{}, ErrInactive
	}

	for range creationAttempts {
		replacement, err := manager.newIssued(record.SubjectID)
		if err != nil {
			return Issued{}, err
		}
		if err := manager.store.Rotate(ctx, current, replacement.Record, now); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Issued{}, fmt.Errorf("rotate durable session: %w", err)
		}

		manager.populateCache(ctx, replacement.Record)
		if err := manager.deleteCached(ctx, current); err != nil {
			return replacement, err
		}
		return replacement, nil
	}

	return Issued{}, fmt.Errorf("create unique replacement session: %w", ErrConflict)
}

// Revoke durably invalidates a credential, then removes its cached state.
func (manager *Manager) Revoke(ctx context.Context, rawToken string) error {
	tokenHash, err := HashToken(rawToken)
	if err != nil {
		return err
	}
	if err := manager.store.Revoke(ctx, tokenHash, manager.now().UTC()); err != nil {
		return fmt.Errorf("revoke durable session: %w", err)
	}
	return manager.deleteCached(ctx, tokenHash)
}

// List returns the durable sessions for a subject. Inactive sessions are
// included so callers can show session history and decide what to remove.
func (manager *Manager) List(ctx context.Context, subjectID string) ([]Record, error) {
	if strings.TrimSpace(subjectID) == "" {
		return nil, fmt.Errorf("%w: subject ID is required", ErrInvalidRecord)
	}
	records, err := manager.store.ListBySubject(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("list durable sessions: %w", err)
	}
	for _, record := range records {
		if err := validRecord(record); err != nil || record.SubjectID != subjectID {
			return nil, ErrInvalidRecord
		}
	}
	return records, nil
}

// RevokeAll durably invalidates every session for a subject, then removes
// cached state for the affected sessions. Durable success is retained when
// cache invalidation fails and ErrCacheSync is returned for retry handling.
func (manager *Manager) RevokeAll(ctx context.Context, subjectID string) error {
	if strings.TrimSpace(subjectID) == "" {
		return fmt.Errorf("%w: subject ID is required", ErrInvalidRecord)
	}
	records, err := manager.store.RevokeAll(ctx, subjectID, manager.now().UTC())
	if err != nil {
		return fmt.Errorf("revoke durable sessions: %w", err)
	}
	var cacheErr error
	for _, record := range records {
		if err := validRecord(record); err != nil || record.SubjectID != subjectID {
			return ErrInvalidRecord
		}
		if err := manager.deleteCached(ctx, record.TokenHash); err != nil {
			if cacheErr == nil {
				cacheErr = err
			}
		}
	}
	return cacheErr
}

// HashToken validates and hashes a raw token for server-side lookup.
func HashToken(rawToken string) (TokenHash, error) {
	return token.HashToken(rawToken)
}

func (manager *Manager) newIssued(subjectID string) (Issued, error) {
	rawToken, tokenHash, err := token.Generate()
	if err != nil {
		return Issued{}, fmt.Errorf("generate session token: %w", err)
	}
	now := manager.now().UTC()

	return Issued{
		Token: rawToken,
		Record: Record{
			SubjectID: subjectID,
			TokenHash: tokenHash,
			CreatedAt: now,
			ExpiresAt: now.Add(manager.lifetime),
		},
	}, nil
}

func validRecord(record Record) error {
	if strings.TrimSpace(record.SubjectID) == "" || record.TokenHash == (TokenHash{}) ||
		record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) {
		return ErrInvalidRecord
	}
	if record.RevokedAt != nil && record.RevokedAt.Before(record.CreatedAt) {
		return ErrInvalidRecord
	}
	if record.ExtendedAt != nil && (record.ExtendedAt.Before(record.CreatedAt) ||
		record.ExtendedAt.After(record.ExpiresAt)) {
		return ErrInvalidRecord
	}
	return nil
}

func (manager *Manager) extendIfDue(ctx context.Context, record Record, now time.Time) (Record, error) {
	if manager.extension == nil {
		return record, nil
	}
	lastExtendedAt := record.CreatedAt
	if record.ExtendedAt != nil {
		lastExtendedAt = *record.ExtendedAt
	}
	if now.Before(lastExtendedAt.Add(manager.extension.After)) {
		return record, nil
	}

	expiresAt := now.Add(manager.lifetime)
	absoluteExpiry := record.CreatedAt.Add(manager.extension.AbsoluteLifetime)
	if expiresAt.After(absoluteExpiry) {
		expiresAt = absoluteExpiry
	}
	if !expiresAt.After(record.ExpiresAt) {
		return record, nil
	}
	extended, err := manager.store.Extend(ctx, record.TokenHash, now, expiresAt)
	if err != nil {
		if errors.Is(err, ErrInactive) || errors.Is(err, ErrNotFound) {
			_ = manager.deleteCached(ctx, record.TokenHash)
			return Record{}, err
		}
		return record, nil
	}
	if validRecord(extended) != nil || extended.TokenHash != record.TokenHash || !extended.ActiveAt(now) {
		return Record{}, ErrInvalidRecord
	}
	manager.populateCache(ctx, extended)
	return extended, nil
}

func (manager *Manager) populateCache(ctx context.Context, record Record) {
	if manager.cache == nil {
		return
	}
	remaining := record.ExpiresAt.Sub(manager.now().UTC())
	if remaining <= 0 {
		return
	}
	ttl := min(manager.cacheTTL, remaining)
	_ = manager.cache.Set(ctx, record, ttl)
}

func (manager *Manager) deleteCached(ctx context.Context, tokenHash TokenHash) error {
	if manager.cache == nil {
		return nil
	}
	if err := manager.cache.Delete(ctx, tokenHash); err != nil {
		return fmt.Errorf("%w: %w", ErrCacheSync, err)
	}
	return nil
}
