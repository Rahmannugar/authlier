// Package refreshtoken manages opaque tokens that renew JWT access tokens.
package refreshtoken

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
	ErrConflict      = errors.New("refresh token conflict")
	ErrInactive      = errors.New("refresh token is inactive")
	ErrInvalidConfig = errors.New("invalid refresh token configuration")
	ErrInvalidRecord = errors.New("invalid refresh token record")
	ErrInvalidToken  = token.ErrInvalidToken
	ErrNotFound      = errors.New("refresh token not found")
	ErrReuseDetected = errors.New("refresh token reuse detected")
)

type TokenHash = token.Hash

// Record is the durable state of one refresh token.
type Record struct {
	SessionID string
	TokenHash TokenHash
	CreatedAt time.Time
	ExpiresAt time.Time
	RotatedAt *time.Time
	RevokedAt *time.Time
}

func (record Record) ActiveAt(at time.Time) bool {
	return record.RotatedAt == nil && record.RevokedAt == nil && at.Before(record.ExpiresAt)
}

type Issued struct {
	Token  string
	Record Record
}

// Store is the durable authority for refresh tokens.
//
// Rotate atomically consumes current and creates replacement. Reuse invalidates
// the durable session and all its refresh tokens before returning
// ErrReuseDetected. RevokeSession performs the same invalidation explicitly.
type Store interface {
	Create(ctx context.Context, record Record) error
	FindByTokenHash(ctx context.Context, tokenHash TokenHash) (Record, error)
	Rotate(ctx context.Context, current TokenHash, replacement Record, rotatedAt time.Time) error
	RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error
}

type Config struct {
	Lifetime time.Duration
	Now      func() time.Time
}

type Manager struct {
	store    Store
	lifetime time.Duration
	now      func() time.Time
}

func NewManager(store Store, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if config.Lifetime <= 0 {
		return nil, fmt.Errorf("%w: lifetime must be positive", ErrInvalidConfig)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{store: store, lifetime: config.Lifetime, now: now}, nil
}

// Create issues the first refresh token for a durable session.
func (manager *Manager) Create(ctx context.Context, sessionID string) (Issued, error) {
	if strings.TrimSpace(sessionID) == "" {
		return Issued{}, fmt.Errorf("%w: session ID is required", ErrInvalidRecord)
	}
	return manager.create(ctx, sessionID)
}

// Rotate consumes a token once and returns its replacement.
func (manager *Manager) Rotate(ctx context.Context, rawToken string) (Issued, error) {
	currentHash, err := token.HashToken(rawToken)
	if err != nil {
		return Issued{}, err
	}
	current, err := manager.store.FindByTokenHash(ctx, currentHash)
	if err != nil {
		return Issued{}, fmt.Errorf("find refresh token: %w", err)
	}
	if err := validRecord(current); err != nil || current.TokenHash != currentHash {
		return Issued{}, ErrInvalidRecord
	}

	for range creationAttempts {
		replacement, err := manager.newIssued(current.SessionID, current.ExpiresAt)
		if err != nil {
			return Issued{}, err
		}
		if err := manager.store.Rotate(ctx, currentHash, replacement.Record, manager.now().UTC()); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Issued{}, fmt.Errorf("rotate refresh token: %w", err)
		}
		return replacement, nil
	}
	return Issued{}, fmt.Errorf("create unique refresh token: %w", ErrConflict)
}

// RevokeSession revokes the session associated with rawToken.
func (manager *Manager) RevokeSession(ctx context.Context, rawToken string) error {
	tokenHash, err := token.HashToken(rawToken)
	if err != nil {
		return err
	}
	record, err := manager.store.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("find refresh token session: %w", err)
	}
	if err := validRecord(record); err != nil || record.TokenHash != tokenHash {
		return ErrInvalidRecord
	}
	if err := manager.store.RevokeSession(ctx, record.SessionID, manager.now().UTC()); err != nil {
		return fmt.Errorf("revoke session refresh tokens: %w", err)
	}
	return nil
}

func (manager *Manager) create(
	ctx context.Context,
	sessionID string,
) (Issued, error) {
	for range creationAttempts {
		issued, err := manager.newIssued(sessionID, time.Time{})
		if err != nil {
			return Issued{}, err
		}
		if err := manager.store.Create(ctx, issued.Record); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Issued{}, fmt.Errorf("create durable refresh token: %w", err)
		}
		return issued, nil
	}
	return Issued{}, fmt.Errorf("create unique refresh token: %w", ErrConflict)
}

func (manager *Manager) newIssued(sessionID string, expiresAt time.Time) (Issued, error) {
	rawToken, tokenHash, err := token.Generate()
	if err != nil {
		return Issued{}, fmt.Errorf("generate refresh token: %w", err)
	}
	now := manager.now().UTC()
	if expiresAt.IsZero() {
		expiresAt = now.Add(manager.lifetime)
	}
	return Issued{
		Token: rawToken,
		Record: Record{
			SessionID: sessionID,
			TokenHash: tokenHash,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		},
	}, nil
}

func validRecord(record Record) error {
	if strings.TrimSpace(record.SessionID) == "" || record.TokenHash == (TokenHash{}) ||
		record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) {
		return ErrInvalidRecord
	}
	if record.RotatedAt != nil && record.RotatedAt.Before(record.CreatedAt) {
		return ErrInvalidRecord
	}
	if record.RevokedAt != nil && record.RevokedAt.Before(record.CreatedAt) {
		return ErrInvalidRecord
	}
	return nil
}
