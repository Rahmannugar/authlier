package refreshtoken_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/refreshtoken"
)

func TestRefreshTokenRotationIsSingleUseAndPreservesExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	manager, err := refreshtoken.NewManager(store, refreshtoken.Config{
		Lifetime: 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	initial, err := manager.Create(ctx, "session_123")
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	now = now.Add(time.Hour)
	replacement, err := manager.Rotate(ctx, initial.Token)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if replacement.Token == initial.Token {
		t.Fatal("rotation reused the current token")
	}
	if !replacement.Record.ExpiresAt.Equal(initial.Record.ExpiresAt) {
		t.Fatal("rotation extended the absolute refresh-token expiry")
	}

	if _, err := manager.Rotate(ctx, initial.Token); !errors.Is(err, refreshtoken.ErrReuseDetected) {
		t.Fatalf("reuse consumed token: got %v, want reuse detected", err)
	}
	if store.records[replacement.Record.TokenHash].RevokedAt == nil {
		t.Fatal("reuse did not revoke the session's replacement token")
	}
	if !store.sessionsRevoked[initial.Record.SessionID] {
		t.Fatal("reuse did not revoke the durable session")
	}
}

func TestRefreshTokenCannotRotateAtExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	manager, err := refreshtoken.NewManager(store, refreshtoken.Config{
		Lifetime: time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	issued, err := manager.Create(ctx, "session_123")
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	now = issued.Record.ExpiresAt
	if _, err := manager.Rotate(ctx, issued.Token); !errors.Is(err, refreshtoken.ErrInactive) {
		t.Fatalf("rotate expired token: got %v, want inactive", err)
	}
}

func TestConcurrentRefreshTokenReuseRevokesTheSession(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	manager, err := refreshtoken.NewManager(store, refreshtoken.Config{
		Lifetime: time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	issued, err := manager.Create(ctx, "session_123")
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	errorsFound := make(chan error, 2)
	for range 2 {
		go func() {
			_, rotateErr := manager.Rotate(ctx, issued.Token)
			errorsFound <- rotateErr
		}()
	}
	var successes, reuses int
	for range 2 {
		err := <-errorsFound
		switch {
		case err == nil:
			successes++
		case errors.Is(err, refreshtoken.ErrReuseDetected):
			reuses++
		default:
			t.Fatalf("unexpected rotation result: %v", err)
		}
	}
	if successes != 1 || reuses != 1 {
		t.Fatalf("rotation outcomes: successes=%d reuses=%d", successes, reuses)
	}
	for _, record := range store.snapshot() {
		if record.RevokedAt == nil {
			t.Fatal("concurrent reuse left a session refresh token active")
		}
	}
}

type memoryStore struct {
	mu              sync.Mutex
	records         map[refreshtoken.TokenHash]refreshtoken.Record
	sessionsRevoked map[string]bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		records:         make(map[refreshtoken.TokenHash]refreshtoken.Record),
		sessionsRevoked: make(map[string]bool),
	}
}

func (store *memoryStore) Create(_ context.Context, record refreshtoken.Record) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.records[record.TokenHash]; exists {
		return refreshtoken.ErrConflict
	}
	store.records[record.TokenHash] = record
	return nil
}

func (store *memoryStore) FindByTokenHash(
	_ context.Context,
	tokenHash refreshtoken.TokenHash,
) (refreshtoken.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[tokenHash]
	if !exists {
		return refreshtoken.Record{}, refreshtoken.ErrNotFound
	}
	return record, nil
}

func (store *memoryStore) Rotate(
	_ context.Context,
	currentHash refreshtoken.TokenHash,
	replacement refreshtoken.Record,
	rotatedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.records[currentHash]
	if !exists {
		return refreshtoken.ErrNotFound
	}
	if current.RotatedAt != nil {
		store.revokeSession(current.SessionID, rotatedAt)
		return refreshtoken.ErrReuseDetected
	}
	if !current.ActiveAt(rotatedAt) {
		return refreshtoken.ErrInactive
	}
	if _, exists := store.records[replacement.TokenHash]; exists {
		return refreshtoken.ErrConflict
	}
	current.RotatedAt = &rotatedAt
	store.records[currentHash] = current
	store.records[replacement.TokenHash] = replacement
	return nil
}

func (store *memoryStore) RevokeSession(_ context.Context, sessionID string, revokedAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revokeSession(sessionID, revokedAt)
	return nil
}

func (store *memoryStore) revokeSession(sessionID string, revokedAt time.Time) {
	store.sessionsRevoked[sessionID] = true
	for tokenHash, record := range store.records {
		if record.SessionID == sessionID && record.RevokedAt == nil {
			record.RevokedAt = &revokedAt
			store.records[tokenHash] = record
		}
	}
}

func (store *memoryStore) snapshot() []refreshtoken.Record {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]refreshtoken.Record, 0, len(store.records))
	for _, record := range store.records {
		records = append(records, record)
	}
	return records
}
