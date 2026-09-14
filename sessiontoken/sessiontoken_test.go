package sessiontoken_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/sessiontoken"
)

const subjectID = "user_123"

func TestSessionLifecycleRotatesExpiresAndRevokesCredentials(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	cache := newMemoryCache()
	manager := newManager(t, store, cache, &now)

	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if issued.Token == "" || issued.Record.ID == "" ||
		issued.Record.TokenHash == (sessiontoken.TokenHash{}) {
		t.Fatal("created session did not contain an opaque credential and hash")
	}
	if stored := store.records[issued.Record.TokenHash]; stored.TokenHash == (sessiontoken.TokenHash{}) {
		t.Fatal("durable store did not receive the token hash")
	}

	resolved, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	if resolved.SubjectID != subjectID {
		t.Fatalf("resolved subject = %q, want %q", resolved.SubjectID, subjectID)
	}

	replacement, err := manager.Rotate(ctx, issued.Token)
	if err != nil {
		t.Fatalf("rotate session: %v", err)
	}
	if replacement.Token == issued.Token {
		t.Fatal("rotation reused the current credential")
	}
	if _, err := manager.Resolve(ctx, issued.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("old credential after rotation: got %v, want inactive", err)
	}
	if _, err := manager.Resolve(ctx, replacement.Token); err != nil {
		t.Fatalf("resolve replacement: %v", err)
	}

	if err := manager.Revoke(ctx, replacement.Token); err != nil {
		t.Fatalf("revoke replacement: %v", err)
	}
	if err := manager.Revoke(ctx, replacement.Token); err != nil {
		t.Fatalf("repeat revocation: %v", err)
	}
	if _, err := manager.Resolve(ctx, replacement.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("revoked credential: got %v, want inactive", err)
	}

	other, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session for expiry check: %v", err)
	}
	now = other.Record.ExpiresAt
	if _, err := manager.Resolve(ctx, other.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("credential at expiry boundary: got %v, want inactive", err)
	}
}

func TestListAndRevokeAllSessionsBySubject(t *testing.T) {
	store := newMemoryStore()
	cache := newMemoryCache()
	manager := newManager(t, store, cache, nil)
	ctx := context.Background()

	first, err := manager.Create(ctx, "user_123")
	if err != nil {
		t.Fatalf("create first session: %v", err)
	}
	second, err := manager.Create(ctx, "user_123")
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	if _, err := manager.Create(ctx, "user_other"); err != nil {
		t.Fatalf("create other session: %v", err)
	}

	records, err := manager.List(ctx, "user_123")
	if err != nil || len(records) != 2 {
		t.Fatalf("list sessions: records=%d err=%v", len(records), err)
	}
	if err := manager.RevokeAll(ctx, "user_123"); err != nil {
		t.Fatalf("revoke all sessions: %v", err)
	}
	if _, err := manager.Resolve(ctx, first.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("first session remained active: %v", err)
	}
	if _, err := manager.Resolve(ctx, second.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("second session remained active: %v", err)
	}
	if len(cache.records) != 1 {
		t.Fatal("revoke all removed an unrelated cached session or left revoked sessions")
	}
	if err := manager.RevokeAll(ctx, "user_123"); err != nil {
		t.Fatalf("revoke all should be idempotent: %v", err)
	}
}

func TestRevokeByIDCannotRevokeAnotherSubjectsSession(t *testing.T) {
	store := newMemoryStore()
	manager := newManager(t, store, nil, nil)
	ctx := context.Background()
	owned, err := manager.Create(ctx, "user_123")
	if err != nil {
		t.Fatalf("create owned session: %v", err)
	}
	other, err := manager.Create(ctx, "user_other")
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}
	if err := manager.RevokeByID(ctx, "user_123", other.Record.ID); !errors.Is(err, sessiontoken.ErrNotFound) {
		t.Fatalf("revoke another subject's session: %v", err)
	}
	if err := manager.RevokeByID(ctx, "user_123", owned.Record.ID); err != nil {
		t.Fatalf("revoke owned session: %v", err)
	}
	if _, err := manager.Resolve(ctx, owned.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("resolve revoked session: %v", err)
	}
}

func TestListAndRevokeAllRequireSubject(t *testing.T) {
	manager := newManager(t, newMemoryStore(), nil, nil)
	if _, err := manager.List(context.Background(), " "); !errors.Is(err, sessiontoken.ErrInvalidRecord) {
		t.Fatalf("list blank subject: %v", err)
	}
	if err := manager.RevokeAll(context.Background(), " "); !errors.Is(err, sessiontoken.ErrInvalidRecord) {
		t.Fatalf("revoke blank subject: %v", err)
	}
}

func TestRevokeAllReportsCacheSynchronizationFailureAfterDurableSuccess(t *testing.T) {
	store := newMemoryStore()
	cache := newMemoryCache()
	manager := newManager(t, store, cache, nil)
	issued, err := manager.Create(context.Background(), "user_123")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	cache.deleteErr = errors.New("cache unavailable")
	if err := manager.RevokeAll(context.Background(), "user_123"); !errors.Is(err, sessiontoken.ErrCacheSync) {
		t.Fatalf("revoke all cache failure: %v", err)
	}
	if store.records[issued.Record.TokenHash].RevokedAt == nil {
		t.Fatal("durable session was not revoked")
	}
}

func TestResolveFallsBackToDurableStoreWhenCacheIsUnavailable(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	cache := newMemoryCache()
	cache.setErr = errors.New("cache unavailable")
	manager := newManager(t, store, cache, &now)

	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("durable creation should survive cache failure: %v", err)
	}
	cache.getErr = errors.New("cache unavailable")
	cache.setErr = nil

	resolved, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("resolve through durable fallback: %v", err)
	}
	if resolved.TokenHash != issued.Record.TokenHash {
		t.Fatal("durable fallback returned the wrong session")
	}
	if store.findCalls != 1 {
		t.Fatalf("durable lookup calls = %d, want 1", store.findCalls)
	}
	if cache.setCalls != 2 {
		t.Fatalf("cache population attempts = %d, want 2", cache.setCalls)
	}
}

func TestResolveRejectsInvalidCachedStateAndUsesDurableAuthority(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	cache := newMemoryCache()
	manager := newManager(t, store, cache, &now)
	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	poisoned := issued.Record
	poisoned.SubjectID = ""
	cache.records[issued.Record.TokenHash] = poisoned

	resolved, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("resolve after invalid cache entry: %v", err)
	}
	if resolved.SubjectID != subjectID {
		t.Fatalf("resolved subject = %q, want durable subject %q", resolved.SubjectID, subjectID)
	}
	if store.findCalls != 1 {
		t.Fatalf("durable lookup calls = %d, want 1", store.findCalls)
	}
}

func TestInactiveCacheEntryFallsBackToDurableState(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	now := start
	store := newMemoryStore()
	cache := newMemoryCache()
	manager := newManager(t, store, cache, &now)
	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	extendedAt := start.Add(time.Hour)
	durable := store.records[issued.Record.TokenHash]
	durable.ExtendedAt = &extendedAt
	durable.ExpiresAt = start.Add(48 * time.Hour)
	store.records[issued.Record.TokenHash] = durable
	now = issued.Record.ExpiresAt

	resolved, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("resolve with stale cache expiry: %v", err)
	}
	if !resolved.ExpiresAt.Equal(durable.ExpiresAt) {
		t.Fatalf("resolved expiry = %v, want %v", resolved.ExpiresAt, durable.ExpiresAt)
	}
}

func TestRevocationAndRotationSurfaceCacheInvalidationFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	cache := newMemoryCache()
	manager := newManager(t, store, cache, &now)
	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	cache.deleteErr = errors.New("cache unavailable")

	replacement, err := manager.Rotate(ctx, issued.Token)
	if !errors.Is(err, sessiontoken.ErrCacheSync) {
		t.Fatalf("rotate error = %v, want cache synchronization failure", err)
	}
	if replacement.Token == "" {
		t.Fatal("durably committed replacement was not returned with cache error")
	}
	if store.records[issued.Record.TokenHash].RevokedAt == nil {
		t.Fatal("current durable session remained active after rotation")
	}

	if err := manager.Revoke(ctx, replacement.Token); !errors.Is(err, sessiontoken.ErrCacheSync) {
		t.Fatalf("revoke error = %v, want cache synchronization failure", err)
	}
	if store.records[replacement.Record.TokenHash].RevokedAt == nil {
		t.Fatal("durable session remained active after cache invalidation failure")
	}
}

func TestSessionExtensionIsOptInAndBounded(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	now := start
	store := newMemoryStore()
	manager, err := sessiontoken.NewManager(store, nil, sessiontoken.Config{
		Lifetime: 24 * time.Hour,
		Extension: &sessiontoken.ExtensionConfig{
			After:            time.Hour,
			AbsoluteLifetime: 72 * time.Hour,
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	now = start.Add(30 * time.Minute)
	beforeThreshold, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("resolve before extension threshold: %v", err)
	}
	if beforeThreshold.ExtendedAt != nil || store.extendCalls != 0 {
		t.Fatal("session extended before the configured threshold")
	}

	now = start.Add(2 * time.Hour)
	extended, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("resolve after extension threshold: %v", err)
	}
	if extended.ExtendedAt == nil || !extended.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("unexpected extension: extended=%v expires=%v", extended.ExtendedAt, extended.ExpiresAt)
	}

	now = start.Add(25 * time.Hour)
	if _, err := manager.Resolve(ctx, issued.Token); err != nil {
		t.Fatalf("extend session a second time: %v", err)
	}
	now = start.Add(48 * time.Hour)
	bounded, err := manager.Resolve(ctx, issued.Token)
	if err != nil {
		t.Fatalf("extend session to absolute boundary: %v", err)
	}
	if !bounded.ExpiresAt.Equal(start.Add(72 * time.Hour)) {
		t.Fatalf("bounded expiry = %v, want %v", bounded.ExpiresAt, start.Add(72*time.Hour))
	}
	now = start.Add(72 * time.Hour)
	if _, err := manager.Resolve(ctx, issued.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("resolve at absolute boundary: got %v, want inactive", err)
	}
}

func TestConcurrentSessionRotationInvalidatesTheOriginalToken(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	manager := newManager(t, store, nil, &now)
	issued, err := manager.Create(ctx, subjectID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	errorsFound := make(chan error, 2)
	for range 2 {
		go func() {
			_, rotateErr := manager.Rotate(ctx, issued.Token)
			errorsFound <- rotateErr
		}()
	}
	var successes, inactive int
	for range 2 {
		err := <-errorsFound
		switch {
		case err == nil:
			successes++
		case errors.Is(err, sessiontoken.ErrInactive):
			inactive++
		default:
			t.Fatalf("unexpected rotation result: %v", err)
		}
	}
	if successes != 1 || inactive != 1 {
		t.Fatalf("rotation outcomes: successes=%d inactive=%d", successes, inactive)
	}
	if _, err := manager.Resolve(ctx, issued.Token); !errors.Is(err, sessiontoken.ErrInactive) {
		t.Fatalf("resolve rotated token: got %v, want inactive", err)
	}
}

func TestCacheTTLNeverExceedsSessionExpiry(t *testing.T) {
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	cache := newMemoryCache()
	manager, err := sessiontoken.NewManager(store, cache, sessiontoken.Config{
		Lifetime: time.Minute,
		CacheTTL: time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	if _, err := manager.Create(context.Background(), subjectID); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if cache.lastTTL != time.Minute {
		t.Fatalf("cache TTL = %v, want %v", cache.lastTTL, time.Minute)
	}
}

func newManager(t *testing.T, store sessiontoken.Store, cache sessiontoken.Cache, now *time.Time) *sessiontoken.Manager {
	t.Helper()
	nowFunc := time.Now
	if now != nil {
		nowFunc = func() time.Time { return *now }
	}
	manager, err := sessiontoken.NewManager(store, cache, sessiontoken.Config{
		Lifetime: 24 * time.Hour,
		CacheTTL: 5 * time.Minute,
		Now:      nowFunc,
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return manager
}

type memoryStore struct {
	mu          sync.Mutex
	records     map[sessiontoken.TokenHash]sessiontoken.Record
	findCalls   int
	extendCalls int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		records: make(map[sessiontoken.TokenHash]sessiontoken.Record),
	}
}

func (store *memoryStore) Create(_ context.Context, record sessiontoken.Record) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.records[record.TokenHash]; exists {
		return sessiontoken.ErrConflict
	}
	store.records[record.TokenHash] = record
	return nil
}

func (store *memoryStore) FindByTokenHash(_ context.Context, tokenHash sessiontoken.TokenHash) (sessiontoken.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.findCalls++
	record, exists := store.records[tokenHash]
	if !exists {
		return sessiontoken.Record{}, sessiontoken.ErrNotFound
	}
	return record, nil
}

func (store *memoryStore) ListBySubject(_ context.Context, subjectID string) ([]sessiontoken.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var records []sessiontoken.Record
	for _, record := range store.records {
		if record.SubjectID == subjectID {
			records = append(records, record)
		}
	}
	return records, nil
}

func (store *memoryStore) Extend(
	_ context.Context,
	tokenHash sessiontoken.TokenHash,
	extendedAt time.Time,
	expiresAt time.Time,
) (sessiontoken.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.extendCalls++
	record, exists := store.records[tokenHash]
	if !exists {
		return sessiontoken.Record{}, sessiontoken.ErrNotFound
	}
	if !record.ActiveAt(extendedAt) {
		return sessiontoken.Record{}, sessiontoken.ErrInactive
	}
	if expiresAt.After(record.ExpiresAt) {
		record.ExtendedAt = &extendedAt
		record.ExpiresAt = expiresAt
		store.records[tokenHash] = record
	}
	return record, nil
}

func (store *memoryStore) Rotate(
	_ context.Context,
	current sessiontoken.TokenHash,
	replacement sessiontoken.Record,
	rotatedAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[current]
	if !exists {
		return sessiontoken.ErrNotFound
	}
	if !record.ActiveAt(rotatedAt) {
		return sessiontoken.ErrInactive
	}
	if _, exists := store.records[replacement.TokenHash]; exists {
		return sessiontoken.ErrConflict
	}
	record.RevokedAt = &rotatedAt
	store.records[current] = record
	store.records[replacement.TokenHash] = replacement
	return nil
}

func (store *memoryStore) Revoke(_ context.Context, tokenHash sessiontoken.TokenHash, revokedAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[tokenHash]
	if !exists {
		return sessiontoken.ErrNotFound
	}
	if record.RevokedAt == nil {
		record.RevokedAt = &revokedAt
		store.records[tokenHash] = record
	}
	return nil
}

func (store *memoryStore) RevokeAll(_ context.Context, subjectID string, revokedAt time.Time) ([]sessiontoken.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var affected []sessiontoken.Record
	for hash, record := range store.records {
		if record.SubjectID != subjectID {
			continue
		}
		if record.RevokedAt == nil {
			record.RevokedAt = &revokedAt
			store.records[hash] = record
		}
		affected = append(affected, record)
	}
	return affected, nil
}

type memoryCache struct {
	records   map[sessiontoken.TokenHash]sessiontoken.Record
	getErr    error
	setErr    error
	deleteErr error
	setCalls  int
	lastTTL   time.Duration
}

func newMemoryCache() *memoryCache {
	return &memoryCache{records: make(map[sessiontoken.TokenHash]sessiontoken.Record)}
}

func (cache *memoryCache) Get(_ context.Context, tokenHash sessiontoken.TokenHash) (sessiontoken.Record, error) {
	if cache.getErr != nil {
		return sessiontoken.Record{}, cache.getErr
	}
	record, exists := cache.records[tokenHash]
	if !exists {
		return sessiontoken.Record{}, sessiontoken.ErrCacheMiss
	}
	return record, nil
}

func (cache *memoryCache) Set(_ context.Context, record sessiontoken.Record, ttl time.Duration) error {
	cache.setCalls++
	cache.lastTTL = ttl
	if cache.setErr != nil {
		return cache.setErr
	}
	cache.records[record.TokenHash] = record
	return nil
}

func (cache *memoryCache) Delete(_ context.Context, tokenHash sessiontoken.TokenHash) error {
	if cache.deleteErr != nil {
		return cache.deleteErr
	}
	delete(cache.records, tokenHash)
	return nil
}
