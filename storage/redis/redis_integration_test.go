package redis_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/sessiontoken"
	authlierredis "github.com/Rahmannugar/authlier/storage/redis"
	redislibrary "github.com/redis/go-redis/v9"
)

func TestSessionCache(t *testing.T) {
	address := os.Getenv("AUTHLIER_REDIS_TEST_ADDRESS")
	if address == "" {
		t.Skip("AUTHLIER_REDIS_TEST_ADDRESS is not set")
	}
	ctx := context.Background()
	client := redislibrary.NewClient(&redislibrary.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush Redis: %v", err)
	}
	cache, err := authlierredis.NewSessionCache(client, "authlier-test")
	if err != nil {
		t.Fatalf("create cache: %v", err)
	}
	var tokenHash sessiontoken.TokenHash
	tokenHash[0] = 1
	now := time.Now().UTC()
	record := sessiontoken.Record{
		SubjectID: "user",
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := cache.Set(ctx, record, time.Minute); err != nil {
		t.Fatalf("set session: %v", err)
	}
	found, err := cache.Get(ctx, tokenHash)
	if err != nil || found.SubjectID != record.SubjectID || found.TokenHash != tokenHash {
		t.Fatalf("get session: record=%+v error=%v", found, err)
	}
	if err := cache.Delete(ctx, tokenHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if _, err := cache.Get(ctx, tokenHash); !errors.Is(err, sessiontoken.ErrCacheMiss) {
		t.Fatalf("cache miss: got %v", err)
	}
}
