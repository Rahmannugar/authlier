// Package redis provides optional Authlier caching backed by Redis.
package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/sessiontoken"
	redislibrary "github.com/redis/go-redis/v9"
)

var ErrInvalidConfig = errors.New("invalid Redis adapter configuration")

type SessionCache struct {
	client redislibrary.UniversalClient
	prefix string
}

func NewSessionCache(
	client redislibrary.UniversalClient,
	keyPrefix string,
) (*SessionCache, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: client is required", ErrInvalidConfig)
	}
	keyPrefix = strings.TrimSpace(keyPrefix)
	if keyPrefix == "" {
		keyPrefix = "authlier"
	}
	return &SessionCache{client: client, prefix: keyPrefix + ":session:"}, nil
}

func (cache *SessionCache) Get(
	ctx context.Context,
	tokenHash sessiontoken.TokenHash,
) (sessiontoken.Record, error) {
	encoded, err := cache.client.Get(ctx, cache.key(tokenHash)).Bytes()
	if errors.Is(err, redislibrary.Nil) {
		return sessiontoken.Record{}, sessiontoken.ErrCacheMiss
	}
	if err != nil {
		return sessiontoken.Record{}, err
	}
	var record sessiontoken.Record
	if err := json.Unmarshal(encoded, &record); err != nil {
		return sessiontoken.Record{}, err
	}
	return record, nil
}

func (cache *SessionCache) Set(
	ctx context.Context,
	record sessiontoken.Record,
	ttl time.Duration,
) error {
	if ttl <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrInvalidConfig)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return cache.client.Set(ctx, cache.key(record.TokenHash), encoded, ttl).Err()
}

func (cache *SessionCache) Delete(
	ctx context.Context,
	tokenHash sessiontoken.TokenHash,
) error {
	return cache.client.Del(ctx, cache.key(tokenHash)).Err()
}

func (cache *SessionCache) key(tokenHash sessiontoken.TokenHash) string {
	return cache.prefix + hex.EncodeToString(tokenHash[:])
}

var _ sessiontoken.Cache = (*SessionCache)(nil)
