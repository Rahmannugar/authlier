// Package redis provides Authlier storage and optional session caching backed by Redis.
package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/sessiontoken"
	redislibrary "github.com/redis/go-redis/v9"
)

var ErrInvalidConfig = errors.New("invalid Redis adapter configuration")

var ErrTransactionConflict = errors.New("Redis transaction could not be completed")

type SecretCodec interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type Config struct {
	KeyPrefix string
	Secrets   SecretCodec
}

type Adapter struct {
	client  redislibrary.UniversalClient
	prefix  string
	secrets SecretCodec
}

func New(client redislibrary.UniversalClient, config Config) (*Adapter, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: client is required", ErrInvalidConfig)
	}
	prefix := strings.TrimSpace(config.KeyPrefix)
	if prefix == "" {
		prefix = "authlier"
	}
	return &Adapter{client: client, prefix: "{" + prefix + "}:", secrets: config.Secrets}, nil
}

func (adapter *Adapter) Migrate(ctx context.Context) error {
	return adapter.client.Ping(ctx).Err()
}

func (adapter *Adapter) Stores() authlier.Stores {
	return authlier.Stores{
		EmailPassword:     adapter.EmailPassword(),
		EmailVerification: adapter.EmailVerification(),
		Google:            adapter.Google(),
		OIDC:              adapter.OIDC(),
		Passkeys:          adapter.Passkeys(),
		PasswordReset:     adapter.PasswordReset(),
		RefreshTokens:     adapter.RefreshTokens(),
		SAML:              adapter.SAML(),
		Sessions:          adapter.Sessions(),
		TOTP:              adapter.TOTP(),
		AccessSessions:    adapter.AccessSessions(),
	}
}

func (adapter *Adapter) key(name string) string { return adapter.prefix + name }

func hashKey(value []byte) string { return hex.EncodeToString(value) }

func readJSON(ctx context.Context, client redislibrary.Cmdable, key, field string, destination any) error {
	encoded, err := client.HGet(ctx, key, field).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, destination)
}

func encodeJSON(value any) ([]byte, error) { return json.Marshal(value) }

func (adapter *Adapter) watch(ctx context.Context, keys []string, operation func(*redislibrary.Tx) error) error {
	for range 16 {
		err := adapter.client.Watch(ctx, operation, keys...)
		if errors.Is(err, redislibrary.TxFailedErr) {
			continue
		}
		return err
	}
	return ErrTransactionConflict
}

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
var _ authlier.Database = (*Adapter)(nil)
