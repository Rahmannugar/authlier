package redis

import (
	"context"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/saml"
	redislibrary "github.com/redis/go-redis/v9"
)

type OIDCStore struct{ adapter *Adapter }
type SAMLStore struct{ adapter *Adapter }

func (adapter *Adapter) OIDC() *OIDCStore { return &OIDCStore{adapter} }
func (adapter *Adapter) SAML() *SAMLStore { return &SAMLStore{adapter} }

func (store *OIDCStore) CreateChallenge(ctx context.Context, challenge oidc.Challenge) error {
	key, field := store.adapter.key("oidc-challenges"), hashKey(challenge.StateHash[:])
	encoded, _ := encodeJSON(challenge)
	created, err := store.adapter.client.HSetNX(ctx, key, field, encoded).Result()
	if err == nil && !created {
		return oidc.ErrConflict
	}
	return err
}

func (store *OIDCStore) ConsumeChallenge(ctx context.Context, stateHash oidc.StateHash, consumedAt time.Time) (oidc.Challenge, error) {
	key, field := store.adapter.key("oidc-challenges"), hashKey(stateHash[:])
	var result oidc.Challenge
	err := store.adapter.watch(ctx, []string{key}, func(tx *redislibrary.Tx) error {
		if err := readJSON(ctx, tx, key, field, &result); errors.Is(err, redislibrary.Nil) {
			return oidc.ErrNotFound
		} else if err != nil {
			return err
		}
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, key, field)
			return nil
		})
		if err == nil && !consumedAt.Before(result.ExpiresAt) {
			return oidc.ErrInactiveState
		}
		return err
	})
	return result, err
}

func (store *SAMLStore) CreateRequest(ctx context.Context, request saml.Request) error {
	key, field := store.adapter.key("saml-requests"), hashKey(request.StateHash[:])
	encoded, _ := encodeJSON(request)
	created, err := store.adapter.client.HSetNX(ctx, key, field, encoded).Result()
	if err == nil && !created {
		return saml.ErrConflict
	}
	return err
}

func (store *SAMLStore) ConsumeRequest(ctx context.Context, stateHash saml.StateHash, consumedAt time.Time) (saml.Request, error) {
	key, field := store.adapter.key("saml-requests"), hashKey(stateHash[:])
	var result saml.Request
	err := store.adapter.watch(ctx, []string{key}, func(tx *redislibrary.Tx) error {
		if err := readJSON(ctx, tx, key, field, &result); errors.Is(err, redislibrary.Nil) {
			return saml.ErrNotFound
		} else if err != nil {
			return err
		}
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, key, field)
			return nil
		})
		if err == nil && !consumedAt.Before(result.ExpiresAt) {
			return saml.ErrInactiveRequest
		}
		return err
	})
	return result, err
}

var _ oidc.Store = (*OIDCStore)(nil)
var _ saml.Store = (*SAMLStore)(nil)
