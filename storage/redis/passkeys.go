package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/passkey"
	redislibrary "github.com/redis/go-redis/v9"
)

type PasskeyStore struct{ adapter *Adapter }

func (adapter *Adapter) Passkeys() *PasskeyStore { return &PasskeyStore{adapter} }

type storedPasskey struct {
	CredentialID []byte
	SubjectID    string
	Credential   []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (store *PasskeyStore) FindUserBySubject(ctx context.Context, subjectID string) (passkey.User, error) {
	return store.findUser(ctx, subjectID, nil)
}

func (store *PasskeyStore) FindUserByCredential(ctx context.Context, credentialID, userHandle []byte) (passkey.User, error) {
	var credential storedPasskey
	if err := readJSON(ctx, store.adapter.client, store.adapter.key("passkeys"), hashKey(credentialID), &credential); errors.Is(err, redislibrary.Nil) {
		return passkey.User{}, passkey.ErrNotFound
	} else if err != nil {
		return passkey.User{}, err
	}
	return store.findUser(ctx, credential.SubjectID, userHandle)
}

func (store *PasskeyStore) findUser(ctx context.Context, subjectID string, expectedHandle []byte) (passkey.User, error) {
	var stored userRecord
	if err := readJSON(ctx, store.adapter.client, store.adapter.key("users"), subjectID, &stored); errors.Is(err, redislibrary.Nil) {
		return passkey.User{}, passkey.ErrNotFound
	} else if err != nil {
		return passkey.User{}, err
	}
	if expectedHandle != nil && !bytes.Equal(stored.WebAuthnHandle, expectedHandle) {
		return passkey.User{}, passkey.ErrNotFound
	}
	user := passkey.User{SubjectID: stored.ID, Handle: stored.WebAuthnHandle, Name: stored.Email, DisplayName: stored.Email}
	fields, err := store.adapter.client.SMembers(ctx, store.adapter.key("passkeys:subject:"+subjectID)).Result()
	if err != nil || len(fields) == 0 {
		return user, err
	}
	values, err := store.adapter.client.HMGet(ctx, store.adapter.key("passkeys"), fields...).Result()
	if err != nil {
		return user, err
	}
	for _, value := range values {
		if value == nil {
			continue
		}
		var storedCredential storedPasskey
		if err := decodeRedisValue(value, &storedCredential); err != nil {
			return user, err
		}
		var credential passkey.Credential
		if err := json.Unmarshal(storedCredential.Credential, &credential); err != nil {
			return user, err
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, nil
}

func (store *PasskeyStore) CreateCeremony(ctx context.Context, ceremony passkey.Ceremony) error {
	key, field := store.adapter.key("passkey-ceremonies"), hashKey(ceremony.TokenHash[:])
	encoded, err := encodeJSON(ceremony)
	if err != nil {
		return err
	}
	created, err := store.adapter.client.HSetNX(ctx, key, field, encoded).Result()
	if err == nil && !created {
		return passkey.ErrConflict
	}
	return err
}

func (store *PasskeyStore) FindCeremony(ctx context.Context, ceremonyHash passkey.CeremonyHash) (passkey.Ceremony, error) {
	var ceremony passkey.Ceremony
	err := readJSON(ctx, store.adapter.client, store.adapter.key("passkey-ceremonies"), hashKey(ceremonyHash[:]), &ceremony)
	if errors.Is(err, redislibrary.Nil) {
		return ceremony, passkey.ErrNotFound
	}
	return ceremony, err
}

func (store *PasskeyStore) CompleteRegistration(ctx context.Context, ceremonyHash passkey.CeremonyHash, subjectID string, credential passkey.Credential, completedAt time.Time) error {
	ceremonies, credentials := store.adapter.key("passkey-ceremonies"), store.adapter.key("passkeys")
	users, subject := store.adapter.key("users"), store.adapter.key("passkeys:subject:"+subjectID)
	ceremonyField, credentialField := hashKey(ceremonyHash[:]), hashKey(credential.ID)
	return store.adapter.watch(ctx, []string{ceremonies, credentials, users, subject}, func(tx *redislibrary.Tx) error {
		if err := validatePasskeyCeremony(ctx, tx, ceremonies, ceremonyField, subjectID, passkey.CeremonyRegistration, completedAt); err != nil {
			return err
		}
		if exists, err := tx.HExists(ctx, users, subjectID).Result(); err != nil {
			return err
		} else if !exists {
			return passkey.ErrNotFound
		}
		if exists, err := tx.HExists(ctx, credentials, credentialField).Result(); err != nil {
			return err
		} else if exists {
			return passkey.ErrConflict
		}
		credentialJSON, err := json.Marshal(credential)
		if err != nil {
			return err
		}
		storedJSON, _ := encodeJSON(storedPasskey{credential.ID, subjectID, credentialJSON, completedAt, completedAt})
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, ceremonies, ceremonyField)
			pipe.HSet(ctx, credentials, credentialField, storedJSON)
			pipe.SAdd(ctx, subject, credentialField)
			return nil
		})
		return err
	})
}

func (store *PasskeyStore) CompleteAuthentication(ctx context.Context, ceremonyHash passkey.CeremonyHash, subjectID string, previous, updated passkey.Credential, completedAt time.Time) error {
	ceremonies, credentials := store.adapter.key("passkey-ceremonies"), store.adapter.key("passkeys")
	ceremonyField, credentialField := hashKey(ceremonyHash[:]), hashKey(previous.ID)
	return store.adapter.watch(ctx, []string{ceremonies, credentials}, func(tx *redislibrary.Tx) error {
		if err := validatePasskeyCeremony(ctx, tx, ceremonies, ceremonyField, subjectID, passkey.CeremonyAuthentication, completedAt); err != nil {
			return err
		}
		var stored storedPasskey
		if err := readJSON(ctx, tx, credentials, credentialField, &stored); errors.Is(err, redislibrary.Nil) {
			return passkey.ErrConflict
		} else if err != nil {
			return err
		}
		previousJSON, err := json.Marshal(previous)
		if err != nil {
			return err
		}
		if stored.SubjectID != subjectID || !bytes.Equal(stored.Credential, previousJSON) {
			return passkey.ErrConflict
		}
		updatedJSON, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		stored.Credential, stored.UpdatedAt = updatedJSON, completedAt
		encoded, _ := encodeJSON(stored)
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, ceremonies, ceremonyField)
			pipe.HSet(ctx, credentials, credentialField, encoded)
			return nil
		})
		return err
	})
}

func (store *PasskeyStore) DeleteCredential(ctx context.Context, subjectID string, credentialID []byte, _ time.Time) error {
	credentials, subject := store.adapter.key("passkeys"), store.adapter.key("passkeys:subject:"+subjectID)
	users, passwords, google := store.adapter.key("users"), store.adapter.key("passwords"), store.adapter.key("google:subject:"+subjectID)
	field := hashKey(credentialID)
	return store.adapter.watch(ctx, []string{credentials, subject, users, passwords, google}, func(tx *redislibrary.Tx) error {
		if exists, err := tx.HExists(ctx, users, subjectID).Result(); err != nil {
			return err
		} else if !exists {
			return passkey.ErrNotFound
		}
		var credential storedPasskey
		if err := readJSON(ctx, tx, credentials, field, &credential); errors.Is(err, redislibrary.Nil) {
			return passkey.ErrNotFound
		} else if err != nil {
			return err
		} else if credential.SubjectID != subjectID {
			return passkey.ErrNotFound
		}
		passkeyCount, err := tx.SCard(ctx, subject).Result()
		if err != nil {
			return err
		}
		passwordExists, err := tx.HExists(ctx, passwords, subjectID).Result()
		if err != nil {
			return err
		}
		googleCount, err := tx.SCard(ctx, google).Result()
		if err != nil {
			return err
		}
		if passkeyCount == 1 && !passwordExists && googleCount == 0 {
			return passkey.ErrLastCredential
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, credentials, field)
			pipe.SRem(ctx, subject, field)
			return nil
		})
		return err
	})
}

func validatePasskeyCeremony(ctx context.Context, tx *redislibrary.Tx, key, field, subjectID string, ceremonyType passkey.CeremonyType, at time.Time) error {
	var ceremony passkey.Ceremony
	if err := readJSON(ctx, tx, key, field, &ceremony); errors.Is(err, redislibrary.Nil) {
		return passkey.ErrInactiveCeremony
	} else if err != nil {
		return err
	}
	if ceremony.Type != ceremonyType || ceremony.SubjectID != subjectID || !at.Before(ceremony.ExpiresAt) {
		return passkey.ErrInactiveCeremony
	}
	return nil
}

var _ passkey.Store = (*PasskeyStore)(nil)
