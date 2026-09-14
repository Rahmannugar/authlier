package redis

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/google/uuid"
	redislibrary "github.com/redis/go-redis/v9"
)

type EmailPasswordStore struct{ adapter *Adapter }
type EmailVerificationStore struct{ adapter *Adapter }
type PasswordResetStore struct{ adapter *Adapter }
type GoogleStore struct{ adapter *Adapter }

func (adapter *Adapter) EmailPassword() *EmailPasswordStore { return &EmailPasswordStore{adapter} }
func (adapter *Adapter) EmailVerification() *EmailVerificationStore {
	return &EmailVerificationStore{adapter}
}
func (adapter *Adapter) PasswordReset() *PasswordResetStore { return &PasswordResetStore{adapter} }
func (adapter *Adapter) Google() *GoogleStore               { return &GoogleStore{adapter} }

type userRecord struct {
	ID             string
	Email          string
	EmailVerified  bool
	WebAuthnHandle []byte
	CreatedAt      time.Time
}

type passwordRecord struct {
	UserID       string
	PasswordHash string
	UpdatedAt    time.Time
}

type oneTimeTokenRecord struct {
	UserID    string
	Email     string
	TokenHash []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

type googleIdentityRecord struct {
	ProviderSubject string
	UserID          string
	Email           string
	LinkedAt        time.Time
}

func (store *EmailPasswordStore) Register(ctx context.Context, registration emailpassword.Registration) (emailpassword.User, error) {
	user, err := newUserRecord(registration.Email, false, registration.CreatedAt)
	if err != nil {
		return emailpassword.User{}, err
	}
	userJSON, _ := encodeJSON(user)
	passwordJSON, _ := encodeJSON(passwordRecord{user.ID, registration.PasswordHash, registration.CreatedAt})
	keys := []string{store.adapter.key("users"), store.adapter.key("users:email"), store.adapter.key("users:handle"), store.adapter.key("passwords")}
	err = store.adapter.watch(ctx, keys, func(tx *redislibrary.Tx) error {
		emailExists, err := tx.HExists(ctx, keys[1], registration.Email).Result()
		if err != nil {
			return err
		}
		handleExists, err := tx.HExists(ctx, keys[2], hashKey(user.WebAuthnHandle)).Result()
		if err != nil {
			return err
		}
		if emailExists || handleExists {
			return emailpassword.ErrConflict
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, keys[0], user.ID, userJSON)
			pipe.HSet(ctx, keys[1], user.Email, user.ID)
			pipe.HSet(ctx, keys[2], hashKey(user.WebAuthnHandle), user.ID)
			pipe.HSet(ctx, keys[3], user.ID, passwordJSON)
			return nil
		})
		return err
	})
	return emailpassword.User{ID: user.ID, Email: user.Email}, err
}

func (store *EmailPasswordStore) FindByEmail(ctx context.Context, email string) (emailpassword.User, emailpassword.PasswordCredential, error) {
	userID, err := store.adapter.client.HGet(ctx, store.adapter.key("users:email"), email).Result()
	if errors.Is(err, redislibrary.Nil) {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
	}
	if err != nil {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, err
	}
	return store.findBySubject(ctx, userID)
}

func (store *EmailPasswordStore) FindBySubject(ctx context.Context, subjectID string) (emailpassword.User, emailpassword.PasswordCredential, error) {
	return store.findBySubject(ctx, subjectID)
}

func (store *EmailPasswordStore) findBySubject(ctx context.Context, subjectID string) (emailpassword.User, emailpassword.PasswordCredential, error) {
	var user userRecord
	if err := readJSON(ctx, store.adapter.client, store.adapter.key("users"), subjectID, &user); errors.Is(err, redislibrary.Nil) {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
	} else if err != nil {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, err
	}
	var password passwordRecord
	if err := readJSON(ctx, store.adapter.client, store.adapter.key("passwords"), subjectID, &password); errors.Is(err, redislibrary.Nil) {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
	} else if err != nil {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, err
	}
	return emailpassword.User{ID: user.ID, Email: user.Email}, emailpassword.PasswordCredential{UserID: user.ID, PasswordHash: password.PasswordHash}, nil
}

func (store *EmailPasswordStore) AddPassword(ctx context.Context, subjectID, passwordHash string, addedAt time.Time) (emailpassword.User, error) {
	users, passwords := store.adapter.key("users"), store.adapter.key("passwords")
	var result emailpassword.User
	err := store.adapter.watch(ctx, []string{users, passwords}, func(tx *redislibrary.Tx) error {
		var user userRecord
		if err := readJSON(ctx, tx, users, subjectID, &user); errors.Is(err, redislibrary.Nil) {
			return emailpassword.ErrNotFound
		} else if err != nil {
			return err
		}
		exists, err := tx.HExists(ctx, passwords, subjectID).Result()
		if err != nil {
			return err
		}
		if exists {
			return emailpassword.ErrConflict
		}
		encoded, _ := encodeJSON(passwordRecord{subjectID, passwordHash, addedAt})
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, passwords, subjectID, encoded)
			return nil
		})
		result = emailpassword.User{ID: user.ID, Email: user.Email}
		return err
	})
	return result, err
}

func (store *EmailPasswordStore) ReplacePasswordHash(ctx context.Context, userID, currentHash, replacementHash string, updatedAt time.Time) error {
	passwords := store.adapter.key("passwords")
	return store.adapter.watch(ctx, []string{passwords}, func(tx *redislibrary.Tx) error {
		var record passwordRecord
		if err := readJSON(ctx, tx, passwords, userID, &record); errors.Is(err, redislibrary.Nil) {
			return emailpassword.ErrConflict
		} else if err != nil {
			return err
		}
		if record.PasswordHash != currentHash {
			return emailpassword.ErrConflict
		}
		record.PasswordHash, record.UpdatedAt = replacementHash, updatedAt
		encoded, _ := encodeJSON(record)
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, passwords, userID, encoded)
			return nil
		})
		return err
	})
}

func (store *EmailPasswordStore) RemovePassword(ctx context.Context, subjectID, currentHash string, _ time.Time) error {
	users, passwords := store.adapter.key("users"), store.adapter.key("passwords")
	passkeys, google := store.adapter.key("passkeys:subject:"+subjectID), store.adapter.key("google:subject:"+subjectID)
	return store.adapter.watch(ctx, []string{users, passwords, passkeys, google}, func(tx *redislibrary.Tx) error {
		if exists, err := tx.HExists(ctx, users, subjectID).Result(); err != nil {
			return err
		} else if !exists {
			return emailpassword.ErrNotFound
		}
		var password passwordRecord
		if err := readJSON(ctx, tx, passwords, subjectID, &password); errors.Is(err, redislibrary.Nil) {
			return emailpassword.ErrNotFound
		} else if err != nil {
			return err
		}
		if password.PasswordHash != currentHash {
			return emailpassword.ErrConflict
		}
		passkeyCount, err := tx.SCard(ctx, passkeys).Result()
		if err != nil {
			return err
		}
		googleCount, err := tx.SCard(ctx, google).Result()
		if err != nil {
			return err
		}
		if passkeyCount+googleCount == 0 {
			return emailpassword.ErrLastCredential
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, passwords, subjectID)
			return nil
		})
		return err
	})
}

func (store *EmailVerificationStore) FindUserByEmail(ctx context.Context, email string) (emailverification.User, error) {
	user, err := store.adapter.findUserByEmail(ctx, email)
	if err != nil {
		return emailverification.User{}, err
	}
	return emailverification.User{ID: user.ID, Email: user.Email, Verified: user.EmailVerified}, nil
}

func (store *EmailVerificationStore) Issue(ctx context.Context, record emailverification.Record) error {
	return store.adapter.issue(ctx, oneTimeTokenRecord{record.UserID, record.Email, record.TokenHash[:], record.CreatedAt, record.ExpiresAt}, "email-verifications", "email-verification-tokens", emailverification.ErrConflict)
}

func (store *EmailVerificationStore) Verify(ctx context.Context, tokenHash emailverification.TokenHash, verifiedAt time.Time) (emailverification.User, error) {
	records, tokens, users := store.adapter.key("email-verifications"), store.adapter.key("email-verification-tokens"), store.adapter.key("users")
	var result emailverification.User
	err := store.adapter.watch(ctx, []string{records, tokens, users}, func(tx *redislibrary.Tx) error {
		userID, err := tx.HGet(ctx, tokens, hashKey(tokenHash[:])).Result()
		if errors.Is(err, redislibrary.Nil) {
			return emailverification.ErrNotFound
		}
		if err != nil {
			return err
		}
		var token oneTimeTokenRecord
		if err = readJSON(ctx, tx, records, userID, &token); err != nil {
			return emailverification.ErrNotFound
		}
		var user userRecord
		if err = readJSON(ctx, tx, users, userID, &user); err != nil {
			return emailverification.ErrNotFound
		}
		result = emailverification.User{ID: user.ID, Email: user.Email, Verified: user.EmailVerified}
		if user.EmailVerified || !verifiedAt.Before(token.ExpiresAt) {
			return emailverification.ErrInactiveToken
		}
		user.EmailVerified = true
		encoded, _ := encodeJSON(user)
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, users, userID, encoded)
			pipe.HDel(ctx, records, userID)
			pipe.HDel(ctx, tokens, hashKey(token.TokenHash))
			return nil
		})
		result.Verified = true
		return err
	})
	return result, err
}

func (store *PasswordResetStore) FindUserByEmail(ctx context.Context, email string) (passwordreset.User, error) {
	user, err := store.adapter.findUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, emailverification.ErrNotFound) {
			return passwordreset.User{}, passwordreset.ErrNotFound
		}
		return passwordreset.User{}, err
	}
	return passwordreset.User{ID: user.ID, Email: user.Email}, nil
}

func (store *PasswordResetStore) Issue(ctx context.Context, record passwordreset.Record) error {
	return store.adapter.issue(ctx, oneTimeTokenRecord{record.UserID, record.Email, record.TokenHash[:], record.CreatedAt, record.ExpiresAt}, "password-resets", "password-reset-tokens", passwordreset.ErrConflict)
}

func (store *PasswordResetStore) ResetPassword(ctx context.Context, tokenHash passwordreset.TokenHash, passwordHash string, resetAt time.Time) (passwordreset.User, error) {
	records, tokens := store.adapter.key("password-resets"), store.adapter.key("password-reset-tokens")
	users, passwords := store.adapter.key("users"), store.adapter.key("passwords")
	var result passwordreset.User
	err := store.adapter.watch(ctx, []string{records, tokens, users, passwords}, func(tx *redislibrary.Tx) error {
		userID, err := tx.HGet(ctx, tokens, hashKey(tokenHash[:])).Result()
		if errors.Is(err, redislibrary.Nil) {
			return passwordreset.ErrNotFound
		}
		if err != nil {
			return err
		}
		var token oneTimeTokenRecord
		if err = readJSON(ctx, tx, records, userID, &token); err != nil {
			return passwordreset.ErrNotFound
		}
		if !resetAt.Before(token.ExpiresAt) {
			return passwordreset.ErrInactiveToken
		}
		var user userRecord
		if err = readJSON(ctx, tx, users, userID, &user); err != nil {
			return passwordreset.ErrNotFound
		}
		passwordJSON, _ := encodeJSON(passwordRecord{userID, passwordHash, resetAt})
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HSet(ctx, passwords, userID, passwordJSON)
			pipe.HDel(ctx, records, userID)
			pipe.HDel(ctx, tokens, hashKey(token.TokenHash))
			return nil
		})
		result = passwordreset.User{ID: user.ID, Email: user.Email}
		return err
	})
	return result, err
}

func (adapter *Adapter) findUserByEmail(ctx context.Context, email string) (userRecord, error) {
	userID, err := adapter.client.HGet(ctx, adapter.key("users:email"), email).Result()
	if errors.Is(err, redislibrary.Nil) {
		return userRecord{}, emailverification.ErrNotFound
	}
	var user userRecord
	if err == nil {
		err = readJSON(ctx, adapter.client, adapter.key("users"), userID, &user)
	}
	if errors.Is(err, redislibrary.Nil) {
		return user, emailverification.ErrNotFound
	}
	return user, err
}

func (adapter *Adapter) issue(ctx context.Context, record oneTimeTokenRecord, recordName, tokenName string, conflict error) error {
	records, tokens := adapter.key(recordName), adapter.key(tokenName)
	return adapter.watch(ctx, []string{records, tokens}, func(tx *redislibrary.Tx) error {
		var previous oneTimeTokenRecord
		previousErr := readJSON(ctx, tx, records, record.UserID, &previous)
		if previousErr != nil && !errors.Is(previousErr, redislibrary.Nil) {
			return previousErr
		}
		owner, err := tx.HGet(ctx, tokens, hashKey(record.TokenHash)).Result()
		if err == nil && owner != record.UserID {
			return conflict
		}
		if err != nil && !errors.Is(err, redislibrary.Nil) {
			return err
		}
		encoded, _ := encodeJSON(record)
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			if previousErr == nil {
				pipe.HDel(ctx, tokens, hashKey(previous.TokenHash))
			}
			pipe.HSet(ctx, records, record.UserID, encoded)
			pipe.HSet(ctx, tokens, hashKey(record.TokenHash), record.UserID)
			return nil
		})
		return err
	})
}

func (store *GoogleStore) CreateChallenge(ctx context.Context, challenge googleoauth.Challenge) error {
	key, field := store.adapter.key("google-challenges"), hashKey(challenge.StateHash[:])
	encoded, _ := encodeJSON(challenge)
	created, err := store.adapter.client.HSetNX(ctx, key, field, encoded).Result()
	if err == nil && !created {
		return googleoauth.ErrConflict
	}
	return err
}

func (store *GoogleStore) ConsumeChallenge(ctx context.Context, stateHash [32]byte, consumedAt time.Time) (googleoauth.Challenge, error) {
	key, field := store.adapter.key("google-challenges"), hashKey(stateHash[:])
	var result googleoauth.Challenge
	err := store.adapter.watch(ctx, []string{key}, func(tx *redislibrary.Tx) error {
		if err := readJSON(ctx, tx, key, field, &result); errors.Is(err, redislibrary.Nil) {
			return googleoauth.ErrNotFound
		} else if err != nil {
			return err
		}
		_, err := tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, key, field)
			return nil
		})
		if err == nil && !consumedAt.Before(result.ExpiresAt) {
			return googleoauth.ErrInvalidState
		}
		return err
	})
	return result, err
}

func (store *GoogleStore) ResolveIdentity(ctx context.Context, resolution googleoauth.IdentityResolution) (googleoauth.User, error) {
	identities := store.adapter.key("google-identities")
	users, emails, handles := store.adapter.key("users"), store.adapter.key("users:email"), store.adapter.key("users:handle")
	var result googleoauth.User
	keys := []string{identities, users, emails, handles}
	if resolution.SubjectID != "" {
		keys = append(keys, store.adapter.key("google:subject:"+resolution.SubjectID))
	}
	err := store.adapter.watch(ctx, keys, func(tx *redislibrary.Tx) error {
		var identity googleIdentityRecord
		err := readJSON(ctx, tx, identities, resolution.ProviderSubject, &identity)
		if err == nil {
			if resolution.SubjectID != "" && identity.UserID != resolution.SubjectID {
				return googleoauth.ErrConflict
			}
			identity.Email = resolution.Email
			encoded, _ := encodeJSON(identity)
			_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
				pipe.HSet(ctx, identities, resolution.ProviderSubject, encoded)
				return nil
			})
			result.ID = identity.UserID
			return err
		}
		if !errors.Is(err, redislibrary.Nil) {
			return err
		}
		userID := resolution.SubjectID
		var user userRecord
		if userID != "" {
			if err := readJSON(ctx, tx, users, userID, &user); errors.Is(err, redislibrary.Nil) {
				return googleoauth.ErrNotFound
			} else if err != nil {
				return err
			}
		} else {
			if exists, err := tx.HExists(ctx, emails, resolution.Email).Result(); err != nil {
				return err
			} else if exists {
				return googleoauth.ErrLinkRequired
			}
			var err error
			user, err = newUserRecord(resolution.Email, true, time.Now().UTC())
			if err != nil {
				return err
			}
			userID = user.ID
		}
		identity = googleIdentityRecord{resolution.ProviderSubject, userID, resolution.Email, time.Now().UTC()}
		identityJSON, _ := encodeJSON(identity)
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			if resolution.SubjectID == "" {
				userJSON, _ := encodeJSON(user)
				pipe.HSet(ctx, users, user.ID, userJSON)
				pipe.HSet(ctx, emails, user.Email, user.ID)
				pipe.HSet(ctx, handles, hashKey(user.WebAuthnHandle), user.ID)
			}
			pipe.HSet(ctx, identities, resolution.ProviderSubject, identityJSON)
			pipe.SAdd(ctx, store.adapter.key("google:subject:"+userID), resolution.ProviderSubject)
			return nil
		})
		result.ID = userID
		return err
	})
	return result, err
}

func (store *GoogleStore) UnlinkIdentity(ctx context.Context, subjectID, providerSubject string, _ time.Time) error {
	users, identities := store.adapter.key("users"), store.adapter.key("google-identities")
	googleSet := store.adapter.key("google:subject:" + subjectID)
	passwords, passkeys := store.adapter.key("passwords"), store.adapter.key("passkeys:subject:"+subjectID)
	return store.adapter.watch(ctx, []string{users, identities, googleSet, passwords, passkeys}, func(tx *redislibrary.Tx) error {
		if exists, err := tx.HExists(ctx, users, subjectID).Result(); err != nil {
			return err
		} else if !exists {
			return googleoauth.ErrNotFound
		}
		var identity googleIdentityRecord
		if err := readJSON(ctx, tx, identities, providerSubject, &identity); errors.Is(err, redislibrary.Nil) {
			return googleoauth.ErrNotFound
		} else if err != nil {
			return err
		} else if identity.UserID != subjectID {
			return googleoauth.ErrNotFound
		}
		passwordCount, err := tx.HExists(ctx, passwords, subjectID).Result()
		if err != nil {
			return err
		}
		passkeyCount, err := tx.SCard(ctx, passkeys).Result()
		if err != nil {
			return err
		}
		googleCount, err := tx.SCard(ctx, googleSet).Result()
		if err != nil {
			return err
		}
		if !passwordCount && passkeyCount+googleCount <= 1 {
			return googleoauth.ErrLastCredential
		}
		_, err = tx.TxPipelined(ctx, func(pipe redislibrary.Pipeliner) error {
			pipe.HDel(ctx, identities, providerSubject)
			pipe.SRem(ctx, googleSet, providerSubject)
			return nil
		})
		return err
	})
}

func (store *GoogleStore) ListIdentities(
	ctx context.Context,
	subjectID string,
) ([]googleoauth.LinkedIdentity, error) {
	providerSubjects, err := store.adapter.client.SMembers(
		ctx, store.adapter.key("google:subject:"+subjectID),
	).Result()
	if err != nil || len(providerSubjects) == 0 {
		return []googleoauth.LinkedIdentity{}, err
	}
	values, err := store.adapter.client.HMGet(
		ctx, store.adapter.key("google-identities"), providerSubjects...,
	).Result()
	if err != nil {
		return nil, err
	}
	identities := make([]googleoauth.LinkedIdentity, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		var identity googleIdentityRecord
		if err := decodeRedisValue(value, &identity); err != nil {
			return nil, err
		}
		identities = append(identities, googleoauth.LinkedIdentity{
			ProviderSubject: identity.ProviderSubject,
			Email:           identity.Email,
			LinkedAt:        identity.LinkedAt,
		})
	}
	slices.SortFunc(identities, func(left, right googleoauth.LinkedIdentity) int {
		return left.LinkedAt.Compare(right.LinkedAt)
	})
	return identities, nil
}

func newUserRecord(email string, verified bool, createdAt time.Time) (userRecord, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return userRecord{}, fmt.Errorf("generate user ID: %w", err)
	}
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return userRecord{}, fmt.Errorf("generate WebAuthn handle: %w", err)
	}
	return userRecord{ID: id.String(), Email: email, EmailVerified: verified, WebAuthnHandle: handle, CreatedAt: createdAt}, nil
}

var _ emailpassword.Store = (*EmailPasswordStore)(nil)
var _ emailpassword.CredentialStore = (*EmailPasswordStore)(nil)
var _ emailverification.Store = (*EmailVerificationStore)(nil)
var _ passwordreset.Store = (*PasswordResetStore)(nil)
var _ googleoauth.Store = (*GoogleStore)(nil)
var _ googleoauth.IdentityStore = (*GoogleStore)(nil)
