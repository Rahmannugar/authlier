package mongodb

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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

type userDocument struct {
	ID             string    `bson:"_id"`
	Email          string    `bson:"email"`
	EmailVerified  bool      `bson:"email_verified"`
	WebAuthnHandle []byte    `bson:"webauthn_handle"`
	CreatedAt      time.Time `bson:"created_at"`
}

type passwordDocument struct {
	UserID       string    `bson:"_id"`
	PasswordHash string    `bson:"password_hash"`
	UpdatedAt    time.Time `bson:"updated_at"`
}

type tokenDocument struct {
	UserID    string    `bson:"_id"`
	Email     string    `bson:"email"`
	TokenHash []byte    `bson:"token_hash"`
	CreatedAt time.Time `bson:"created_at"`
	ExpiresAt time.Time `bson:"expires_at"`
}

type googleIdentityDocument struct {
	ProviderSubject string    `bson:"_id"`
	UserID          string    `bson:"user_id"`
	Email           string    `bson:"email"`
	LinkedAt        time.Time `bson:"linked_at"`
}

func (store *EmailPasswordStore) Register(ctx context.Context, registration emailpassword.Registration) (emailpassword.User, error) {
	var user emailpassword.User
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		document, err := newUserDocument(registration.Email, false, registration.CreatedAt)
		if err != nil {
			return err
		}
		if _, err = store.adapter.collection(usersCollection).InsertOne(tx, document); err != nil {
			if duplicateKey(err) {
				return emailpassword.ErrConflict
			}
			return err
		}
		_, err = store.adapter.collection(passwordsCollection).InsertOne(tx, passwordDocument{
			UserID: document.ID, PasswordHash: registration.PasswordHash, UpdatedAt: registration.CreatedAt,
		})
		if err != nil {
			return err
		}
		user = emailpassword.User{ID: document.ID, Email: document.Email}
		return nil
	})
	return user, err
}

func (store *EmailPasswordStore) FindByEmail(ctx context.Context, email string) (emailpassword.User, emailpassword.PasswordCredential, error) {
	var document userDocument
	if err := store.adapter.collection(usersCollection).FindOne(ctx, bson.M{"email": email}).Decode(&document); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
		}
		return emailpassword.User{}, emailpassword.PasswordCredential{}, err
	}
	return store.findWithPassword(ctx, document)
}

func (store *EmailPasswordStore) FindBySubject(ctx context.Context, subjectID string) (emailpassword.User, emailpassword.PasswordCredential, error) {
	var document userDocument
	if err := store.adapter.collection(usersCollection).FindOne(ctx, bson.M{"_id": subjectID}).Decode(&document); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
		}
		return emailpassword.User{}, emailpassword.PasswordCredential{}, err
	}
	return store.findWithPassword(ctx, document)
}

func (store *EmailPasswordStore) findWithPassword(ctx context.Context, document userDocument) (emailpassword.User, emailpassword.PasswordCredential, error) {
	var password passwordDocument
	err := store.adapter.collection(passwordsCollection).FindOne(ctx, bson.M{"_id": document.ID}).Decode(&password)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return emailpassword.User{}, emailpassword.PasswordCredential{}, emailpassword.ErrNotFound
	}
	return emailpassword.User{ID: document.ID, Email: document.Email}, emailpassword.PasswordCredential{
		UserID: document.ID, PasswordHash: password.PasswordHash,
	}, err
}

func (store *EmailPasswordStore) AddPassword(ctx context.Context, subjectID, passwordHash string, addedAt time.Time) (emailpassword.User, error) {
	var user emailpassword.User
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		document, err := store.adapter.lockUser(tx, subjectID)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return emailpassword.ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err = store.adapter.collection(passwordsCollection).InsertOne(tx, passwordDocument{subjectID, passwordHash, addedAt}); err != nil {
			if duplicateKey(err) {
				return emailpassword.ErrConflict
			}
			return err
		}
		user = emailpassword.User{ID: document.ID, Email: document.Email}
		return nil
	})
	return user, err
}

func (store *EmailPasswordStore) ReplacePasswordHash(ctx context.Context, userID, currentHash, replacementHash string, updatedAt time.Time) error {
	result, err := store.adapter.collection(passwordsCollection).UpdateOne(ctx,
		bson.M{"_id": userID, "password_hash": currentHash},
		bson.M{"$set": bson.M{"password_hash": replacementHash, "updated_at": updatedAt}},
	)
	if err == nil && result.MatchedCount == 0 {
		return emailpassword.ErrConflict
	}
	return err
}

func (store *EmailPasswordStore) RemovePassword(ctx context.Context, subjectID, currentHash string, _ time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		if _, err := store.adapter.lockUser(tx, subjectID); errors.Is(err, mongo.ErrNoDocuments) {
			return emailpassword.ErrNotFound
		} else if err != nil {
			return err
		}
		var password passwordDocument
		if err := store.adapter.collection(passwordsCollection).FindOne(tx, bson.M{"_id": subjectID}).Decode(&password); errors.Is(err, mongo.ErrNoDocuments) {
			return emailpassword.ErrNotFound
		} else if err != nil {
			return err
		}
		if password.PasswordHash != currentHash {
			return emailpassword.ErrConflict
		}
		count, err := store.adapter.otherCredentialCount(tx, subjectID)
		if err != nil {
			return err
		}
		if count == 0 {
			return emailpassword.ErrLastCredential
		}
		_, err = store.adapter.collection(passwordsCollection).DeleteOne(tx, bson.M{"_id": subjectID})
		return err
	})
}

func (store *EmailVerificationStore) FindUserByEmail(ctx context.Context, email string) (emailverification.User, error) {
	var document userDocument
	err := store.adapter.collection(usersCollection).FindOne(ctx, bson.M{"email": email}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return emailverification.User{}, emailverification.ErrNotFound
	}
	return emailverification.User{ID: document.ID, Email: document.Email, Verified: document.EmailVerified}, err
}

func (store *EmailVerificationStore) Issue(ctx context.Context, record emailverification.Record) error {
	_, err := store.adapter.collection(emailVerificationsCollection).ReplaceOne(ctx, bson.M{"_id": record.UserID}, tokenDocument{
		UserID: record.UserID, Email: record.Email, TokenHash: record.TokenHash[:], CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
	}, options.Replace().SetUpsert(true))
	if duplicateKey(err) {
		return emailverification.ErrConflict
	}
	return err
}

func (store *EmailVerificationStore) Verify(ctx context.Context, tokenHash emailverification.TokenHash, verifiedAt time.Time) (emailverification.User, error) {
	var user emailverification.User
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		var token tokenDocument
		if err := store.adapter.collection(emailVerificationsCollection).FindOne(tx, bson.M{"token_hash": tokenHash[:]}).Decode(&token); errors.Is(err, mongo.ErrNoDocuments) {
			return emailverification.ErrNotFound
		} else if err != nil {
			return err
		}
		var document userDocument
		if err := store.adapter.collection(usersCollection).FindOne(tx, bson.M{"_id": token.UserID}).Decode(&document); errors.Is(err, mongo.ErrNoDocuments) {
			return emailverification.ErrNotFound
		} else if err != nil {
			return err
		}
		user = emailverification.User{ID: document.ID, Email: document.Email, Verified: document.EmailVerified}
		if user.Verified || !verifiedAt.Before(token.ExpiresAt) {
			return emailverification.ErrInactiveToken
		}
		if _, err := store.adapter.collection(usersCollection).UpdateOne(tx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"email_verified": true}}); err != nil {
			return err
		}
		if _, err := store.adapter.collection(emailVerificationsCollection).DeleteOne(tx, bson.M{"_id": token.UserID}); err != nil {
			return err
		}
		user.Verified = true
		return nil
	})
	return user, err
}

func (store *PasswordResetStore) FindUserByEmail(ctx context.Context, email string) (passwordreset.User, error) {
	var document userDocument
	err := store.adapter.collection(usersCollection).FindOne(ctx, bson.M{"email": email}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return passwordreset.User{}, passwordreset.ErrNotFound
	}
	return passwordreset.User{ID: document.ID, Email: document.Email}, err
}

func (store *PasswordResetStore) Issue(ctx context.Context, record passwordreset.Record) error {
	_, err := store.adapter.collection(passwordResetsCollection).ReplaceOne(ctx, bson.M{"_id": record.UserID}, tokenDocument{
		UserID: record.UserID, Email: record.Email, TokenHash: record.TokenHash[:], CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
	}, options.Replace().SetUpsert(true))
	if duplicateKey(err) {
		return passwordreset.ErrConflict
	}
	return err
}

func (store *PasswordResetStore) ResetPassword(ctx context.Context, tokenHash passwordreset.TokenHash, passwordHash string, resetAt time.Time) (passwordreset.User, error) {
	var user passwordreset.User
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		var token tokenDocument
		if err := store.adapter.collection(passwordResetsCollection).FindOne(tx, bson.M{"token_hash": tokenHash[:]}).Decode(&token); errors.Is(err, mongo.ErrNoDocuments) {
			return passwordreset.ErrNotFound
		} else if err != nil {
			return err
		}
		if !resetAt.Before(token.ExpiresAt) {
			return passwordreset.ErrInactiveToken
		}
		var document userDocument
		if err := store.adapter.collection(usersCollection).FindOne(tx, bson.M{"_id": token.UserID}).Decode(&document); errors.Is(err, mongo.ErrNoDocuments) {
			return passwordreset.ErrNotFound
		} else if err != nil {
			return err
		}
		_, err := store.adapter.collection(passwordsCollection).ReplaceOne(tx, bson.M{"_id": token.UserID}, passwordDocument{
			UserID: token.UserID, PasswordHash: passwordHash, UpdatedAt: resetAt,
		}, options.Replace().SetUpsert(true))
		if err != nil {
			return err
		}
		if _, err = store.adapter.collection(passwordResetsCollection).DeleteOne(tx, bson.M{"_id": token.UserID}); err != nil {
			return err
		}
		user = passwordreset.User{ID: document.ID, Email: document.Email}
		return nil
	})
	return user, err
}

func (store *GoogleStore) CreateChallenge(ctx context.Context, challenge googleoauth.Challenge) error {
	_, err := store.adapter.collection(googleChallengesCollection).InsertOne(ctx, bson.M{
		"_id": challenge.StateHash[:], "nonce": challenge.Nonce, "code_verifier": challenge.CodeVerifier,
		"subject_id": challenge.SubjectID, "created_at": challenge.CreatedAt, "expires_at": challenge.ExpiresAt,
	})
	if duplicateKey(err) {
		return googleoauth.ErrConflict
	}
	return err
}

func (store *GoogleStore) ConsumeChallenge(ctx context.Context, stateHash [32]byte, consumedAt time.Time) (googleoauth.Challenge, error) {
	var document struct {
		StateHash    []byte    `bson:"_id"`
		Nonce        string    `bson:"nonce"`
		CodeVerifier string    `bson:"code_verifier"`
		SubjectID    string    `bson:"subject_id"`
		CreatedAt    time.Time `bson:"created_at"`
		ExpiresAt    time.Time `bson:"expires_at"`
	}
	err := store.adapter.collection(googleChallengesCollection).FindOneAndDelete(ctx, bson.M{"_id": stateHash[:]}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return googleoauth.Challenge{}, googleoauth.ErrNotFound
	}
	challenge := googleoauth.Challenge{Nonce: document.Nonce, CodeVerifier: document.CodeVerifier, SubjectID: document.SubjectID, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt}
	copy(challenge.StateHash[:], document.StateHash)
	if err == nil && !consumedAt.Before(challenge.ExpiresAt) {
		return challenge, googleoauth.ErrInvalidState
	}
	return challenge, err
}

func (store *GoogleStore) ResolveIdentity(ctx context.Context, resolution googleoauth.IdentityResolution) (googleoauth.User, error) {
	var user googleoauth.User
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		var identity googleIdentityDocument
		err := store.adapter.collection(googleIdentitiesCollection).FindOne(tx, bson.M{"_id": resolution.ProviderSubject}).Decode(&identity)
		if err == nil {
			if resolution.SubjectID != "" && identity.UserID != resolution.SubjectID {
				return googleoauth.ErrConflict
			}
			_, err = store.adapter.collection(googleIdentitiesCollection).UpdateOne(tx, bson.M{"_id": resolution.ProviderSubject}, bson.M{"$set": bson.M{"email": resolution.Email}})
			user.ID = identity.UserID
			return err
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			return err
		}
		userID := resolution.SubjectID
		if userID != "" {
			if _, err = store.adapter.lockUser(tx, userID); errors.Is(err, mongo.ErrNoDocuments) {
				return googleoauth.ErrNotFound
			} else if err != nil {
				return err
			}
		} else {
			var existing userDocument
			err = store.adapter.collection(usersCollection).FindOne(tx, bson.M{"email": resolution.Email}).Decode(&existing)
			if err == nil {
				return googleoauth.ErrLinkRequired
			}
			if !errors.Is(err, mongo.ErrNoDocuments) {
				return err
			}
			document, createErr := newUserDocument(resolution.Email, true, time.Now().UTC())
			if createErr != nil {
				return createErr
			}
			if _, err = store.adapter.collection(usersCollection).InsertOne(tx, document); err != nil {
				if duplicateKey(err) {
					return googleoauth.ErrLinkRequired
				}
				return err
			}
			userID = document.ID
		}
		_, err = store.adapter.collection(googleIdentitiesCollection).InsertOne(tx, googleIdentityDocument{
			ProviderSubject: resolution.ProviderSubject, UserID: userID, Email: resolution.Email, LinkedAt: time.Now().UTC(),
		})
		if duplicateKey(err) {
			return googleoauth.ErrConflict
		}
		user.ID = userID
		return err
	})
	return user, err
}

func (store *GoogleStore) UnlinkIdentity(ctx context.Context, subjectID, providerSubject string, _ time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		if _, err := store.adapter.lockUser(tx, subjectID); errors.Is(err, mongo.ErrNoDocuments) {
			return googleoauth.ErrNotFound
		} else if err != nil {
			return err
		}
		var identity googleIdentityDocument
		if err := store.adapter.collection(googleIdentitiesCollection).FindOne(tx, bson.M{"_id": providerSubject, "user_id": subjectID}).Decode(&identity); errors.Is(err, mongo.ErrNoDocuments) {
			return googleoauth.ErrNotFound
		} else if err != nil {
			return err
		}
		passwords, err := store.adapter.collection(passwordsCollection).CountDocuments(tx, bson.M{"_id": subjectID})
		if err != nil {
			return err
		}
		passkeys, err := store.adapter.collection(passkeyCredentialsCollection).CountDocuments(tx, bson.M{"subject_id": subjectID})
		if err != nil {
			return err
		}
		otherGoogleIdentities, err := store.adapter.collection(googleIdentitiesCollection).CountDocuments(tx, bson.M{
			"user_id": subjectID, "_id": bson.M{"$ne": providerSubject},
		})
		if err != nil {
			return err
		}
		if passwords+passkeys+otherGoogleIdentities == 0 {
			return googleoauth.ErrLastCredential
		}
		_, err = store.adapter.collection(googleIdentitiesCollection).DeleteOne(tx, bson.M{"_id": providerSubject, "user_id": subjectID})
		return err
	})
}

func newUserDocument(email string, verified bool, createdAt time.Time) (userDocument, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return userDocument{}, fmt.Errorf("generate user ID: %w", err)
	}
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return userDocument{}, fmt.Errorf("generate WebAuthn handle: %w", err)
	}
	return userDocument{ID: id.String(), Email: email, EmailVerified: verified, WebAuthnHandle: handle, CreatedAt: createdAt}, nil
}

func (adapter *Adapter) lockUser(ctx context.Context, subjectID string) (userDocument, error) {
	var user userDocument
	err := adapter.collection(usersCollection).FindOneAndUpdate(ctx, bson.M{"_id": subjectID}, bson.M{"$inc": bson.M{"credential_version": 1}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&user)
	return user, err
}

func (adapter *Adapter) otherCredentialCount(ctx context.Context, subjectID string) (int64, error) {
	googleCount, err := adapter.collection(googleIdentitiesCollection).CountDocuments(ctx, bson.M{"user_id": subjectID})
	if err != nil {
		return 0, err
	}
	passkeyCount, err := adapter.collection(passkeyCredentialsCollection).CountDocuments(ctx, bson.M{"subject_id": subjectID})
	return googleCount + passkeyCount, err
}

var _ emailpassword.Store = (*EmailPasswordStore)(nil)
var _ emailpassword.CredentialStore = (*EmailPasswordStore)(nil)
var _ emailverification.Store = (*EmailVerificationStore)(nil)
var _ passwordreset.Store = (*PasswordResetStore)(nil)
var _ googleoauth.Store = (*GoogleStore)(nil)
var _ googleoauth.IdentityStore = (*GoogleStore)(nil)
