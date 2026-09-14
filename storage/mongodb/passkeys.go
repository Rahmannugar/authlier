package mongodb

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/passkey"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type PasskeyStore struct{ adapter *Adapter }

func (adapter *Adapter) Passkeys() *PasskeyStore { return &PasskeyStore{adapter} }

type passkeyCredentialDocument struct {
	CredentialID []byte    `bson:"_id"`
	SubjectID    string    `bson:"subject_id"`
	Credential   []byte    `bson:"credential"`
	CreatedAt    time.Time `bson:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at"`
}

type passkeyCeremonyDocument struct {
	TokenHash  []byte               `bson:"_id"`
	Type       passkey.CeremonyType `bson:"ceremony_type"`
	SubjectID  string               `bson:"subject_id"`
	Session    []byte               `bson:"session_data"`
	CreatedAt  time.Time            `bson:"created_at"`
	ExpiresAt  time.Time            `bson:"expires_at"`
	ConsumedAt *time.Time           `bson:"consumed_at,omitempty"`
}

func (store *PasskeyStore) FindUserBySubject(ctx context.Context, subjectID string) (passkey.User, error) {
	return store.findUser(ctx, bson.M{"_id": subjectID})
}

func (store *PasskeyStore) FindUserByCredential(ctx context.Context, credentialID, userHandle []byte) (passkey.User, error) {
	var credential passkeyCredentialDocument
	if err := store.adapter.collection(passkeyCredentialsCollection).FindOne(ctx, bson.M{"_id": credentialID}).Decode(&credential); errors.Is(err, mongo.ErrNoDocuments) {
		return passkey.User{}, passkey.ErrNotFound
	} else if err != nil {
		return passkey.User{}, err
	}
	return store.findUser(ctx, bson.M{"_id": credential.SubjectID, "webauthn_handle": userHandle})
}

func (store *PasskeyStore) findUser(ctx context.Context, filter bson.M) (passkey.User, error) {
	var document userDocument
	if err := store.adapter.collection(usersCollection).FindOne(ctx, filter).Decode(&document); errors.Is(err, mongo.ErrNoDocuments) {
		return passkey.User{}, passkey.ErrNotFound
	} else if err != nil {
		return passkey.User{}, err
	}
	user := passkey.User{SubjectID: document.ID, Handle: document.WebAuthnHandle, Name: document.Email, DisplayName: document.Email}
	cursor, err := store.adapter.collection(passkeyCredentialsCollection).Find(ctx, bson.M{"subject_id": document.ID})
	if err != nil {
		return user, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var stored passkeyCredentialDocument
		if err := cursor.Decode(&stored); err != nil {
			return user, err
		}
		var credential passkey.Credential
		if err := json.Unmarshal(stored.Credential, &credential); err != nil {
			return user, err
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, cursor.Err()
}

func (store *PasskeyStore) CreateCeremony(ctx context.Context, ceremony passkey.Ceremony) error {
	session, err := json.Marshal(ceremony.Session)
	if err != nil {
		return err
	}
	_, err = store.adapter.collection(passkeyCeremoniesCollection).InsertOne(ctx, passkeyCeremonyDocument{
		TokenHash: ceremony.TokenHash[:], Type: ceremony.Type, SubjectID: ceremony.SubjectID,
		Session: session, CreatedAt: ceremony.CreatedAt, ExpiresAt: ceremony.ExpiresAt,
	})
	if duplicateKey(err) {
		return passkey.ErrConflict
	}
	return err
}

func (store *PasskeyStore) FindCeremony(ctx context.Context, ceremonyHash passkey.CeremonyHash) (passkey.Ceremony, error) {
	var document passkeyCeremonyDocument
	err := store.adapter.collection(passkeyCeremoniesCollection).FindOne(ctx, bson.M{"_id": ceremonyHash[:], "consumed_at": bson.M{"$exists": false}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return passkey.Ceremony{}, passkey.ErrNotFound
	}
	return decodeCeremony(document, err)
}

func decodeCeremony(document passkeyCeremonyDocument, err error) (passkey.Ceremony, error) {
	var hash passkey.CeremonyHash
	copy(hash[:], document.TokenHash)
	ceremony := passkey.Ceremony{Type: document.Type, TokenHash: hash, SubjectID: document.SubjectID, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt}
	if err == nil {
		err = json.Unmarshal(document.Session, &ceremony.Session)
	}
	return ceremony, err
}

func (store *PasskeyStore) CompleteRegistration(ctx context.Context, ceremonyHash passkey.CeremonyHash, subjectID string, credential passkey.Credential, completedAt time.Time) error {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		if err := store.consumeCeremony(tx, ceremonyHash, subjectID, passkey.CeremonyRegistration, completedAt); err != nil {
			return err
		}
		if _, err := store.adapter.lockUser(tx, subjectID); errors.Is(err, mongo.ErrNoDocuments) {
			return passkey.ErrNotFound
		} else if err != nil {
			return err
		}
		_, err := store.adapter.collection(passkeyCredentialsCollection).InsertOne(tx, passkeyCredentialDocument{credential.ID, subjectID, encoded, completedAt, completedAt})
		if duplicateKey(err) {
			return passkey.ErrConflict
		}
		return err
	})
}

func (store *PasskeyStore) CompleteAuthentication(ctx context.Context, ceremonyHash passkey.CeremonyHash, subjectID string, previous, updated passkey.Credential, completedAt time.Time) error {
	previousJSON, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	updatedJSON, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		if err := store.consumeCeremony(tx, ceremonyHash, subjectID, passkey.CeremonyAuthentication, completedAt); err != nil {
			return err
		}
		result, err := store.adapter.collection(passkeyCredentialsCollection).UpdateOne(tx,
			bson.M{"_id": previous.ID, "subject_id": subjectID, "credential": previousJSON},
			bson.M{"$set": bson.M{"credential": updatedJSON, "updated_at": completedAt}},
		)
		if err == nil && result.MatchedCount == 0 {
			return passkey.ErrConflict
		}
		return err
	})
}

func (store *PasskeyStore) DeleteCredential(ctx context.Context, subjectID string, credentialID []byte, _ time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		if _, err := store.adapter.lockUser(tx, subjectID); errors.Is(err, mongo.ErrNoDocuments) {
			return passkey.ErrNotFound
		} else if err != nil {
			return err
		}
		passkeys, err := store.adapter.collection(passkeyCredentialsCollection).CountDocuments(tx, bson.M{"subject_id": subjectID})
		if err != nil {
			return err
		}
		passwords, err := store.adapter.collection(passwordsCollection).CountDocuments(tx, bson.M{"_id": subjectID})
		if err != nil {
			return err
		}
		googleIdentities, err := store.adapter.collection(googleIdentitiesCollection).CountDocuments(tx, bson.M{"user_id": subjectID})
		if err != nil {
			return err
		}
		if passkeys == 1 && passwords+googleIdentities == 0 {
			return passkey.ErrLastCredential
		}
		result, err := store.adapter.collection(passkeyCredentialsCollection).DeleteOne(tx, bson.M{"_id": credentialID, "subject_id": subjectID})
		if err == nil && result.DeletedCount == 0 {
			return passkey.ErrNotFound
		}
		return err
	})
}

func (store *PasskeyStore) consumeCeremony(ctx context.Context, hash passkey.CeremonyHash, subjectID string, ceremonyType passkey.CeremonyType, at time.Time) error {
	result, err := store.adapter.collection(passkeyCeremoniesCollection).UpdateOne(ctx, bson.M{
		"_id": hash[:], "ceremony_type": ceremonyType, "subject_id": subjectID,
		"consumed_at": bson.M{"$exists": false}, "expires_at": bson.M{"$gt": at},
	}, bson.M{"$set": bson.M{"consumed_at": at}})
	if err == nil && result.MatchedCount == 0 {
		return passkey.ErrInactiveCeremony
	}
	return err
}

var _ passkey.Store = (*PasskeyStore)(nil)
