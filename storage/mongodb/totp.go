package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Rahmannugar/authlier/totp"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type TOTPStore struct{ adapter *Adapter }

func (adapter *Adapter) TOTP() *TOTPStore { return &TOTPStore{adapter} }

func (store *TOTPStore) IsEnabled(ctx context.Context, subjectID string) (bool, error) {
	count, err := store.adapter.collection(totpCredentialsCollection).CountDocuments(ctx, bson.M{
		"_id": subjectID,
		"$or": bson.A{
			bson.M{"disabled_at": bson.M{"$exists": false}},
			bson.M{"disabled_at": nil},
		},
	})
	return count > 0, err
}

type totpEnrollmentDocument struct {
	SubjectID string    `bson:"_id"`
	Secret    []byte    `bson:"encrypted_secret"`
	CreatedAt time.Time `bson:"created_at"`
	ExpiresAt time.Time `bson:"expires_at"`
}

type totpCredentialDocument struct {
	SubjectID       string     `bson:"_id"`
	Secret          []byte     `bson:"encrypted_secret"`
	EnabledAt       time.Time  `bson:"enabled_at"`
	LastUsedCounter *int64     `bson:"last_used_counter,omitempty"`
	DisabledAt      *time.Time `bson:"disabled_at,omitempty"`
}

type totpChallengeDocument struct {
	TokenHash  []byte     `bson:"_id"`
	SubjectID  string     `bson:"subject_id"`
	CreatedAt  time.Time  `bson:"created_at"`
	ExpiresAt  time.Time  `bson:"expires_at"`
	ConsumedAt *time.Time `bson:"consumed_at,omitempty"`
}

func (store *TOTPStore) BeginEnrollment(ctx context.Context, enrollment totp.Enrollment) error {
	secret, err := store.encrypt(ctx, enrollment.Secret)
	if err != nil {
		return err
	}
	_, err = store.adapter.collection(totpEnrollmentsCollection).ReplaceOne(ctx, bson.M{"_id": enrollment.SubjectID}, totpEnrollmentDocument{
		enrollment.SubjectID, secret, enrollment.CreatedAt, enrollment.ExpiresAt,
	}, options.Replace().SetUpsert(true))
	return err
}

func (store *TOTPStore) FindEnrollment(ctx context.Context, subjectID string) (totp.Enrollment, error) {
	var document totpEnrollmentDocument
	err := store.adapter.collection(totpEnrollmentsCollection).FindOne(ctx, bson.M{"_id": subjectID}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return totp.Enrollment{}, totp.ErrNotFound
	}
	if err != nil {
		return totp.Enrollment{}, err
	}
	secret, err := store.decrypt(ctx, document.Secret)
	return totp.Enrollment{SubjectID: document.SubjectID, Secret: string(secret), CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt}, err
}

func (store *TOTPStore) Enable(ctx context.Context, subjectID string, confirmedCounter uint64, recoveryCodes []totp.RecoveryCodeHash, enabledAt time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		var enrollment totpEnrollmentDocument
		if err := store.adapter.collection(totpEnrollmentsCollection).FindOne(tx, bson.M{"_id": subjectID}).Decode(&enrollment); errors.Is(err, mongo.ErrNoDocuments) {
			return totp.ErrNotFound
		} else if err != nil {
			return err
		}
		if !enabledAt.Before(enrollment.ExpiresAt) {
			return totp.ErrInactiveEnrollment
		}
		counter := int64(confirmedCounter)
		_, err := store.adapter.collection(totpCredentialsCollection).ReplaceOne(tx, bson.M{"_id": subjectID}, totpCredentialDocument{
			SubjectID: subjectID, Secret: enrollment.Secret, EnabledAt: enabledAt, LastUsedCounter: &counter,
		}, options.Replace().SetUpsert(true))
		if err != nil {
			return err
		}
		if _, err = store.adapter.collection(totpRecoveryCodesCollection).DeleteMany(tx, bson.M{"subject_id": subjectID}); err != nil {
			return err
		}
		if len(recoveryCodes) > 0 {
			documents := make([]any, len(recoveryCodes))
			for index := range recoveryCodes {
				documents[index] = bson.M{"subject_id": subjectID, "code_hash": recoveryCodes[index][:]}
			}
			if _, err = store.adapter.collection(totpRecoveryCodesCollection).InsertMany(tx, documents); err != nil {
				return err
			}
		}
		_, err = store.adapter.collection(totpEnrollmentsCollection).DeleteOne(tx, bson.M{"_id": subjectID})
		return err
	})
}

func (store *TOTPStore) Disable(ctx context.Context, subjectID string, disabledAt time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		collection := store.adapter.collection(totpCredentialsCollection)
		result, err := collection.UpdateOne(tx, bson.M{"_id": subjectID, "disabled_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"disabled_at": disabledAt}})
		if err != nil {
			return err
		}
		if result.MatchedCount == 0 {
			if err := collection.FindOne(tx, bson.M{"_id": subjectID}).Err(); errors.Is(err, mongo.ErrNoDocuments) {
				return totp.ErrNotFound
			} else if err != nil {
				return err
			}
		}
		_, err = store.adapter.collection(totpRecoveryCodesCollection).DeleteMany(tx, bson.M{"subject_id": subjectID})
		return err
	})
}

func (store *TOTPStore) CreateChallenge(ctx context.Context, challenge totp.Challenge) error {
	_, err := store.adapter.collection(totpChallengesCollection).InsertOne(ctx, totpChallengeDocument{
		challenge.TokenHash[:], challenge.SubjectID, challenge.CreatedAt, challenge.ExpiresAt, nil,
	})
	if duplicateKey(err) {
		return totp.ErrConflict
	}
	return err
}

func (store *TOTPStore) FindChallenge(ctx context.Context, challengeHash totp.ChallengeHash) (totp.Challenge, totp.Credential, error) {
	var challengeDocument totpChallengeDocument
	if err := store.adapter.collection(totpChallengesCollection).FindOne(ctx, bson.M{"_id": challengeHash[:], "consumed_at": bson.M{"$exists": false}}).Decode(&challengeDocument); errors.Is(err, mongo.ErrNoDocuments) {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	} else if err != nil {
		return totp.Challenge{}, totp.Credential{}, err
	}
	var credentialDocument totpCredentialDocument
	if err := store.adapter.collection(totpCredentialsCollection).FindOne(ctx, bson.M{"_id": challengeDocument.SubjectID, "disabled_at": bson.M{"$exists": false}}).Decode(&credentialDocument); errors.Is(err, mongo.ErrNoDocuments) {
		return totp.Challenge{}, totp.Credential{}, totp.ErrNotFound
	} else if err != nil {
		return totp.Challenge{}, totp.Credential{}, err
	}
	secret, err := store.decrypt(ctx, credentialDocument.Secret)
	var hash totp.ChallengeHash
	copy(hash[:], challengeDocument.TokenHash)
	challenge := totp.Challenge{SubjectID: challengeDocument.SubjectID, TokenHash: hash, CreatedAt: challengeDocument.CreatedAt, ExpiresAt: challengeDocument.ExpiresAt}
	credential := totp.Credential{SubjectID: credentialDocument.SubjectID, Secret: string(secret), EnabledAt: credentialDocument.EnabledAt}
	if credentialDocument.LastUsedCounter != nil {
		credential.LastUsedCounter = uint64(*credentialDocument.LastUsedCounter)
		credential.HasLastUsedCounter = true
	}
	return challenge, credential, err
}

func (store *TOTPStore) CompleteCode(ctx context.Context, challengeHash totp.ChallengeHash, counter uint64, completedAt time.Time) (string, error) {
	var subjectID string
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		var err error
		subjectID, err = store.consumeChallenge(tx, challengeHash, completedAt)
		if err != nil {
			return err
		}
		result, err := store.adapter.collection(totpCredentialsCollection).UpdateOne(tx, bson.M{
			"_id": subjectID, "disabled_at": bson.M{"$exists": false},
			"$or": bson.A{bson.M{"last_used_counter": bson.M{"$exists": false}}, bson.M{"last_used_counter": bson.M{"$lt": int64(counter)}}},
		}, bson.M{"$set": bson.M{"last_used_counter": int64(counter)}})
		if err == nil && result.MatchedCount == 0 {
			return totp.ErrInvalidCode
		}
		return err
	})
	return subjectID, err
}

func (store *TOTPStore) CompleteRecovery(ctx context.Context, challengeHash totp.ChallengeHash, recoveryCode totp.RecoveryCodeHash, completedAt time.Time) (string, error) {
	var subjectID string
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		var err error
		subjectID, err = store.consumeChallenge(tx, challengeHash, completedAt)
		if err != nil {
			return err
		}
		result, err := store.adapter.collection(totpRecoveryCodesCollection).UpdateOne(tx, bson.M{
			"subject_id": subjectID, "code_hash": recoveryCode[:], "used_at": bson.M{"$exists": false},
		}, bson.M{"$set": bson.M{"used_at": completedAt}})
		if err == nil && result.MatchedCount == 0 {
			return totp.ErrInvalidCode
		}
		return err
	})
	return subjectID, err
}

func (store *TOTPStore) consumeChallenge(ctx context.Context, hash totp.ChallengeHash, at time.Time) (string, error) {
	var document totpChallengeDocument
	err := store.adapter.collection(totpChallengesCollection).FindOneAndUpdate(ctx, bson.M{
		"_id": hash[:], "consumed_at": bson.M{"$exists": false}, "expires_at": bson.M{"$gt": at},
	}, bson.M{"$set": bson.M{"consumed_at": at}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", totp.ErrInactiveChallenge
	}
	return document.SubjectID, err
}

func (store *TOTPStore) encrypt(ctx context.Context, secret string) ([]byte, error) {
	if store.adapter.secrets == nil {
		return nil, fmt.Errorf("%w: secret codec is required for TOTP", ErrInvalidConfig)
	}
	return store.adapter.secrets.Encrypt(ctx, []byte(secret))
}

func (store *TOTPStore) decrypt(ctx context.Context, encrypted []byte) ([]byte, error) {
	if store.adapter.secrets == nil {
		return nil, fmt.Errorf("%w: secret codec is required for TOTP", ErrInvalidConfig)
	}
	return store.adapter.secrets.Decrypt(ctx, encrypted)
}

var _ totp.Store = (*TOTPStore)(nil)
