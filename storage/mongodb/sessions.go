package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/sessiontoken"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type SessionStore struct{ adapter *Adapter }
type RefreshTokenStore struct{ adapter *Adapter }
type AccessSessionStore struct{ adapter *Adapter }

func (adapter *Adapter) Sessions() *SessionStore { return &SessionStore{adapter} }
func (adapter *Adapter) RefreshTokens() *RefreshTokenStore {
	return &RefreshTokenStore{adapter}
}
func (adapter *Adapter) AccessSessions() *AccessSessionStore { return &AccessSessionStore{adapter} }

type sessionDocument struct {
	TokenHash  []byte     `bson:"_id"`
	ID         string     `bson:"session_id"`
	SubjectID  string     `bson:"subject_id"`
	CreatedAt  time.Time  `bson:"created_at"`
	ExpiresAt  time.Time  `bson:"expires_at"`
	ExtendedAt *time.Time `bson:"extended_at,omitempty"`
	RevokedAt  *time.Time `bson:"revoked_at,omitempty"`
}

func sessionDocumentFrom(record sessiontoken.Record) sessionDocument {
	return sessionDocument{
		TokenHash: record.TokenHash[:], ID: record.ID, SubjectID: record.SubjectID,
		CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
		ExtendedAt: record.ExtendedAt, RevokedAt: record.RevokedAt,
	}
}

func (document sessionDocument) record() sessiontoken.Record {
	var hash sessiontoken.TokenHash
	copy(hash[:], document.TokenHash)
	return sessiontoken.Record{
		ID: document.ID, SubjectID: document.SubjectID, TokenHash: hash,
		CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt,
		ExtendedAt: document.ExtendedAt, RevokedAt: document.RevokedAt,
	}
}

func (store *SessionStore) Create(ctx context.Context, record sessiontoken.Record) error {
	_, err := store.adapter.collection(sessionsCollection).InsertOne(ctx, sessionDocumentFrom(record))
	if duplicateKey(err) {
		return sessiontoken.ErrConflict
	}
	return err
}

func (store *SessionStore) FindByTokenHash(ctx context.Context, tokenHash sessiontoken.TokenHash) (sessiontoken.Record, error) {
	var document sessionDocument
	err := store.adapter.collection(sessionsCollection).FindOne(ctx, bson.M{"_id": tokenHash[:]}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return sessiontoken.Record{}, sessiontoken.ErrNotFound
	}
	return document.record(), err
}

func (store *SessionStore) ListBySubject(ctx context.Context, subjectID string) ([]sessiontoken.Record, error) {
	cursor, err := store.adapter.collection(sessionsCollection).Find(ctx, bson.M{"subject_id": subjectID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var documents []sessionDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, err
	}
	records := make([]sessiontoken.Record, len(documents))
	for index := range documents {
		records[index] = documents[index].record()
	}
	return records, nil
}

func (store *SessionStore) Extend(ctx context.Context, tokenHash sessiontoken.TokenHash, extendedAt, expiresAt time.Time) (sessiontoken.Record, error) {
	var document sessionDocument
	err := store.adapter.collection(sessionsCollection).FindOneAndUpdate(ctx, bson.M{
		"_id": tokenHash[:], "revoked_at": bson.M{"$exists": false}, "expires_at": bson.M{"$gt": extendedAt, "$lt": expiresAt},
	}, bson.M{"$set": bson.M{"extended_at": extendedAt, "expires_at": expiresAt}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return sessiontoken.Record{}, sessiontoken.ErrInactive
	}
	return document.record(), err
}

func (store *SessionStore) Rotate(ctx context.Context, current sessiontoken.TokenHash, replacement sessiontoken.Record, rotatedAt time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		var currentDocument sessionDocument
		if err := store.adapter.collection(sessionsCollection).FindOne(tx, bson.M{"_id": current[:]}).Decode(&currentDocument); errors.Is(err, mongo.ErrNoDocuments) {
			return sessiontoken.ErrNotFound
		} else if err != nil {
			return err
		}
		if currentDocument.RevokedAt != nil || !rotatedAt.Before(currentDocument.ExpiresAt) {
			return sessiontoken.ErrInactive
		}
		if _, err := store.adapter.collection(sessionsCollection).InsertOne(tx, sessionDocumentFrom(replacement)); err != nil {
			if duplicateKey(err) {
				return sessiontoken.ErrConflict
			}
			return err
		}
		_, err := store.adapter.collection(sessionsCollection).UpdateOne(tx, bson.M{"_id": current[:], "revoked_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"revoked_at": rotatedAt}})
		return err
	})
}

func (store *SessionStore) Revoke(ctx context.Context, tokenHash sessiontoken.TokenHash, revokedAt time.Time) error {
	collection := store.adapter.collection(sessionsCollection)
	result, err := collection.UpdateOne(ctx, bson.M{
		"_id": tokenHash[:], "revoked_at": bson.M{"$exists": false},
	}, bson.M{"$set": bson.M{"revoked_at": revokedAt}})
	if err != nil || result.MatchedCount != 0 {
		return err
	}
	if err := collection.FindOne(ctx, bson.M{"_id": tokenHash[:]}).Err(); errors.Is(err, mongo.ErrNoDocuments) {
		return sessiontoken.ErrNotFound
	} else {
		return err
	}
}

func (store *SessionStore) RevokeAll(ctx context.Context, subjectID string, revokedAt time.Time) ([]sessiontoken.Record, error) {
	var records []sessiontoken.Record
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		cursor, err := store.adapter.collection(sessionsCollection).Find(tx, bson.M{"subject_id": subjectID})
		if err != nil {
			return err
		}
		defer cursor.Close(tx)
		var documents []sessionDocument
		if err = cursor.All(tx, &documents); err != nil {
			return err
		}
		if _, err = store.adapter.collection(sessionsCollection).UpdateMany(tx, bson.M{"subject_id": subjectID, "revoked_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"revoked_at": revokedAt}}); err != nil {
			return err
		}
		records = make([]sessiontoken.Record, len(documents))
		for index := range documents {
			if documents[index].RevokedAt == nil {
				documents[index].RevokedAt = &revokedAt
			}
			records[index] = documents[index].record()
		}
		return nil
	})
	return records, err
}

type accessSessionDocument struct {
	ID        string     `bson:"_id"`
	SubjectID string     `bson:"subject_id"`
	CreatedAt time.Time  `bson:"created_at"`
	ExpiresAt time.Time  `bson:"expires_at"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty"`
}

func (store *AccessSessionStore) Create(ctx context.Context, session authlier.AccessSession) error {
	_, err := store.adapter.collection(accessSessionsCollection).InsertOne(ctx, accessSessionDocument{session.ID, session.SubjectID, session.CreatedAt, session.ExpiresAt, session.RevokedAt})
	return err
}

func (store *AccessSessionStore) ResolveSession(ctx context.Context, sessionID string) (accesstoken.Session, error) {
	var document accessSessionDocument
	err := store.adapter.collection(accessSessionsCollection).FindOne(ctx, bson.M{
		"_id": sessionID, "revoked_at": bson.M{"$exists": false},
		"$expr": bson.M{"$gt": bson.A{"$expires_at", "$$NOW"}},
	}).Decode(&document)
	return accesstoken.Session{ID: document.ID, SubjectID: document.SubjectID}, err
}

func (store *AccessSessionStore) Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error {
	_, err := store.adapter.collection(accessSessionsCollection).UpdateOne(ctx, bson.M{"_id": sessionID, "revoked_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"revoked_at": revokedAt}})
	return err
}

type refreshTokenDocument struct {
	TokenHash []byte     `bson:"_id"`
	SessionID string     `bson:"session_id"`
	CreatedAt time.Time  `bson:"created_at"`
	ExpiresAt time.Time  `bson:"expires_at"`
	RotatedAt *time.Time `bson:"rotated_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty"`
}

func refreshDocumentFrom(record refreshtoken.Record) refreshTokenDocument {
	return refreshTokenDocument{record.TokenHash[:], record.SessionID, record.CreatedAt, record.ExpiresAt, record.RotatedAt, record.RevokedAt}
}

func (document refreshTokenDocument) record() refreshtoken.Record {
	var hash refreshtoken.TokenHash
	copy(hash[:], document.TokenHash)
	return refreshtoken.Record{SessionID: document.SessionID, TokenHash: hash, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt, RotatedAt: document.RotatedAt, RevokedAt: document.RevokedAt}
}

func (store *RefreshTokenStore) Create(ctx context.Context, record refreshtoken.Record) error {
	_, err := store.adapter.collection(refreshTokensCollection).InsertOne(ctx, refreshDocumentFrom(record))
	if duplicateKey(err) {
		return refreshtoken.ErrConflict
	}
	return err
}

func (store *RefreshTokenStore) FindByTokenHash(ctx context.Context, tokenHash refreshtoken.TokenHash) (refreshtoken.Record, error) {
	var document refreshTokenDocument
	err := store.adapter.collection(refreshTokensCollection).FindOne(ctx, bson.M{"_id": tokenHash[:]}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return refreshtoken.Record{}, refreshtoken.ErrNotFound
	}
	return document.record(), err
}

func (store *RefreshTokenStore) Rotate(ctx context.Context, current refreshtoken.TokenHash, replacement refreshtoken.Record, rotatedAt time.Time) error {
	reused := false
	err := store.adapter.transaction(ctx, func(tx context.Context) error {
		var document refreshTokenDocument
		if err := store.adapter.collection(refreshTokensCollection).FindOne(tx, bson.M{"_id": current[:]}).Decode(&document); errors.Is(err, mongo.ErrNoDocuments) {
			return refreshtoken.ErrNotFound
		} else if err != nil {
			return err
		}
		if document.RotatedAt != nil || document.RevokedAt != nil || !rotatedAt.Before(document.ExpiresAt) {
			reused = true
			return store.adapter.revokeAccessSession(tx, document.SessionID, rotatedAt)
		}
		if _, err := store.adapter.collection(refreshTokensCollection).InsertOne(tx, refreshDocumentFrom(replacement)); err != nil {
			if duplicateKey(err) {
				return refreshtoken.ErrConflict
			}
			return err
		}
		_, err := store.adapter.collection(refreshTokensCollection).UpdateOne(tx, bson.M{"_id": current[:], "rotated_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"rotated_at": rotatedAt}})
		return err
	})
	if err == nil && reused {
		return refreshtoken.ErrReuseDetected
	}
	return err
}

func (store *RefreshTokenStore) RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error {
	return store.adapter.transaction(ctx, func(tx context.Context) error {
		return store.adapter.revokeAccessSession(tx, sessionID, revokedAt)
	})
}

func (adapter *Adapter) revokeAccessSession(ctx context.Context, sessionID string, revokedAt time.Time) error {
	if _, err := adapter.collection(accessSessionsCollection).UpdateOne(ctx, bson.M{"_id": sessionID, "revoked_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"revoked_at": revokedAt}}); err != nil {
		return err
	}
	_, err := adapter.collection(refreshTokensCollection).UpdateMany(ctx, bson.M{"session_id": sessionID, "revoked_at": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"revoked_at": revokedAt}})
	return err
}

var _ sessiontoken.Store = (*SessionStore)(nil)
var _ refreshtoken.Store = (*RefreshTokenStore)(nil)
var _ authlier.AccessSessionStore = (*AccessSessionStore)(nil)
