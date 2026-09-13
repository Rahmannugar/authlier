package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/saml"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type OIDCStore struct{ adapter *Adapter }
type SAMLStore struct{ adapter *Adapter }

func (adapter *Adapter) OIDC() *OIDCStore { return &OIDCStore{adapter} }
func (adapter *Adapter) SAML() *SAMLStore { return &SAMLStore{adapter} }

type oidcChallengeDocument struct {
	StateHash            []byte    `bson:"_id"`
	ConnectionID         string    `bson:"connection_id"`
	Issuer               string    `bson:"issuer"`
	ClientID             string    `bson:"client_id"`
	RedirectURL          string    `bson:"redirect_url"`
	Scopes               []string  `bson:"scopes"`
	RequireVerifiedEmail bool      `bson:"require_verified_email"`
	Nonce                string    `bson:"nonce"`
	CodeVerifier         string    `bson:"code_verifier"`
	CreatedAt            time.Time `bson:"created_at"`
	ExpiresAt            time.Time `bson:"expires_at"`
}

func (store *OIDCStore) CreateChallenge(ctx context.Context, challenge oidc.Challenge) error {
	_, err := store.adapter.collection(oidcChallengesCollection).InsertOne(ctx, oidcChallengeDocument{
		challenge.StateHash[:], challenge.ConnectionID, challenge.Issuer, challenge.ClientID,
		challenge.RedirectURL, challenge.Scopes, challenge.RequireVerifiedEmail, challenge.Nonce,
		challenge.CodeVerifier, challenge.CreatedAt, challenge.ExpiresAt,
	})
	if duplicateKey(err) {
		return oidc.ErrConflict
	}
	return err
}

func (store *OIDCStore) ConsumeChallenge(ctx context.Context, stateHash oidc.StateHash, consumedAt time.Time) (oidc.Challenge, error) {
	var document oidcChallengeDocument
	err := store.adapter.collection(oidcChallengesCollection).FindOneAndDelete(ctx, bson.M{"_id": stateHash[:]}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return oidc.Challenge{}, oidc.ErrNotFound
	}
	var stored oidc.StateHash
	copy(stored[:], document.StateHash)
	challenge := oidc.Challenge{StateHash: stored, ConnectionID: document.ConnectionID, Issuer: document.Issuer, ClientID: document.ClientID, RedirectURL: document.RedirectURL, Scopes: document.Scopes, RequireVerifiedEmail: document.RequireVerifiedEmail, Nonce: document.Nonce, CodeVerifier: document.CodeVerifier, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt}
	if err == nil && !consumedAt.Before(challenge.ExpiresAt) {
		return challenge, oidc.ErrInactiveState
	}
	return challenge, err
}

type samlRequestDocument struct {
	StateHash      []byte    `bson:"_id"`
	ConnectionID   string    `bson:"connection_id"`
	ConnectionHash []byte    `bson:"connection_hash"`
	RequestID      string    `bson:"request_id"`
	CreatedAt      time.Time `bson:"created_at"`
	ExpiresAt      time.Time `bson:"expires_at"`
}

func (store *SAMLStore) CreateRequest(ctx context.Context, request saml.Request) error {
	_, err := store.adapter.collection(samlRequestsCollection).InsertOne(ctx, samlRequestDocument{
		request.StateHash[:], request.ConnectionID, request.ConnectionHash[:], request.RequestID, request.CreatedAt, request.ExpiresAt,
	})
	if duplicateKey(err) {
		return saml.ErrConflict
	}
	return err
}

func (store *SAMLStore) ConsumeRequest(ctx context.Context, stateHash saml.StateHash, consumedAt time.Time) (saml.Request, error) {
	var document samlRequestDocument
	err := store.adapter.collection(samlRequestsCollection).FindOneAndDelete(ctx, bson.M{"_id": stateHash[:]}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return saml.Request{}, saml.ErrNotFound
	}
	var stored saml.StateHash
	var connectionHash [32]byte
	copy(stored[:], document.StateHash)
	copy(connectionHash[:], document.ConnectionHash)
	request := saml.Request{StateHash: stored, ConnectionID: document.ConnectionID, ConnectionHash: connectionHash, RequestID: document.RequestID, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt}
	if err == nil && !consumedAt.Before(request.ExpiresAt) {
		return request, saml.ErrInactiveRequest
	}
	return request, err
}

var _ oidc.Store = (*OIDCStore)(nil)
var _ saml.Store = (*SAMLStore)(nil)
