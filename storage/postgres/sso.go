package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/saml"
	"github.com/jackc/pgx/v5"
)

type OIDCStore struct{ adapter *Adapter }
type SAMLStore struct{ adapter *Adapter }

func (adapter *Adapter) OIDC() *OIDCStore { return &OIDCStore{adapter: adapter} }
func (adapter *Adapter) SAML() *SAMLStore { return &SAMLStore{adapter: adapter} }

func (store *OIDCStore) CreateChallenge(ctx context.Context, challenge oidc.Challenge) error {
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_oidc_challenges
		(state_hash, connection_id, issuer, client_id, redirect_url, scopes,
		require_verified_email, nonce, code_verifier, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		challenge.StateHash[:], challenge.ConnectionID, challenge.Issuer, challenge.ClientID,
		challenge.RedirectURL, challenge.Scopes, challenge.RequireVerifiedEmail,
		challenge.Nonce, challenge.CodeVerifier, challenge.CreatedAt, challenge.ExpiresAt)
	if uniqueViolation(err) {
		return oidc.ErrConflict
	}
	return err
}

func (store *OIDCStore) ConsumeChallenge(
	ctx context.Context,
	stateHash oidc.StateHash,
	consumedAt time.Time,
) (oidc.Challenge, error) {
	var challenge oidc.Challenge
	var storedHash []byte
	err := store.adapter.pool.QueryRow(ctx, `DELETE FROM authlier_oidc_challenges
		WHERE state_hash = $1 RETURNING state_hash, connection_id, issuer, client_id,
		redirect_url, scopes, require_verified_email, nonce, code_verifier, created_at, expires_at`,
		stateHash[:],
	).Scan(&storedHash, &challenge.ConnectionID, &challenge.Issuer, &challenge.ClientID,
		&challenge.RedirectURL, &challenge.Scopes, &challenge.RequireVerifiedEmail,
		&challenge.Nonce, &challenge.CodeVerifier, &challenge.CreatedAt, &challenge.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return challenge, oidc.ErrNotFound
	}
	if err != nil {
		return challenge, err
	}
	copy(challenge.StateHash[:], storedHash)
	if !consumedAt.Before(challenge.ExpiresAt) {
		return challenge, oidc.ErrInactiveState
	}
	return challenge, nil
}

func (store *SAMLStore) CreateRequest(ctx context.Context, request saml.Request) error {
	_, err := store.adapter.pool.Exec(ctx, `INSERT INTO authlier_saml_requests
		(state_hash, connection_id, connection_hash, request_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, request.StateHash[:], request.ConnectionID,
		request.ConnectionHash[:], request.RequestID, request.CreatedAt, request.ExpiresAt)
	if uniqueViolation(err) {
		return saml.ErrConflict
	}
	return err
}

func (store *SAMLStore) ConsumeRequest(
	ctx context.Context,
	stateHash saml.StateHash,
	consumedAt time.Time,
) (saml.Request, error) {
	var request saml.Request
	var storedState, connectionHash []byte
	err := store.adapter.pool.QueryRow(ctx, `DELETE FROM authlier_saml_requests
		WHERE state_hash = $1 RETURNING state_hash, connection_id, connection_hash,
		request_id, created_at, expires_at`, stateHash[:],
	).Scan(&storedState, &request.ConnectionID, &connectionHash, &request.RequestID,
		&request.CreatedAt, &request.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return request, saml.ErrNotFound
	}
	if err != nil {
		return request, err
	}
	copy(request.StateHash[:], storedState)
	copy(request.ConnectionHash[:], connectionHash)
	if !consumedAt.Before(request.ExpiresAt) {
		return request, saml.ErrInactiveRequest
	}
	return request, nil
}

var _ oidc.Store = (*OIDCStore)(nil)
var _ saml.Store = (*SAMLStore)(nil)
