package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/saml"
)

type OIDCStore struct{ adapter *Adapter }
type SAMLStore struct{ adapter *Adapter }

func (adapter *Adapter) OIDC() *OIDCStore { return &OIDCStore{adapter: adapter} }
func (adapter *Adapter) SAML() *SAMLStore { return &SAMLStore{adapter: adapter} }

func (store *OIDCStore) CreateChallenge(ctx context.Context, challenge oidc.Challenge) error {
	scopes, err := json.Marshal(challenge.Scopes)
	if err != nil {
		return err
	}
	_, err = store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_oidc_challenges
		(state_hash, connection_id, issuer, client_id, redirect_url, scopes,
		require_verified_email, nonce, code_verifier, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		challenge.StateHash[:], challenge.ConnectionID, challenge.Issuer, challenge.ClientID,
		challenge.RedirectURL, scopes, challenge.RequireVerifiedEmail,
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
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return oidc.Challenge{}, err
	}
	defer tx.Rollback()
	var challenge oidc.Challenge
	var storedHash, scopes []byte
	err = tx.QueryRowContext(ctx, `SELECT state_hash, connection_id, issuer, client_id,
		redirect_url, scopes, require_verified_email, nonce, code_verifier, created_at, expires_at
		FROM authlier_oidc_challenges WHERE state_hash = ? FOR UPDATE`,
		stateHash[:],
	).Scan(&storedHash, &challenge.ConnectionID, &challenge.Issuer, &challenge.ClientID,
		&challenge.RedirectURL, &scopes, &challenge.RequireVerifiedEmail,
		&challenge.Nonce, &challenge.CodeVerifier, &challenge.CreatedAt, &challenge.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return challenge, oidc.ErrNotFound
	}
	if err != nil {
		return challenge, err
	}
	if err := json.Unmarshal(scopes, &challenge.Scopes); err != nil {
		return challenge, err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM authlier_oidc_challenges WHERE state_hash = ?", stateHash[:]); err != nil {
		return challenge, err
	}
	if err := tx.Commit(); err != nil {
		return challenge, err
	}
	copy(challenge.StateHash[:], storedHash)
	if !consumedAt.Before(challenge.ExpiresAt) {
		return challenge, oidc.ErrInactiveState
	}
	return challenge, nil
}

func (store *SAMLStore) CreateRequest(ctx context.Context, request saml.Request) error {
	_, err := store.adapter.database.ExecContext(ctx, `INSERT INTO authlier_saml_requests
		(state_hash, connection_id, connection_hash, request_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, request.StateHash[:], request.ConnectionID,
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
	tx, err := store.adapter.database.BeginTx(ctx, nil)
	if err != nil {
		return saml.Request{}, err
	}
	defer tx.Rollback()
	var request saml.Request
	var storedState, connectionHash []byte
	err = tx.QueryRowContext(ctx, `SELECT state_hash, connection_id, connection_hash,
		request_id, created_at, expires_at FROM authlier_saml_requests
		WHERE state_hash = ? FOR UPDATE`, stateHash[:],
	).Scan(&storedState, &request.ConnectionID, &connectionHash, &request.RequestID,
		&request.CreatedAt, &request.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return request, saml.ErrNotFound
	}
	if err != nil {
		return request, err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM authlier_saml_requests WHERE state_hash = ?", stateHash[:]); err != nil {
		return request, err
	}
	if err := tx.Commit(); err != nil {
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
