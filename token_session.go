package authlier

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/token"
	"github.com/google/uuid"
)

type Session struct {
	ID        string
	SubjectID string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type bearerSessionManager struct {
	store           AccessSessionStore
	issuer          *accesstoken.Issuer
	verifier        *accesstoken.Verifier
	refreshTokens   *refreshtoken.Manager
	refreshLifetime time.Duration
	now             func() time.Time
}

type bearerSessionIssued struct {
	Session               Session
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

func newBearerSessionManager(
	store AccessSessionStore,
	refreshStore refreshtoken.Store,
	config BearerSessionConfig,
) (*bearerSessionManager, error) {
	if config.RefreshTokenLifetime <= config.AccessTokenLifetime {
		return nil, fmt.Errorf(
			"%w: refresh token lifetime must exceed access token lifetime",
			ErrInvalidConfig,
		)
	}
	publicKeys := make(map[string]ed25519.PublicKey, len(config.PublicKeys)+1)
	for keyID, publicKey := range config.PublicKeys {
		publicKeys[keyID] = publicKey
	}
	if len(config.PrivateKey) == ed25519.PrivateKeySize && strings.TrimSpace(config.KeyID) != "" {
		publicKey, ok := config.PrivateKey.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: invalid bearer signing key", ErrInvalidConfig)
		}
		publicKeys[config.KeyID] = publicKey
	}
	issuer, err := accesstoken.NewIssuer(accesstoken.IssuerConfig{
		Issuer: config.Issuer, Audience: config.Audience,
		Lifetime: config.AccessTokenLifetime, KeyID: config.KeyID, PrivateKey: config.PrivateKey,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bearer token issuer", ErrInvalidConfig)
	}
	verifier, err := accesstoken.NewVerifier(store, accesstoken.VerifierConfig{
		Issuer: config.Issuer, Audience: config.Audience,
		PublicKeys: publicKeys, Leeway: config.Leeway,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bearer token verifier", ErrInvalidConfig)
	}
	refreshTokens, err := refreshtoken.NewManager(refreshStore, refreshtoken.Config{
		Lifetime: config.RefreshTokenLifetime,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: invalid refresh token configuration", ErrInvalidConfig)
	}
	return &bearerSessionManager{
		store: store, issuer: issuer, verifier: verifier, refreshTokens: refreshTokens,
		refreshLifetime: config.RefreshTokenLifetime, now: time.Now,
	}, nil
}

func (manager *bearerSessionManager) Create(
	ctx context.Context,
	subjectID string,
) (bearerSessionIssued, error) {
	if strings.TrimSpace(subjectID) == "" {
		return bearerSessionIssued{}, fmt.Errorf("create bearer session: subject ID is required")
	}
	sessionID, err := uuid.NewV7()
	if err != nil {
		return bearerSessionIssued{}, fmt.Errorf("generate bearer session ID: %w", err)
	}
	now := manager.now().UTC().Truncate(time.Second)
	session := AccessSession{
		ID: sessionID.String(), SubjectID: subjectID,
		CreatedAt: now, ExpiresAt: now.Add(manager.refreshLifetime),
	}
	rawRefreshToken, refreshHash, err := token.Generate()
	if err != nil {
		return bearerSessionIssued{}, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshRecord := refreshtoken.Record{
		SessionID: session.ID, TokenHash: refreshHash,
		CreatedAt: now, ExpiresAt: session.ExpiresAt,
	}
	accessToken, err := manager.issuer.IssueUntil(subjectID, session.ID, session.ExpiresAt)
	if err != nil {
		return bearerSessionIssued{}, fmt.Errorf("issue access token: %w", err)
	}
	if err := manager.store.CreateSession(ctx, session, refreshRecord); err != nil {
		return bearerSessionIssued{}, fmt.Errorf("create bearer session: %w", err)
	}
	return bearerSessionIssued{
		Session: Session{
			ID: session.ID, SubjectID: session.SubjectID,
			CreatedAt: session.CreatedAt, ExpiresAt: session.ExpiresAt,
		},
		AccessToken: accessToken.Token, AccessTokenExpiresAt: accessToken.ExpiresAt,
		RefreshToken: rawRefreshToken, RefreshTokenExpiresAt: refreshRecord.ExpiresAt,
	}, nil
}

func (manager *bearerSessionManager) Refresh(
	ctx context.Context,
	rawRefreshToken string,
) (bearerSessionIssued, error) {
	current, err := manager.refreshTokens.Resolve(ctx, rawRefreshToken)
	if err != nil {
		if errors.Is(err, refreshtoken.ErrInactive) {
			_, rotationErr := manager.refreshTokens.Rotate(ctx, rawRefreshToken)
			if rotationErr != nil {
				return bearerSessionIssued{}, rotationErr
			}
		}
		return bearerSessionIssued{}, err
	}
	durable, err := manager.store.ResolveSession(ctx, current.SessionID)
	if err != nil || durable.ID != current.SessionID || !durable.ActiveAt(manager.now().UTC()) {
		return bearerSessionIssued{}, accesstoken.ErrInactiveSession
	}
	accessToken, err := manager.issuer.IssueUntil(
		durable.SubjectID,
		durable.ID,
		durable.ExpiresAt,
	)
	if err != nil {
		return bearerSessionIssued{}, err
	}
	replacement, err := manager.refreshTokens.Rotate(ctx, rawRefreshToken)
	if err != nil {
		return bearerSessionIssued{}, err
	}
	return bearerSessionIssued{
		Session: Session{
			ID: durable.ID, SubjectID: durable.SubjectID,
			CreatedAt: durable.CreatedAt, ExpiresAt: durable.ExpiresAt,
		},
		AccessToken: accessToken.Token, AccessTokenExpiresAt: accessToken.ExpiresAt,
		RefreshToken: replacement.Token, RefreshTokenExpiresAt: replacement.Record.ExpiresAt,
	}, nil
}

func (manager *bearerSessionManager) Resolve(
	ctx context.Context,
	rawAccessToken string,
) (Session, error) {
	_, durable, err := manager.verifier.VerifySession(ctx, rawAccessToken)
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID: durable.ID, SubjectID: durable.SubjectID,
		CreatedAt: durable.CreatedAt, ExpiresAt: durable.ExpiresAt,
	}, nil
}

func (manager *bearerSessionManager) List(
	ctx context.Context,
	subjectID string,
) ([]Session, error) {
	records, err := manager.store.ListBySubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(records))
	now := manager.now().UTC()
	for _, record := range records {
		if record.RevokedAt != nil || !now.Before(record.ExpiresAt) {
			continue
		}
		sessions = append(sessions, Session{
			ID: record.ID, SubjectID: record.SubjectID,
			CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
		})
	}
	return sessions, nil
}

func (manager *bearerSessionManager) Revoke(ctx context.Context, sessionID string) error {
	return manager.refreshTokens.RevokeSessionID(ctx, sessionID)
}

func (manager *bearerSessionManager) RevokeByRefreshToken(
	ctx context.Context,
	rawRefreshToken string,
) error {
	return manager.refreshTokens.RevokeSession(ctx, rawRefreshToken)
}

func (manager *bearerSessionManager) RevokeByID(
	ctx context.Context,
	subjectID string,
	sessionID string,
) error {
	records, err := manager.store.ListBySubject(ctx, subjectID)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.ID == sessionID {
			return manager.Revoke(ctx, sessionID)
		}
	}
	return refreshtoken.ErrNotFound
}

func (manager *bearerSessionManager) RevokeAll(ctx context.Context, subjectID string) error {
	return manager.store.RevokeAll(ctx, subjectID, manager.now().UTC())
}
