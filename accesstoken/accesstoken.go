// Package accesstoken issues and verifies short-lived JWT access tokens.
package accesstoken

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/token"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

const maximumTokenLength = 8192

var (
	ErrInactiveSession = errors.New("access token session is inactive")
	ErrInvalidConfig   = errors.New("invalid access token configuration")
	ErrInvalidToken    = errors.New("invalid access token")
)

// Claims are the verified identity and session references in an access token.
type Claims struct {
	SessionID string `json:"sid"`
	jwtlib.RegisteredClaims
}

type Issued struct {
	Token     string
	ExpiresAt time.Time
}

type IssuerConfig struct {
	Issuer     string
	Audience   string
	Lifetime   time.Duration
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Now        func() time.Time
}

type Issuer struct {
	issuer     string
	audience   string
	lifetime   time.Duration
	keyID      string
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

func NewIssuer(config IssuerConfig) (*Issuer, error) {
	if strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.Audience) == "" ||
		strings.TrimSpace(config.KeyID) == "" || config.Lifetime <= 0 ||
		len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidConfig
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Issuer{
		issuer:     config.Issuer,
		audience:   config.Audience,
		lifetime:   config.Lifetime,
		keyID:      config.KeyID,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...),
		now:        now,
	}, nil
}

// Issue signs a JWT for an existing durable session.
func (issuer *Issuer) Issue(subjectID, sessionID string) (Issued, error) {
	return issuer.issue(subjectID, sessionID, time.Time{})
}

// IssueUntil signs an access token without allowing it to outlive maximumExpiry.
func (issuer *Issuer) IssueUntil(
	subjectID string,
	sessionID string,
	maximumExpiry time.Time,
) (Issued, error) {
	return issuer.issue(subjectID, sessionID, maximumExpiry)
}

func (issuer *Issuer) issue(subjectID, sessionID string, maximumExpiry time.Time) (Issued, error) {
	if strings.TrimSpace(subjectID) == "" || strings.TrimSpace(sessionID) == "" {
		return Issued{}, ErrInvalidToken
	}
	tokenID, _, err := token.Generate()
	if err != nil {
		return Issued{}, fmt.Errorf("generate access token ID: %w", err)
	}
	now := issuer.now().UTC().Truncate(time.Second)
	expiresAt := now.Add(issuer.lifetime)
	if !maximumExpiry.IsZero() && expiresAt.After(maximumExpiry) {
		expiresAt = maximumExpiry.UTC().Truncate(time.Second)
	}
	if !expiresAt.After(now) {
		return Issued{}, ErrInactiveSession
	}
	claims := Claims{
		SessionID: sessionID,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    issuer.issuer,
			Subject:   subjectID,
			Audience:  jwtlib.ClaimStrings{issuer.audience},
			ExpiresAt: jwtlib.NewNumericDate(expiresAt),
			NotBefore: jwtlib.NewNumericDate(now),
			IssuedAt:  jwtlib.NewNumericDate(now),
			ID:        tokenID,
		},
	}
	signed := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, claims)
	signed.Header["kid"] = issuer.keyID
	rawToken, err := signed.SignedString(issuer.privateKey)
	if err != nil {
		return Issued{}, fmt.Errorf("sign access token: %w", err)
	}
	return Issued{Token: rawToken, ExpiresAt: expiresAt}, nil
}

type Session struct {
	ID        string
	SubjectID string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (session Session) ActiveAt(at time.Time) bool {
	return at.Before(session.ExpiresAt)
}

// SessionResolver resolves an active durable session.
type SessionResolver interface {
	ResolveSession(ctx context.Context, sessionID string) (Session, error)
}

type VerifierConfig struct {
	Issuer     string
	Audience   string
	PublicKeys map[string]ed25519.PublicKey
	Leeway     time.Duration
	Now        func() time.Time
}

type Verifier struct {
	issuer     string
	audience   string
	publicKeys map[string]ed25519.PublicKey
	leeway     time.Duration
	now        func() time.Time
	resolver   SessionResolver
}

func NewVerifier(resolver SessionResolver, config VerifierConfig) (*Verifier, error) {
	if resolver == nil || strings.TrimSpace(config.Issuer) == "" ||
		strings.TrimSpace(config.Audience) == "" || len(config.PublicKeys) == 0 || config.Leeway < 0 {
		return nil, ErrInvalidConfig
	}
	publicKeys := make(map[string]ed25519.PublicKey, len(config.PublicKeys))
	for keyID, publicKey := range config.PublicKeys {
		if strings.TrimSpace(keyID) == "" || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidConfig
		}
		publicKeys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		issuer:     config.Issuer,
		audience:   config.Audience,
		publicKeys: publicKeys,
		leeway:     config.Leeway,
		now:        now,
		resolver:   resolver,
	}, nil
}

// Verify validates the JWT and its durable session.
func (verifier *Verifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	claims, _, err := verifier.VerifySession(ctx, rawToken)
	return claims, err
}

// VerifySession validates the token and returns its durable session.
func (verifier *Verifier) VerifySession(
	ctx context.Context,
	rawToken string,
) (Claims, Session, error) {
	if len(rawToken) == 0 || len(rawToken) > maximumTokenLength {
		return Claims{}, Session{}, ErrInvalidToken
	}
	claims := Claims{}
	parsed, err := jwtlib.ParseWithClaims(
		rawToken,
		&claims,
		func(parsedToken *jwtlib.Token) (any, error) {
			if parsedToken.Method != jwtlib.SigningMethodEdDSA {
				return nil, ErrInvalidToken
			}
			keyID, ok := parsedToken.Header["kid"].(string)
			if !ok {
				return nil, ErrInvalidToken
			}
			publicKey, exists := verifier.publicKeys[keyID]
			if !exists {
				return nil, ErrInvalidToken
			}
			return publicKey, nil
		},
		jwtlib.WithValidMethods([]string{jwtlib.SigningMethodEdDSA.Alg()}),
		jwtlib.WithIssuer(verifier.issuer),
		jwtlib.WithAudience(verifier.audience),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithIssuedAt(),
		jwtlib.WithLeeway(verifier.leeway),
		jwtlib.WithTimeFunc(verifier.now),
	)
	if err != nil || !parsed.Valid || strings.TrimSpace(claims.Subject) == "" ||
		strings.TrimSpace(claims.SessionID) == "" || strings.TrimSpace(claims.ID) == "" ||
		claims.IssuedAt == nil || claims.NotBefore == nil {
		return Claims{}, Session{}, ErrInvalidToken
	}

	activeSession, err := verifier.resolver.ResolveSession(ctx, claims.SessionID)
	if err != nil || activeSession.ID != claims.SessionID || activeSession.SubjectID != claims.Subject ||
		!activeSession.ActiveAt(verifier.now().UTC()) {
		return Claims{}, Session{}, ErrInactiveSession
	}
	return claims, activeSession, nil
}
