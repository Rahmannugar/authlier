package accesstoken_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/accesstoken"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestAccessTokenRequiresAValidDurableSession(t *testing.T) {
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	issuer, err := accesstoken.NewIssuer(accesstoken.IssuerConfig{
		Issuer: "https://auth.example.com", Audience: "example-api",
		Lifetime: 5 * time.Minute, KeyID: "current", PrivateKey: privateKey,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	resolver := &sessionResolver{session: accesstoken.Session{
		ID: "session_123", SubjectID: "user_123", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}}
	verifier, err := accesstoken.NewVerifier(resolver, accesstoken.VerifierConfig{
		Issuer: "https://auth.example.com", Audience: "example-api",
		PublicKeys: map[string]ed25519.PublicKey{"current": publicKey},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	issued, err := issuer.Issue("user_123", "session_123")
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	claims, err := verifier.Verify(context.Background(), issued.Token)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Subject != "user_123" || claims.SessionID != "session_123" {
		t.Fatalf("unexpected claims: subject=%q session=%q", claims.Subject, claims.SessionID)
	}

	resolver.err = errors.New("revoked")
	if _, err := verifier.Verify(context.Background(), issued.Token); !errors.Is(err, accesstoken.ErrInactiveSession) {
		t.Fatalf("verify revoked session: got %v, want inactive session", err)
	}
}

func TestAccessTokenRejectsInvalidSignatureAndExpiry(t *testing.T) {
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	issuer, err := accesstoken.NewIssuer(accesstoken.IssuerConfig{
		Issuer: "issuer", Audience: "audience", Lifetime: time.Minute,
		KeyID: "key-1", PrivateKey: privateKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	resolver := &sessionResolver{session: accesstoken.Session{
		ID: "session", SubjectID: "user", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}}
	verifier, err := accesstoken.NewVerifier(resolver, accesstoken.VerifierConfig{
		Issuer: "issuer", Audience: "audience",
		PublicKeys: map[string]ed25519.PublicKey{"key-1": publicKey},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	issued, err := issuer.Issue("user", "session")
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}

	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate untrusted signing key: %v", err)
	}
	untrustedIssuer, err := accesstoken.NewIssuer(accesstoken.IssuerConfig{
		Issuer: "issuer", Audience: "audience", Lifetime: time.Minute,
		KeyID: "key-1", PrivateKey: otherPrivateKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create untrusted issuer: %v", err)
	}
	untrusted, err := untrustedIssuer.Issue("user", "session")
	if err != nil {
		t.Fatalf("issue token with untrusted key: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), untrusted.Token); !errors.Is(err, accesstoken.ErrInvalidToken) {
		t.Fatalf("verify invalid signature: got %v, want invalid token", err)
	}
	missingTimes := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, accesstoken.Claims{
		SessionID: "session",
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "user",
			Audience:  jwtlib.ClaimStrings{"audience"},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(time.Minute)),
			ID:        "token-id",
		},
	})
	missingTimes.Header["kid"] = "key-1"
	missingTimesToken, err := missingTimes.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token without required time claims: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), missingTimesToken); !errors.Is(err, accesstoken.ErrInvalidToken) {
		t.Fatalf("verify missing time claims: got %v, want invalid token", err)
	}
	now = issued.ExpiresAt
	if _, err := verifier.Verify(context.Background(), issued.Token); !errors.Is(err, accesstoken.ErrInvalidToken) {
		t.Fatalf("verify expired token: got %v, want invalid token", err)
	}
}

func TestAccessTokenDoesNotOutliveDurableSession(t *testing.T) {
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	issuer, err := accesstoken.NewIssuer(accesstoken.IssuerConfig{
		Issuer: "issuer", Audience: "audience", Lifetime: 15 * time.Minute,
		KeyID: "current", PrivateKey: privateKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}

	maximumExpiry := now.Add(2 * time.Minute)
	issued, err := issuer.IssueUntil("user", "session", maximumExpiry)
	if err != nil {
		t.Fatalf("issue capped access token: %v", err)
	}
	if !issued.ExpiresAt.Equal(maximumExpiry) {
		t.Fatalf("expiry=%s want %s", issued.ExpiresAt, maximumExpiry)
	}
	if _, err := issuer.IssueUntil("user", "session", now); !errors.Is(err, accesstoken.ErrInactiveSession) {
		t.Fatalf("issue for expired session: got %v, want inactive session", err)
	}
}

type sessionResolver struct {
	session accesstoken.Session
	err     error
}

func (resolver *sessionResolver) ResolveSession(_ context.Context, _ string) (accesstoken.Session, error) {
	return resolver.session, resolver.err
}
