// Package authlier provides configurable authentication for Go applications.
package authlier

import (
	"context"
	"time"

	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/passkey"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/saml"
	"github.com/Rahmannugar/authlier/sessiontoken"
	"github.com/Rahmannugar/authlier/totp"
)

type EmailPasswordStore interface {
	emailpassword.Store
	emailpassword.CredentialStore
}

type GoogleStore interface {
	googleoauth.Store
	googleoauth.IdentityStore
}

type AccessSession struct {
	ID        string
	SubjectID string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

type AccessSessionStore interface {
	accesstoken.SessionResolver
	Create(ctx context.Context, session AccessSession) error
	Revoke(ctx context.Context, sessionID string, revokedAt time.Time) error
}

type Stores struct {
	EmailPassword     EmailPasswordStore
	EmailVerification emailverification.Store
	Google            GoogleStore
	OIDC              oidc.Store
	Passkeys          passkey.Store
	PasswordReset     passwordreset.Store
	RefreshTokens     refreshtoken.Store
	SAML              saml.Store
	Sessions          sessiontoken.Store
	TOTP              totp.Store
	AccessSessions    AccessSessionStore
}

type Database interface {
	Migrate(ctx context.Context) error
	Stores() Stores
}
