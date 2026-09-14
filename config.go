package authlier

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/passkey"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/Rahmannugar/authlier/saml"
	"github.com/Rahmannugar/authlier/sessiontoken"
	"github.com/Rahmannugar/authlier/totp"
)

type SessionMode string

const (
	SessionModeCookie SessionMode = "cookie"
	SessionModeBearer SessionMode = "bearer"
)

type EmailAndPasswordConfig struct {
	Enabled                  bool
	RequireEmailVerification bool
	ValidatePassword         emailpassword.PasswordValidator
	AttemptGuard             emailpassword.AttemptGuard
	SecurityEvents           emailpassword.SecurityEventSink
}

type EmailVerificationConfig struct {
	Enabled                     bool
	Lifetime                    time.Duration
	VerificationURL             string
	Sender                      emailverification.Sender
	SendOnSignUp                bool
	SendOnSignIn                bool
	AutoSignInAfterVerification bool
	AttemptGuard                emailverification.AttemptGuard
	SecurityEvents              emailverification.SecurityEventSink
}

type PasswordResetConfig struct {
	Enabled                bool
	Lifetime               time.Duration
	ResetURL               string
	Sender                 passwordreset.Sender
	KeepSessionsAfterReset bool
	AttemptGuard           passwordreset.AttemptGuard
	SecurityEvents         passwordreset.SecurityEventSink
}

type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	SameSite http.SameSite
}

type SessionConfig struct {
	Mode      SessionMode
	Lifetime  time.Duration
	FreshAge  time.Duration
	Cache     sessiontoken.Cache
	CacheTTL  time.Duration
	Extension *sessiontoken.ExtensionConfig
	Cookie    CookieConfig
	Bearer    BearerSessionConfig
}

type BearerSessionConfig struct {
	Issuer               string
	Audience             string
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	KeyID                string
	PrivateKey           ed25519.PrivateKey
	PublicKeys           map[string]ed25519.PublicKey
	Leeway               time.Duration
}

type TOTPConfig struct {
	Enabled            bool
	EnrollmentLifetime time.Duration
	ChallengeLifetime  time.Duration
	RecoveryCodeCount  int
	AttemptGuard       totp.AttemptGuard
	SecurityEvents     totp.SecurityEventSink
}

type PasskeyConfig struct {
	Enabled          bool
	RelyingPartyID   string
	RelyingPartyName string
	Origins          []string
	CeremonyLifetime time.Duration
	AttemptGuard     passkey.AttemptGuard
	SecurityEvents   passkey.SecurityEventSink
}

type GoogleConfig struct {
	Enabled            bool
	ClientID           string
	ClientSecret       string
	RedirectURL        string
	SuccessRedirectURL string
	StateLifetime      time.Duration
	HTTPClient         *http.Client
	Provider           googleoauth.Provider
	SecurityEvents     googleoauth.SecurityEventSink
}

type OIDCIdentityResolver func(context.Context, oidc.Identity) (string, error)

type OIDCConfig struct {
	Enabled            bool
	Connections        oidc.ConnectionSource
	ResolveIdentity    OIDCIdentityResolver
	StateLifetime      time.Duration
	HTTPClient         *http.Client
	SuccessRedirectURL string
	AttemptGuard       oidc.AttemptGuard
	SecurityEvents     oidc.SecurityEventSink
}

type SAMLIdentityResolver func(context.Context, saml.Identity) (string, error)

type SAMLConfig struct {
	Enabled            bool
	Connections        saml.ConnectionSource
	ResolveIdentity    SAMLIdentityResolver
	RequestLifetime    time.Duration
	SuccessRedirectURL string
	AttemptGuard       saml.AttemptGuard
	SecurityEvents     saml.SecurityEventSink
}

type Config struct {
	AppName           string
	BaseURL           string
	BasePath          string
	Database          Database
	TrustedOrigins    []string
	TrustedProxies    []string
	EmailAndPassword  EmailAndPasswordConfig
	EmailVerification EmailVerificationConfig
	PasswordReset     PasswordResetConfig
	Session           SessionConfig
	TOTP              TOTPConfig
	Passkeys          PasskeyConfig
	Google            GoogleConfig
	OIDC              OIDCConfig
	SAML              SAMLConfig
}
