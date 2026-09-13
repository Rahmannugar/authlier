package authlier

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

var ErrInvalidConfig = errors.New("invalid Authlier configuration")

type Auth struct {
	handler                       http.Handler
	password                      *emailpassword.Manager
	emailVerification             *emailverification.Manager
	passwordReset                 *passwordreset.Manager
	passkeys                      *passkey.Manager
	google                        *googleoauth.Manager
	oidc                          *oidc.Manager
	saml                          *saml.Manager
	sessions                      *sessiontoken.Manager
	totp                          *totp.Manager
	sessionFreshAge               time.Duration
	requireEmailVerification      bool
	sendVerificationOnSignUp      bool
	sendVerificationOnSignIn      bool
	autoSignInAfterVerification   bool
	revokeSessionsOnPasswordReset bool
	googleSuccessRedirectURL      string
	oidcSuccessRedirectURL        string
	samlSuccessRedirectURL        string
	resolveOIDCIdentity           OIDCIdentityResolver
	resolveSAMLIdentity           SAMLIdentityResolver
	cookieName                    string
}

func New(config Config) (*Auth, error) {
	if strings.TrimSpace(config.AppName) == "" || config.Database == nil {
		return nil, fmt.Errorf("%w: app name and database are required", ErrInvalidConfig)
	}
	baseURL, err := url.Parse(strings.TrimSpace(config.BaseURL))
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "https" && baseURL.Scheme != "http") ||
		baseURL.User != nil || baseURL.Path != "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("%w: valid base URL is required", ErrInvalidConfig)
	}
	if !config.EmailAndPassword.Enabled && !config.Google.Enabled && !config.Passkeys.Enabled &&
		!config.OIDC.Enabled && !config.SAML.Enabled {
		return nil, fmt.Errorf("%w: enable at least one sign-in method", ErrInvalidConfig)
	}
	if config.EmailAndPassword.RequireEmailVerification && !config.EmailVerification.Enabled {
		return nil, fmt.Errorf("%w: required email verification must be enabled", ErrInvalidConfig)
	}
	if config.PasswordReset.Enabled && !config.EmailAndPassword.Enabled {
		return nil, fmt.Errorf("%w: password reset requires email and password authentication", ErrInvalidConfig)
	}
	basePath := strings.TrimSpace(config.BasePath)
	if basePath == "" {
		basePath = "/api/auth"
	}
	if !strings.HasPrefix(basePath, "/") || strings.HasSuffix(basePath, "/") {
		return nil, fmt.Errorf("%w: base path must start but not end with a slash", ErrInvalidConfig)
	}
	if config.Session.Lifetime <= 0 {
		return nil, fmt.Errorf("%w: session lifetime must be positive", ErrInvalidConfig)
	}
	freshAge := config.Session.FreshAge
	if freshAge <= 0 {
		freshAge = 15 * time.Minute
	}
	stores := config.Database.Stores()
	if stores.Sessions == nil {
		return nil, fmt.Errorf("%w: database does not provide session storage", ErrInvalidConfig)
	}
	var passwords *emailpassword.Manager
	if config.EmailAndPassword.Enabled {
		if stores.EmailPassword == nil {
			return nil, fmt.Errorf("%w: database does not provide password storage", ErrInvalidConfig)
		}
		passwords, err = emailpassword.NewManager(stores.EmailPassword, emailpassword.Config{
			Credentials:      stores.EmailPassword,
			ValidatePassword: config.EmailAndPassword.ValidatePassword,
			AttemptGuard:     config.EmailAndPassword.AttemptGuard,
			SecurityEvents:   config.EmailAndPassword.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
	}
	sessions, err := sessiontoken.NewManager(stores.Sessions, config.Session.Cache, sessiontoken.Config{
		Lifetime:  config.Session.Lifetime,
		CacheTTL:  config.Session.CacheTTL,
		Extension: config.Session.Extension,
	})
	if err != nil {
		return nil, err
	}
	auth := &Auth{
		password:                      passwords,
		sessions:                      sessions,
		sessionFreshAge:               freshAge,
		requireEmailVerification:      config.EmailAndPassword.RequireEmailVerification,
		sendVerificationOnSignUp:      config.EmailVerification.SendOnSignUp,
		sendVerificationOnSignIn:      config.EmailVerification.SendOnSignIn,
		autoSignInAfterVerification:   config.EmailVerification.AutoSignInAfterVerification,
		revokeSessionsOnPasswordReset: config.PasswordReset.RevokeSessionsOnPasswordReset,
	}
	if config.TOTP.Enabled {
		if stores.TOTP == nil {
			return nil, fmt.Errorf("%w: database does not provide TOTP storage", ErrInvalidConfig)
		}
		auth.totp, err = totp.NewManager(stores.TOTP, totp.Config{
			Issuer:             config.AppName,
			EnrollmentLifetime: config.TOTP.EnrollmentLifetime,
			ChallengeLifetime:  config.TOTP.ChallengeLifetime,
			RecoveryCodeCount:  config.TOTP.RecoveryCodeCount,
			AttemptGuard:       config.TOTP.AttemptGuard,
			SecurityEvents:     config.TOTP.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
	}
	if config.Passkeys.Enabled {
		if stores.Passkeys == nil {
			return nil, fmt.Errorf("%w: database does not provide passkey storage", ErrInvalidConfig)
		}
		relyingPartyID := strings.TrimSpace(config.Passkeys.RelyingPartyID)
		if relyingPartyID == "" {
			relyingPartyID = baseURL.Hostname()
		}
		relyingPartyName := strings.TrimSpace(config.Passkeys.RelyingPartyName)
		if relyingPartyName == "" {
			relyingPartyName = config.AppName
		}
		origins := append([]string(nil), config.Passkeys.Origins...)
		if len(origins) == 0 {
			origins = []string{baseURL.Scheme + "://" + baseURL.Host}
			origins = append(origins, config.TrustedOrigins...)
		}
		auth.passkeys, err = passkey.NewManager(stores.Passkeys, passkey.Config{
			RelyingPartyID:   relyingPartyID,
			RelyingPartyName: relyingPartyName,
			Origins:          origins,
			CeremonyLifetime: config.Passkeys.CeremonyLifetime,
			AttemptGuard:     config.Passkeys.AttemptGuard,
			SecurityEvents:   config.Passkeys.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
	}
	if config.Google.Enabled {
		if stores.Google == nil {
			return nil, fmt.Errorf("%w: database does not provide Google OAuth storage", ErrInvalidConfig)
		}
		provider := config.Google.Provider
		if provider == nil {
			provider, err = googleoauth.NewGoogleProvider(googleoauth.GoogleProviderConfig{
				ClientID:     config.Google.ClientID,
				ClientSecret: config.Google.ClientSecret,
				HTTPClient:   config.Google.HTTPClient,
			})
			if err != nil {
				return nil, err
			}
		}
		redirectURL := strings.TrimSpace(config.Google.RedirectURL)
		if redirectURL == "" {
			redirectURL = baseURL.Scheme + "://" + baseURL.Host + basePath + "/callback/google"
		}
		auth.google, err = googleoauth.NewManager(stores.Google, provider, googleoauth.Config{
			ClientID:         config.Google.ClientID,
			AuthorizationURL: googleoauth.AuthorizationEndpoint,
			RedirectURL:      redirectURL,
			StateLifetime:    config.Google.StateLifetime,
			Identities:       stores.Google,
			SecurityEvents:   config.Google.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
		auth.googleSuccessRedirectURL, err = parseSuccessRedirectURL(config.Google.SuccessRedirectURL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid Google success redirect URL", ErrInvalidConfig)
		}
	}
	if config.OIDC.Enabled {
		if stores.OIDC == nil || config.OIDC.Connections == nil || config.OIDC.ResolveIdentity == nil {
			return nil, fmt.Errorf("%w: OIDC storage, connections, and identity resolver are required", ErrInvalidConfig)
		}
		httpClient := config.OIDC.HTTPClient
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		auth.oidc, err = oidc.NewManager(stores.OIDC, config.OIDC.Connections, oidc.Config{
			StateLifetime:  config.OIDC.StateLifetime,
			HTTPClient:     httpClient,
			AttemptGuard:   config.OIDC.AttemptGuard,
			SecurityEvents: config.OIDC.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
		auth.oidcSuccessRedirectURL, err = parseSuccessRedirectURL(config.OIDC.SuccessRedirectURL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid OIDC success redirect URL", ErrInvalidConfig)
		}
		auth.resolveOIDCIdentity = config.OIDC.ResolveIdentity
	}
	if config.SAML.Enabled {
		if stores.SAML == nil || config.SAML.Connections == nil || config.SAML.ResolveIdentity == nil {
			return nil, fmt.Errorf("%w: SAML storage, connections, and identity resolver are required", ErrInvalidConfig)
		}
		auth.saml, err = saml.NewManager(stores.SAML, config.SAML.Connections, saml.Config{
			RequestLifetime: config.SAML.RequestLifetime,
			AttemptGuard:    config.SAML.AttemptGuard,
			SecurityEvents:  config.SAML.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
		auth.samlSuccessRedirectURL, err = parseSuccessRedirectURL(config.SAML.SuccessRedirectURL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid SAML success redirect URL", ErrInvalidConfig)
		}
		auth.resolveSAMLIdentity = config.SAML.ResolveIdentity
	}
	if config.EmailVerification.Enabled {
		if stores.EmailVerification == nil {
			return nil, fmt.Errorf("%w: database does not provide email verification storage", ErrInvalidConfig)
		}
		auth.emailVerification, err = emailverification.NewManager(
			stores.EmailVerification,
			emailverification.Config{
				Lifetime:       config.EmailVerification.Lifetime,
				Sender:         config.EmailVerification.Sender,
				AttemptGuard:   config.EmailVerification.AttemptGuard,
				SecurityEvents: config.EmailVerification.SecurityEvents,
			},
		)
		if err != nil {
			return nil, err
		}
	}
	if config.PasswordReset.Enabled {
		if stores.PasswordReset == nil {
			return nil, fmt.Errorf("%w: database does not provide password reset storage", ErrInvalidConfig)
		}
		auth.passwordReset, err = passwordreset.NewManager(stores.PasswordReset, passwordreset.Config{
			Lifetime:         config.PasswordReset.Lifetime,
			Sender:           config.PasswordReset.Sender,
			ValidatePassword: passwordreset.PasswordValidator(config.EmailAndPassword.ValidatePassword),
			AttemptGuard:     config.PasswordReset.AttemptGuard,
			SecurityEvents:   config.PasswordReset.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
	}
	handler, err := newHandler(auth, config, baseURL, basePath)
	if err != nil {
		return nil, err
	}
	auth.handler = handler
	return auth, nil
}

func (auth *Auth) Handler() http.Handler { return auth.handler }

func (auth *Auth) ResolveSession(r *http.Request) (sessiontoken.Record, error) {
	cookie, err := r.Cookie(auth.cookieName)
	if err != nil {
		return sessiontoken.Record{}, sessiontoken.ErrInvalidToken
	}
	return auth.sessions.Resolve(r.Context(), cookie.Value)
}

func parseSuccessRedirectURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return "", ErrInvalidConfig
	}
	return parsed.String(), nil
}
