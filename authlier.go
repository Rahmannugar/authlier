package authlier

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/accesstoken"
	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/passkey"
	passwordhash "github.com/Rahmannugar/authlier/password"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/Rahmannugar/authlier/saml"
	"github.com/Rahmannugar/authlier/sessiontoken"
	"github.com/Rahmannugar/authlier/totp"
)

var ErrInvalidConfig = errors.New("invalid Authlier configuration")

const (
	defaultSessionLifetime      = 7 * 24 * time.Hour
	defaultFreshAge             = 15 * time.Minute
	defaultAccessTokenLifetime  = 15 * time.Minute
	defaultRefreshTokenLifetime = 30 * 24 * time.Hour
	defaultEmailTokenLifetime   = time.Hour
	defaultEmailOTPLifetime     = 10 * time.Minute
	defaultTOTPEnrollment       = 10 * time.Minute
	defaultTOTPChallenge        = 5 * time.Minute
	defaultTOTPRecoveryCodes    = 10
	defaultPasskeyCeremony      = 5 * time.Minute
	defaultProviderState        = 10 * time.Minute
	defaultSAMLRequestLifetime  = 5 * time.Minute
)

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
	bearerSessions                *bearerSessionManager
	sessionMode                   SessionMode
	totp                          *totp.Manager
	sessionFreshAge               time.Duration
	requireEmailVerification      bool
	sendVerificationOnSignUp      bool
	sendVerificationOnSignIn      bool
	autoSignInAfterVerification   bool
	emailVerificationDelivery     emailverification.DeliveryMethod
	revokeSessionsOnPasswordReset bool
	googleSuccessRedirectURL      string
	oidcSuccessRedirectURL        string
	samlSuccessRedirectURL        string
	resolveOIDCIdentity           OIDCIdentityResolver
	resolveSAMLIdentity           SAMLIdentityResolver
	cookieName                    string
}

type configuredPasswords struct {
	algorithm passwordhash.Algorithm
}

func (passwords configuredPasswords) Hash(plainPassword string) (string, error) {
	return passwordhash.HashWithAlgorithm(plainPassword, passwords.algorithm)
}

func (passwords configuredPasswords) Verify(
	plainPassword string,
	encodedHash string,
) (passwordhash.Verification, error) {
	return passwordhash.VerifyWithAlgorithm(plainPassword, encodedHash, passwords.algorithm)
}

func New(config Config) (*Auth, error) {
	applyConfigDefaults(&config)
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
	if config.EmailAndPassword.PasswordHashAlgorithm != passwordhash.Argon2id &&
		config.EmailAndPassword.PasswordHashAlgorithm != passwordhash.Bcrypt {
		return nil, fmt.Errorf("%w: password hash algorithm must be argon2id or bcrypt", ErrInvalidConfig)
	}
	basePath := strings.TrimSpace(config.BasePath)
	if basePath == "" {
		basePath = "/api/auth"
	}
	if !strings.HasPrefix(basePath, "/") || strings.HasSuffix(basePath, "/") {
		return nil, fmt.Errorf("%w: base path must start but not end with a slash", ErrInvalidConfig)
	}
	if config.Session.FreshAge <= 0 {
		return nil, fmt.Errorf("%w: session fresh age must be positive", ErrInvalidConfig)
	}
	if config.Session.Mode != SessionModeCookie && config.Session.Mode != SessionModeBearer {
		return nil, fmt.Errorf("%w: session mode must be cookie or bearer", ErrInvalidConfig)
	}
	if config.Session.Mode == SessionModeBearer &&
		(config.Google.Enabled || config.OIDC.Enabled || config.SAML.Enabled) {
		return nil, fmt.Errorf(
			"%w: Google, OIDC, and SAML require cookie sessions",
			ErrInvalidConfig,
		)
	}
	stores := config.Database.Stores()
	passwordEngine := configuredPasswords{algorithm: config.EmailAndPassword.PasswordHashAlgorithm}
	validatePassword := configuredPasswordValidator(config.EmailAndPassword)
	var passwords *emailpassword.Manager
	if config.EmailAndPassword.Enabled {
		if stores.EmailPassword == nil {
			return nil, fmt.Errorf("%w: database does not provide password storage", ErrInvalidConfig)
		}
		passwords, err = emailpassword.NewManager(stores.EmailPassword, emailpassword.Config{
			Passwords:        passwordEngine,
			Credentials:      stores.EmailPassword,
			ValidatePassword: validatePassword,
			AttemptGuard:     config.EmailAndPassword.AttemptGuard,
			SecurityEvents:   config.EmailAndPassword.SecurityEvents,
		})
		if err != nil {
			return nil, err
		}
	}
	auth := &Auth{
		password:                      passwords,
		sessionMode:                   config.Session.Mode,
		sessionFreshAge:               config.Session.FreshAge,
		requireEmailVerification:      config.EmailAndPassword.RequireEmailVerification,
		sendVerificationOnSignUp:      config.EmailVerification.SendOnSignUp,
		sendVerificationOnSignIn:      config.EmailVerification.SendOnSignIn,
		autoSignInAfterVerification:   config.EmailVerification.AutoSignInAfterVerification,
		emailVerificationDelivery:     config.EmailVerification.Delivery,
		revokeSessionsOnPasswordReset: !config.PasswordReset.KeepSessionsAfterReset,
	}
	if config.Session.Mode == SessionModeCookie {
		if stores.Sessions == nil {
			return nil, fmt.Errorf("%w: database does not provide cookie session storage", ErrInvalidConfig)
		}
		auth.sessions, err = sessiontoken.NewManager(
			stores.Sessions,
			config.Session.Cache,
			sessiontoken.Config{
				Lifetime: config.Session.Lifetime, CacheTTL: config.Session.CacheTTL,
				Extension: config.Session.Extension,
			},
		)
		if err != nil {
			return nil, err
		}
	} else {
		if stores.AccessSessions == nil || stores.RefreshTokens == nil {
			return nil, fmt.Errorf("%w: database does not provide bearer session storage", ErrInvalidConfig)
		}
		if config.Session.Cache != nil || config.Session.Extension != nil {
			return nil, fmt.Errorf(
				"%w: cache and extension apply only to cookie sessions",
				ErrInvalidConfig,
			)
		}
		if strings.TrimSpace(config.Session.Bearer.Issuer) == "" {
			config.Session.Bearer.Issuer = baseURL.Scheme + "://" + baseURL.Host
		}
		auth.bearerSessions, err = newBearerSessionManager(
			stores.AccessSessions,
			stores.RefreshTokens,
			config.Session.Bearer,
		)
		if err != nil {
			return nil, err
		}
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
		if config.EmailVerification.Sender == nil {
			return nil, fmt.Errorf("%w: email verification sender is required", ErrInvalidConfig)
		}
		verificationSender := config.EmailVerification.Sender
		if config.EmailVerification.Delivery == emailverification.DeliveryMethodLink {
			verificationURL := config.EmailVerification.VerificationURL
			if strings.TrimSpace(verificationURL) == "" {
				verificationURL = baseURL.Scheme + "://" + baseURL.Host + basePath + "/verify-email"
			}
			verificationSender, err = newVerificationURLSender(verificationSender, verificationURL)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid email verification URL", ErrInvalidConfig)
			}
		}
		auth.emailVerification, err = emailverification.NewManager(
			stores.EmailVerification,
			emailverification.Config{
				Delivery:       config.EmailVerification.Delivery,
				OTPSecret:      config.EmailVerification.OTPSecret,
				Lifetime:       config.EmailVerification.Lifetime,
				Sender:         verificationSender,
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
		if config.PasswordReset.Sender == nil {
			return nil, fmt.Errorf("%w: password reset sender is required", ErrInvalidConfig)
		}
		resetURL := config.PasswordReset.ResetURL
		if strings.TrimSpace(resetURL) == "" {
			resetURL = baseURL.Scheme + "://" + baseURL.Host + "/reset-password"
		}
		resetSender, err := newResetURLSender(config.PasswordReset.Sender, resetURL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid password reset URL", ErrInvalidConfig)
		}
		auth.passwordReset, err = passwordreset.NewManager(stores.PasswordReset, passwordreset.Config{
			Lifetime:         config.PasswordReset.Lifetime,
			Sender:           resetSender,
			Passwords:        passwordEngine,
			ValidatePassword: passwordreset.PasswordValidator(validatePassword),
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

func configuredPasswordValidator(config EmailAndPasswordConfig) emailpassword.PasswordValidator {
	if config.PasswordHashAlgorithm != passwordhash.Bcrypt {
		return config.ValidatePassword
	}
	return func(plainPassword string) error {
		if len(plainPassword) > passwordhash.BcryptMaximumPasswordLength {
			return passwordhash.ErrPasswordTooLong
		}
		if config.ValidatePassword != nil {
			return config.ValidatePassword(plainPassword)
		}
		return nil
	}
}

func applyConfigDefaults(config *Config) {
	if config.EmailAndPassword.PasswordHashAlgorithm == "" {
		config.EmailAndPassword.PasswordHashAlgorithm = passwordhash.DefaultAlgorithm
	}
	if config.Session.Mode == "" {
		config.Session.Mode = SessionModeCookie
	}
	if config.Session.Lifetime == 0 {
		config.Session.Lifetime = defaultSessionLifetime
	}
	if config.Session.FreshAge == 0 {
		config.Session.FreshAge = defaultFreshAge
	}
	if config.Session.Bearer.AccessTokenLifetime == 0 {
		config.Session.Bearer.AccessTokenLifetime = defaultAccessTokenLifetime
	}
	if config.Session.Bearer.RefreshTokenLifetime == 0 {
		config.Session.Bearer.RefreshTokenLifetime = defaultRefreshTokenLifetime
	}
	if config.EmailVerification.Delivery == "" {
		config.EmailVerification.Delivery = emailverification.DeliveryMethodLink
	}
	if config.EmailVerification.Lifetime == 0 {
		if config.EmailVerification.Delivery == emailverification.DeliveryMethodOTP {
			config.EmailVerification.Lifetime = defaultEmailOTPLifetime
		} else {
			config.EmailVerification.Lifetime = defaultEmailTokenLifetime
		}
	}
	if config.PasswordReset.Lifetime == 0 {
		config.PasswordReset.Lifetime = defaultEmailTokenLifetime
	}
	if config.TOTP.EnrollmentLifetime == 0 {
		config.TOTP.EnrollmentLifetime = defaultTOTPEnrollment
	}
	if config.TOTP.ChallengeLifetime == 0 {
		config.TOTP.ChallengeLifetime = defaultTOTPChallenge
	}
	if config.TOTP.RecoveryCodeCount == 0 {
		config.TOTP.RecoveryCodeCount = defaultTOTPRecoveryCodes
	}
	if config.Passkeys.CeremonyLifetime == 0 {
		config.Passkeys.CeremonyLifetime = defaultPasskeyCeremony
	}
	if config.Google.StateLifetime == 0 {
		config.Google.StateLifetime = defaultProviderState
	}
	if config.OIDC.StateLifetime == 0 {
		config.OIDC.StateLifetime = defaultProviderState
	}
	if config.SAML.RequestLifetime == 0 {
		config.SAML.RequestLifetime = defaultSAMLRequestLifetime
	}
}

func (auth *Auth) Handler() http.Handler { return auth.handler }

func (auth *Auth) ResolveSession(r *http.Request) (Session, error) {
	if auth.sessionMode == SessionModeBearer {
		token, err := bearerToken(r.Header.Get("Authorization"))
		if err != nil {
			return Session{}, err
		}
		return auth.bearerSessions.Resolve(r.Context(), token)
	}
	cookie, err := r.Cookie(auth.cookieName)
	if err != nil {
		return Session{}, sessiontoken.ErrInvalidToken
	}
	record, err := auth.sessions.Resolve(r.Context(), cookie.Value)
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID: record.ID, SubjectID: record.SubjectID,
		CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
	}, nil
}

func bearerToken(authorization string) (string, error) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", accesstoken.ErrInvalidToken
	}
	return parts[1], nil
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
