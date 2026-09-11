package authlier

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/sessiontoken"
)

var ErrInvalidConfig = errors.New("invalid Authlier configuration")

type EmailAndPasswordConfig struct {
	Enabled          bool
	ValidatePassword emailpassword.PasswordValidator
	AttemptGuard     emailpassword.AttemptGuard
	SecurityEvents   emailpassword.SecurityEventSink
}

type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	SameSite http.SameSite
}

type SessionConfig struct {
	Lifetime  time.Duration
	Cache     sessiontoken.Cache
	CacheTTL  time.Duration
	Extension *sessiontoken.ExtensionConfig
	Cookie    CookieConfig
}

type Config struct {
	AppName          string
	BaseURL          string
	BasePath         string
	Database         Database
	TrustedOrigins   []string
	EmailAndPassword EmailAndPasswordConfig
	Session          SessionConfig
}

type Auth struct {
	handler    http.Handler
	password   *emailpassword.Manager
	sessions   *sessiontoken.Manager
	cookieName string
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
	if !config.EmailAndPassword.Enabled {
		return nil, fmt.Errorf("%w: enable at least one sign-in method", ErrInvalidConfig)
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
	stores := config.Database.Stores()
	if stores.EmailPassword == nil || stores.Sessions == nil {
		return nil, fmt.Errorf("%w: database does not provide password and session storage", ErrInvalidConfig)
	}
	passwords, err := emailpassword.NewManager(stores.EmailPassword, emailpassword.Config{
		Credentials:      stores.EmailPassword,
		ValidatePassword: config.EmailAndPassword.ValidatePassword,
		AttemptGuard:     config.EmailAndPassword.AttemptGuard,
		SecurityEvents:   config.EmailAndPassword.SecurityEvents,
	})
	if err != nil {
		return nil, err
	}
	sessions, err := sessiontoken.NewManager(stores.Sessions, config.Session.Cache, sessiontoken.Config{
		Lifetime:  config.Session.Lifetime,
		CacheTTL:  config.Session.CacheTTL,
		Extension: config.Session.Extension,
	})
	if err != nil {
		return nil, err
	}
	auth := &Auth{password: passwords, sessions: sessions}
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
