---
title: Configuration
description: Configure Authlier and enable the authentication methods your application uses.
icon: Gear
---

Create one `authlier.Config` when the application starts. `AppName`, `BaseURL`,
`Database`, and at least one sign-in method are required.

```go
auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://app.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})
```

`BaseURL` is the public origin that receives Authlier requests. Authlier uses
its scheme to decide whether the session cookie must be Secure.

## Route prefix

Authlier does not force its routes to live at `/api/auth`. Choose the route
prefix with `BasePath`, then mount `auth.Handler()` at that same path in your Go
server.

The default is `/api/auth`. It works well when the frontend and Go server share
one public domain:

```text
https://app.example.com/api/auth/sign-in/email
```

When the Go server already has a dedicated API domain, you may prefer `/auth`
so that `api` is not repeated in the URL:

```go
auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://api.example.com",
	BasePath: "/auth",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})

http.Handle("/auth/", auth.Handler())
```

The routes now begin with `https://api.example.com/auth`. For example, email
sign-in is available at `https://api.example.com/auth/sign-in/email`.

`BasePath` must start with `/` and must not end with `/`. The path passed to
`http.Handle` ends with `/` because Go uses that trailing slash to match every
Authlier route beneath the prefix. `http.Handle` and `http.NewServeMux` are both
part of Go's standard `net/http` package; Authlier does not require a third-party
router.

## Browser origins

Authlier accepts browser requests from `BaseURL`. Add another frontend origin
only when the application needs one:

```go
TrustedOrigins: []string{
	"https://admin.example.com",
},
```

POST requests without an allowed `Origin` header are rejected. This protects
cookie-authenticated routes from cross-site requests.

## Sessions

Sessions last seven days by default. The default cookie is named
`authlier_session`, uses `/` as its path, and uses `SameSite=Lax`.

```go
Session: authlier.SessionConfig{
	Lifetime: 30 * 24 * time.Hour,
	Cookie: authlier.CookieConfig{
		Name:   "session",
		Domain: ".example.com",
	},
},
```

See [Sessions](sessions.md) before enabling session extension or a Redis cache.

## Optional authentication methods

Each method is disabled until its `Enabled` field is true:

```go
EmailAndPassword:  authlier.EmailAndPasswordConfig{Enabled: true},
EmailVerification: authlier.EmailVerificationConfig{Enabled: true},
PasswordReset:     authlier.PasswordResetConfig{Enabled: true},
Google:            authlier.GoogleConfig{Enabled: true},
TOTP:              authlier.TOTPConfig{Enabled: true},
Passkeys:          authlier.PasskeyConfig{Enabled: true},
OIDC:              authlier.OIDCConfig{Enabled: true},
SAML:              authlier.SAMLConfig{Enabled: true},
```

Some methods require more settings. Their guides show the complete
configuration rather than listing every field here.
