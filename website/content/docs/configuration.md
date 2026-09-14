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
	BaseURL:  "https://server.example.com",
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

The default is `/api/auth`. For a server at `server.example.com`, email sign-in
is available at:

```text
https://server.example.com/api/auth/sign-in/email
```

If that server already uses an `api` subdomain, you may prefer `/auth` so the
URL does not repeat `api`:

```go
auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://server.example.com",
	BasePath: "/auth",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})

http.Handle("/auth/", auth.Handler())
```

The routes now begin with `https://server.example.com/auth`. `BasePath` changes
the Authlier route prefix; it does not change your server's domain.

`BasePath` must start with `/` and must not end with `/`. The path passed to
`http.Handle` ends with `/` because Go uses that trailing slash to match every
Authlier route beneath the prefix. `http.Handle` and `http.NewServeMux` are both
part of Go's standard `net/http` package; Authlier does not require a third-party
router.

## Browser origins

Authlier accepts browser requests from `BaseURL`. If the browser client is
served from another origin, add that client origin:

```go
TrustedOrigins: []string{
	"https://client.example.com",
},
```

For browser requests, the browser creates the `Origin` header automatically.
Your frontend does not set `Access-Control-Allow-Origin`; Authlier adds that
response header after it recognizes the origin. Cookie mode rejects POST
requests whose origin is missing or untrusted, which protects the session
cookie from cross-site requests.

Native clients do not send browser origin headers. Bearer mode therefore accepts
a request without `Origin`, but still rejects an untrusted origin when a browser
does send one. See [Bearer tokens](/docs/bearer-tokens).

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

See [Sessions](/docs/sessions) before enabling session extension or a Redis
cache.

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
