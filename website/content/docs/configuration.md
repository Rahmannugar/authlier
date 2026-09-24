---
title: Configuration
description: Configure Authlier's server URL, routes, client origins, sessions, and sign-in methods.
icon: Gear
---

Create one `authlier.Config` when your Go server starts. Authlier validates the
configuration and returns an error before the server begins accepting requests
when required settings are missing or incompatible.

## Required configuration

A working configuration needs four decisions:

| Setting | What to provide |
| --- | --- |
| `AppName` | The product name that authentication features may show to users. |
| `BaseURL` | The public `http` or `https` origin of the Go server receiving Authlier requests. Do not include a path. |
| `Database` | An official adapter or your own implementation of `authlier.Database`. |
| Sign-in method | Enable at least one of email and password, Google, passkeys, OIDC, or SAML. |

This is a complete email and password configuration using the default cookie
session and `/api/auth` route prefix:

```go
auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://server.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})
if err != nil {
	log.Fatal(err)
}

http.Handle("/api/auth/", auth.Handler())
```

`BaseURL` describes where the Go server is publicly reachable. The path passed
to `http.Handle` decides where the handler is mounted inside that server.

## Route prefix

Authlier's default `BasePath` is `/api/auth`, so the configuration above creates
routes such as:

```text
https://server.example.com/api/auth/sign-in/email
```

Set `BasePath` when a different prefix fits the server better. For example, an
API subdomain may use `/auth` to avoid repeating `api` in the URL:

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

Email sign-in is now
`https://api.example.com/auth/sign-in/email`. `BasePath` must begin with `/`
and must not end with `/`. Mount the handler at the same prefix. The trailing
slash in `http.Handle("/auth/", ...)` is Go's subtree-matching syntax; it is not
part of `BasePath`.

The examples use Go's standard `net/http` package, not a third-party mux. Any
router that accepts an `http.Handler` can mount the same Authlier handler.

## Choose a password-hashing algorithm

Email and password authentication uses Argon2id by default. Most applications
should keep that default:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled:               true,
	PasswordHashAlgorithm: password.Argon2id,
},
```

Applications that must remain compatible with a legacy credential system can
select bcrypt:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled:               true,
	PasswordHashAlgorithm: password.Bcrypt,
},
```

Import the algorithm constants from
`github.com/Rahmannugar/authlier/password`. The selection applies to sign-up,
setting or changing a password, password recovery, and automatic hash upgrades.
Authlier still recognizes both supported formats and never replaces an
Argon2id credential with bcrypt during sign-in. Read
[Email and password](/docs/email-password) before selecting bcrypt.

## Browser origins

`BaseURL` is trusted automatically. Add `TrustedOrigins` only for browser
clients served from another origin:

```go
TrustedOrigins: []string{
	"https://client.example.com",
},
```

For example, this setting lets a frontend at `client.example.com` call Authlier
on `server.example.com`. The browser sends the `Origin` request header.
Authlier compares it with this list and, when allowed, writes the required CORS
response headers.

Frontend code does not set an origin as trusted. It only uses the Go server URL
and, in cookie mode, includes credentials in cross-origin requests:

```ts
fetch('https://server.example.com/api/auth/session', {
  credentials: 'include',
});
```

Cookie mode rejects state-changing requests without a trusted `Origin`. Bearer
mode permits requests without `Origin` because native and server clients do not
send browser origin headers, but it still rejects an explicitly untrusted
browser origin.

## Choose a session mode

Cookie mode is the default:

```go
Session: authlier.SessionConfig{
	Mode: authlier.SessionModeCookie,
},
```

Authlier stores the raw session token in an HttpOnly cookie and only its hash in
the database. This is usually the simplest browser setup because frontend
JavaScript never receives the credential.

Bearer mode returns an access token and rotating refresh token in the JSON
authentication response:

```go
Session: authlier.SessionConfig{
	Mode: authlier.SessionModeBearer,
	Bearer: authlier.BearerSessionConfig{
		Audience:   "acme-api",
		KeyID:      "2026-09",
		PrivateKey: privateKey,
	},
},
```

Web, mobile, CLI, and server clients may all use bearer mode. The application
chooses it when the client needs direct control of credentials. Read
[Bearer tokens](/docs/bearer-tokens) for key generation, token storage,
refresh, revocation, and current provider-flow limits.

## Configure cookie sessions

Cookie sessions last seven days by default. The default cookie is named
`authlier_session`, uses path `/`, and uses `SameSite=Lax`:

```go
Session: authlier.SessionConfig{
	Lifetime: 30 * 24 * time.Hour,
	Cookie: authlier.CookieConfig{
		Name:   "session",
		Domain: ".example.com",
	},
},
```

Authlier automatically makes the cookie `HttpOnly` and makes it `Secure` when
`BaseURL` uses HTTPS. Read [Sessions](/docs/sessions) before adding session
extension or a Redis cache.

## Enable authentication methods

Authentication methods are opt-in. A method contributes its HTTP routes only
when enabled:

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

Enabling a method is only the first field for features that need email delivery,
provider credentials, WebAuthn settings, or organization connections. Each
authentication guide explains what the application must provide and shows a
complete configuration.

Email verification uses one-time links by default. Set
`Delivery: emailverification.DeliveryMethodOTP` for six-digit email codes. OTP
mode requires a 32-byte application-managed `OTPSecret` and an `AttemptGuard`;
see [Email verification](/docs/email-verification) for the complete
configuration and route contract.

## Trusted proxies

Authlier uses a request source key for attempt guards and security events. Add
`TrustedProxies` only when the Go server is behind a proxy that you operate and
the proxy sets the forwarding headers Authlier reads:

```go
TrustedProxies: []string{"10.0.0.0/8"},
```

Do not trust every address. An untrusted client must not be allowed to choose
the IP address used by rate limits or security records.

The next page, [Bearer tokens](/docs/bearer-tokens), explains bearer-specific
fields. Otherwise continue to [Sessions](/docs/sessions) or choose an
authentication method from the sidebar.
