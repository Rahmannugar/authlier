---
title: Bearer tokens
description: Use access and refresh tokens with web, mobile, CLI, and API clients.
icon: Key
---

Bearer mode is an alternative to Authlier's default cookie session. It works
with web applications, mobile applications, command-line tools, and
server-to-server clients. The client receives the credentials and sends the
access token in an `Authorization` header.

A browser application can use bearer mode, but it must protect the returned
tokens from script injection. An HttpOnly cookie is the better default when the
browser does not need direct control of the credential because browser
JavaScript cannot read that cookie.

Bearer mode returns two credentials after authentication:

- a short-lived Ed25519-signed JWT access token for API requests;
- a rotating opaque refresh token for obtaining the next token pair.

Authlier stores the durable session and only the refresh-token hash. Each API
request verifies the JWT and confirms that its durable session is still active,
so signing out or revoking a session takes effect before the JWT expires.

## Configure bearer mode

Load the Ed25519 private key from your server's secret storage. Do not place the
key directly in source code.

```go
auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://server.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
	Session: authlier.SessionConfig{
		Mode: authlier.SessionModeBearer,
		Bearer: authlier.BearerSessionConfig{
			Audience:   "acme-api",
			KeyID:      "2026-09",
			PrivateKey: privateKey,
		},
	},
})
```

The bearer settings mean:

| Setting | Meaning |
| --- | --- |
| `Audience` | The server or API the access token is intended for. Choose a stable value such as `acme-api`. Authlier writes it into the JWT and rejects a token whose audience differs from this configuration. |
| `KeyID` | A public name for the signing key, such as `2026-09`. It is written into the JWT header so Authlier knows which public key should verify the signature. It is not a secret. Change it when rotating to a new key. |
| `PrivateKey` | The Ed25519 private key used to sign access tokens. Your application loads it from server-side secret storage. Never send it to a client or commit it to the repository. |

Yes, the application configures `Audience`. It separates tokens meant for
different APIs. For example, a token issued for `acme-api` will not validate in
an Authlier instance configured for `acme-admin`, even if both instances can
access the same signing key.

The issuer identifies who created the token and defaults to `BaseURL`. Access
tokens last 15 minutes and refresh tokens last 30 days unless you set
`AccessTokenLifetime` and `RefreshTokenLifetime`. The refresh-token lifetime is
also the final lifetime of the durable bearer session.

`PublicKeys` contains additional Ed25519 public keys that may verify existing
tokens during key rotation. Authlier automatically derives the current public
key from `PrivateKey` and registers it under `KeyID`.

## Authenticate requests

Sign-up and sign-in return a session and token pair:

```json
{
  "user": { "id": "...", "email": "person@example.com" },
  "session": { "id": "...", "subjectId": "...", "createdAt": "...", "expiresAt": "..." },
  "tokens": {
    "accessToken": "...",
    "accessTokenExpiresAt": "...",
    "refreshToken": "...",
    "refreshTokenExpiresAt": "..."
  }
}
```

Send the access token to Authlier and your own protected server routes:

```text
Authorization: Bearer <access-token>
```

`auth.ResolveSession(request)` reads that header and returns the same `Session`
type used by cookie mode.

On mobile and desktop clients, store the refresh token in the operating
system's protected credential storage. A browser using bearer mode should keep
the access token in memory and avoid persistent JavaScript-readable refresh
token storage where possible. Never place either token in URLs or logs.

## Refresh tokens

When the access token expires, exchange the current refresh token:

```http
POST /api/auth/token/refresh
Content-Type: application/json

{"refreshToken":"..."}
```

The response contains a new access token and a new refresh token. Replace the
old refresh token immediately. A refresh token can be used only once; reuse
revokes its durable session and every refresh token in that session.

## Sign out

Send the current access token when it is still valid:

```http
POST /api/auth/sign-out
Authorization: Bearer <access-token>
```

If the access token has expired, send the refresh token in the JSON body
instead. Authlier uses it to find and revoke the same durable session.

## Browser provider flows

Google, OIDC, and SAML sign-in require cookie mode in this release. This is
because the identity provider completes sign-in by redirecting a browser to
your Authlier callback. A browser application can receive an HttpOnly cookie
from that callback, but a mobile or CLI client cannot safely collect the
callback's response from the browser.

Authlier must not solve that problem by adding the access or refresh token to a
redirect URL. URLs can appear in browser history, proxy and server logs,
analytics, screenshots, and operating-system handoff records. A leaked refresh
token would let another client keep creating access tokens until the durable
session is revoked.

A safe native-provider flow needs one additional exchange:

1. The native client opens the provider sign-in page in the system browser.
2. The provider redirects the browser to the Authlier callback on your Go
   server.
3. After verifying the provider response, Authlier creates a random,
   short-lived, single-use exchange code. The server stores only the code hash.
4. The server redirects the browser to the native application with that code,
   but without any access or refresh token.
5. The native application sends the code directly to the Go server. The server
   consumes it once and returns the access and refresh tokens in the protected
   response body.

That exchange-code flow is not included yet, so Authlier rejects Google, OIDC,
or SAML configuration when bearer mode is selected. This prevents an
application from accidentally shipping an unsafe provider-token redirect.
