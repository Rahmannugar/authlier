---
title: Bearer tokens
description: Use access and refresh tokens with mobile, CLI, and API clients.
icon: Key
---

Bearer mode is for clients that cannot use Authlier's HttpOnly browser cookie,
including mobile applications, command-line tools, and server-to-server API
clients. Browser applications should normally keep the default cookie mode.

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

The issuer defaults to `BaseURL`. Access tokens last 15 minutes and refresh
tokens last 30 days unless you set `AccessTokenLifetime` and
`RefreshTokenLifetime`. The refresh-token lifetime is also the final lifetime
of the durable bearer session.

`PublicKeys` may contain older verification keys during key rotation. The
public key derived from `PrivateKey` is automatically registered under `KeyID`.

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

Store the refresh token in the operating system's protected credential storage.
Do not place it in browser local storage or logs.

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

Google, OIDC, and SAML sign-in require cookie mode in this release. Their
callbacks arrive through a browser, and putting access or refresh tokens in a
redirect URL would expose them. Authlier will need a server-side, one-time
exchange code before those flows can safely return credentials to a native
client.
