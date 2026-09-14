---
title: HTTP routes
description: Reference the routes added by Authlier's standard handler.
icon: List
---

The examples use the default `/api/auth` base path. Changing `Config.BasePath`
changes the prefix for every route. Authlier only registers routes for enabled
features, except session routes, which are always available.

## Common response rules

Successful JSON responses use `Content-Type: application/json`. A successful
operation with nothing to return uses `204 No Content`. Errors use one shape:

```json
{"error":{"code":"invalid_request"}}
```

The browser adds an `Origin` header to its POST requests. That origin must match
`BaseURL` or `TrustedOrigins`. SAML's provider callback is the exception because
the identity provider posts it from another origin. Native clients using bearer
mode may omit `Origin`.

## Email and password

| Route | Request | Result |
| --- | --- | --- |
| `POST /api/auth/sign-up/email` | `email`, `password` | Creates the user and usually a session |
| `POST /api/auth/sign-in/email` | `email`, `password` | Creates a session or returns a TOTP challenge |
| `POST /api/auth/change-password` | `currentPassword`, `newPassword`, `revokeOtherSessions` | Replaces the current password |
| `POST /api/auth/set-password` | `password` | Adds a password to an authenticated account |
| `POST /api/auth/remove-password` | `currentPassword` | Removes the password when another sign-in method remains |

## Email verification and recovery

| Route | Request | Result |
| --- | --- | --- |
| `POST /api/auth/send-verification-email` | `email` | Sends a verification message and returns `202` |
| `GET /api/auth/verify-email?token=...` | Query token | Verifies the email |
| `POST /api/auth/forgot-password` | `email` | Sends a reset message and returns `202` |
| `POST /api/auth/reset-password` | `token`, `newPassword` | Replaces the password and usually revokes sessions |

The two message-request routes deliberately return the same public result when
an email address does not belong to an account.

## Sessions

| Route | Request | Result |
| --- | --- | --- |
| `GET /api/auth/session` | Session cookie or bearer access token | Returns the current session |
| `POST /api/auth/sign-out` | Current credential | Revokes the current session |
| `POST /api/auth/token/refresh` | `refreshToken` in bearer mode | Rotates the refresh token and returns a new token pair |
| `GET /api/auth/list-sessions` | Session cookie or bearer access token | Returns active sessions for the current subject |
| `POST /api/auth/revoke-session` | `sessionId` | Revokes one session owned by the current subject |
| `POST /api/auth/revoke-other-sessions` | Current credential | Revokes the others and replaces the current session |
| `POST /api/auth/revoke-sessions` | Current credential | Revokes every session for the current subject |

In bearer mode, authenticated routes use `Authorization: Bearer <access-token>`.
Authentication and refresh responses include the `tokens` object described in
[Bearer tokens](/docs/bearer-tokens).

## Google

| Route | Request | Result |
| --- | --- | --- |
| `POST /api/auth/sign-in/google` | Empty body | Returns the Google authorization URL |
| `GET /api/auth/callback/google` | Provider query | Validates the callback and creates a session |
| `POST /api/auth/link-account/google` | Session cookie | Returns an authorization URL for account linking |
| `GET /api/auth/list-accounts/google` | Session cookie | Lists linked Google identities |
| `POST /api/auth/unlink-account/google` | `providerSubject` | Removes one linked Google identity |

## TOTP

| Route | Request | Result |
| --- | --- | --- |
| `POST /api/auth/two-factor/totp/enable` | `accountName` | Starts enrollment and returns the secret and URI |
| `POST /api/auth/two-factor/totp/confirm` | `code` | Enables TOTP and returns recovery codes |
| `POST /api/auth/two-factor/verify` | `challengeToken`, `code` | Completes sign-in with an authenticator code |
| `POST /api/auth/two-factor/recover` | `challengeToken`, `code` | Completes sign-in with a recovery code |
| `POST /api/auth/two-factor/disable` | Session cookie | Removes the TOTP credential |

## Passkeys

| Route | Request | Result |
| --- | --- | --- |
| `POST /api/auth/passkey/register/options` | Session cookie | Returns registration options and a ceremony token |
| `POST /api/auth/passkey/register/verify` | `ceremonyToken`, `response` | Verifies and stores the new credential |
| `POST /api/auth/passkey/sign-in/options` | Empty body | Returns assertion options and a ceremony token |
| `POST /api/auth/passkey/sign-in/verify` | `ceremonyToken`, `response` | Verifies the assertion and creates a session |
| `GET /api/auth/passkey/list` | Session cookie | Lists credential IDs |
| `POST /api/auth/passkey/remove` | `credentialId` | Removes a credential when another method remains |

## SSO

| Route | Request | Result |
| --- | --- | --- |
| `POST /api/auth/sso/oidc/sign-in` | `connectionId` | Returns the provider authorization URL |
| `GET /api/auth/sso/oidc/callback` | Provider query | Resolves the OIDC identity and creates a session |
| `POST /api/auth/sso/saml/sign-in` | `connectionId` | Returns the provider authorization URL |
| `POST /api/auth/sso/saml/callback` | SAML form post | Resolves the SAML identity and creates a session |
| `GET /api/auth/sso/saml/metadata?connectionId=...` | Connection query | Returns service-provider metadata |

## Error codes

Common codes include `invalid_request`, `invalid_credentials`,
`not_authenticated`, `recent_authentication_required`, `too_many_attempts`,
`invalid_token`, `last_sign_in_method`, `session_not_found`, and
`sso_connection_not_found`. Feature-specific verification failures use stable
codes such as `passkey_verification_failed`, `google_authentication_failed`,
`oidc_authentication_failed`, and `saml_authentication_failed`.

Treat unrecognized codes as a general failure so a newer Authlier version does
not break the interface.
