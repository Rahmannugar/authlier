---
title: TOTP two-factor authentication
description: Add authenticator-app enrollment, sign-in challenges, and recovery codes.
icon: Shield
---

TOTP adds an authenticator-app code after a primary sign-in method succeeds.

```go
TOTP: authlier.TOTPConfig{
	Enabled: true,
},
```

The storage adapter needs a secret codec because TOTP secrets must be encrypted
at rest. Configure that codec on the selected [storage adapter](/docs/storage).

## Enroll an authenticator

Enrollment requires a recent authenticated session.

1. Call `POST /api/auth/two-factor/totp/enable` with
   `{"accountName":"person@example.com"}`.
2. Show the returned `uri` as a QR code or let the user copy the returned
   secret into an authenticator app.
3. Call `POST /api/auth/two-factor/totp/confirm` with `{"code":"123456"}`.
4. Show the returned recovery codes once and ask the user to store them safely.

The credential is not enabled until the confirmation code succeeds.

## Complete sign-in

When TOTP is enabled, password sign-in returns:

```json
{
  "twoFactorRequired": true,
  "challengeToken": "opaque one-time token",
  "expiresAt": "2026-09-14T12:00:00Z"
}
```

Submit the authenticator code:

```http
POST /api/auth/two-factor/verify
Content-Type: application/json

{"challengeToken":"...","code":"123456"}
```

Use `/api/auth/two-factor/recover` with the same body shape when `code` is a
recovery code. A successful request consumes the challenge and creates the
session. Each recovery code can be used once.

`POST /api/auth/two-factor/disable` requires a recent session.
