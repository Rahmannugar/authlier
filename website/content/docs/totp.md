---
title: TOTP two-factor authentication
description: Add authenticator-app enrollment, sign-in challenges, and recovery codes.
icon: Shield
---

TOTP adds a second factor after a primary sign-in method succeeds. The user
enrolls an authenticator app once, then supplies its rotating code during later
sign-ins.

Authlier creates and verifies TOTP secrets, challenges, and recovery codes. The
client is responsible for displaying the enrollment QR code and collecting
codes from the user.

## Configure the Go server

```go
TOTP: authlier.TOTPConfig{
	Enabled: true,
},
```

The selected storage adapter also needs a secret codec because Authlier must
decrypt the TOTP secret to verify a code. Configure that codec on the
[storage adapter](/docs/storage#encrypt-totp-secrets) before starting the
server; TOTP configuration fails without it.

## Enroll an authenticator

Enrollment requires a recent authenticated session.

1. Call `POST /api/auth/two-factor/totp/enable` with
   `{"accountName":"person@example.com"}`.
2. Show the returned `uri` as a QR code or let the user copy the returned
   secret into an authenticator app.
3. Call `POST /api/auth/two-factor/totp/confirm` with `{"code":"123456"}`.
4. Show the returned recovery codes once and ask the user to store them safely.

The `uri` contains the enrollment secret. Render it only on the authenticated
enrollment screen and do not log it. The credential is not enabled until the
confirmation code succeeds.

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

The successful verification response creates the same cookie or bearer session
that a sign-in without TOTP would create. `POST
/api/auth/two-factor/disable` requires a recent session.
