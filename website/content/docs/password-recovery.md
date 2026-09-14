---
title: Password recovery
description: Configure forgot-password email delivery and single-use password resets.
icon: Lock
---

Password recovery lets a user replace a forgotten password without presenting
the old one. Authlier owns the single-use reset token and password update. Your
Go server provides the sender that delivers the reset URL.

The flow deliberately has two routes: requesting a reset never reveals whether
an account exists, while completing a reset requires the secret token from the
email.

## Provide email delivery

Password recovery requires email and password authentication plus a
`passwordreset.Sender`:

```go
type resetSender struct{}

func (resetSender) SendPasswordReset(
	ctx context.Context,
	message passwordreset.Message,
) error {
	return mailer.Send(ctx, message.Email, "Reset your password", message.URL)
}
```

Add it to the root Authlier configuration:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled: true,
},
PasswordReset: authlier.PasswordResetConfig{
	Enabled: true,
	Sender:  resetSender{},
},
```

## Request a reset

```http
POST /api/auth/forgot-password
Content-Type: application/json

{"email":"person@example.com"}
```

The route returns `202 Accepted` whether or not the account exists. Keep the
same public user experience so the flow does not reveal registered addresses.

## Set the new password

```http
POST /api/auth/reset-password
Content-Type: application/json

{"token":"token from the reset URL","newPassword":"new secure password"}
```

Reset tokens are expiring and single-use. By default, a successful reset
revokes the account's existing sessions. Set `KeepSessionsAfterReset: true`
only when the application deliberately accepts the weaker recovery behavior.

The replacement password uses `EmailAndPassword.PasswordHashAlgorithm`, just
like sign-up and password changes. The default is Argon2id. A bcrypt selection
therefore applies to recovery as well and retains bcrypt's 72-byte input limit.

By default the generated URL points to the Authlier handler on `BaseURL`. Set
`ResetURL` when the email should open a page in your browser client. That page
reads the token and sends the reset request shown above to your Go server; the
frontend never validates or consumes the token itself.
