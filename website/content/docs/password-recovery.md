---
title: Password recovery
description: Configure forgot-password email delivery and single-use password resets.
icon: Lock
---

Password recovery needs email and password authentication plus a
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

```go
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

Set `ResetURL` when the email should open a page in your browser client instead
of Authlier's default endpoint. That page reads the token and sends the request
shown above.
