---
title: Email verification
description: Send one-time verification links and require verified email before sign-in.
icon: Email
---

Authlier creates and consumes verification tokens. Your application sends the
message through an `emailverification.Sender` implementation.

```go
type verificationSender struct{}

func (verificationSender) SendVerification(
	ctx context.Context,
	message emailverification.Message,
) error {
	return mailer.Send(ctx, message.Email, "Verify your email", message.URL)
}
```

Add the sender to the configuration:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled:                  true,
	RequireEmailVerification: true,
},
EmailVerification: authlier.EmailVerificationConfig{
	Enabled:                     true,
	Sender:                      verificationSender{},
	SendOnSignUp:                true,
	AutoSignInAfterVerification: true,
},
```

The default verification URL is
`{BaseURL}/api/auth/verify-email?token=...`. Set `VerificationURL` when a
frontend page should receive the token instead. That page must submit the token
to Authlier's verification route.

## Routes

- `POST /api/auth/send-verification-email` accepts `{"email":"..."}` and
  returns `202 Accepted`.
- `GET /api/auth/verify-email?token=...` consumes the token and returns the
  verified user.

Verification tokens expire after one hour by default and are single-use. The
sender receives the raw token and URL only for delivery; do not log either.
