---
title: Email verification
description: Send one-time verification links and require verified email before sign-in.
icon: Email
---

Email verification proves that a user controls an email address. Authlier
creates, hashes, expires, and consumes the one-time token. Your Go server
provides a sender that delivers the URL through its email provider.

The complete flow is:

1. Sign-up or an explicit client request asks Authlier to send verification.
2. Authlier creates a token and passes the recipient and URL to your sender.
3. The user opens the URL in a browser.
4. Authlier consumes the token once and marks the address as verified.

## Provide email delivery

```go
type verificationSender struct{}

func (verificationSender) SendVerification(
	ctx context.Context,
	message emailverification.Message,
) error {
	return mailer.Send(ctx, message.Email, "Verify your email", message.URL)
}
```

`mailer.Send` represents your own email-provider integration. Authlier does not
choose an email service or send mail directly.

## Configure verification

Add the sender beside email and password configuration:

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

`RequireEmailVerification` prevents password sign-in until verification is
complete. `SendOnSignUp` sends the first message automatically.
`AutoSignInAfterVerification` creates the configured session when the token is
accepted.

## Choose where the email opens

By default the email opens
`{BaseURL}/api/auth/verify-email?token=...`, which lets the Authlier handler
consume the token directly. Set `VerificationURL` to a frontend page when your
application needs to show its own verification interface. That page reads the
token from its URL and submits it to the Authlier verification route; it must
not treat the token as verified by itself.

## Routes

- `POST /api/auth/send-verification-email` accepts `{"email":"..."}` and
  returns `202 Accepted`.
- `GET /api/auth/verify-email?token=...` consumes the token and returns the
  verified user.

Verification tokens expire after one hour by default and are single-use. The
sender receives the raw token and URL only for delivery. Do not store or log
either value.
