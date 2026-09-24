---
title: Email verification
description: Verify email ownership with a one-time link or email OTP.
icon: Email
---

Email verification proves that a user controls an email address. Authlier can
deliver a one-time link or a six-digit email OTP. Your Go server provides the
sender that hands the message to its email provider.

The complete flow is:

1. Sign-up or an explicit client request asks Authlier to send verification.
2. Authlier creates a link token or OTP and passes it to your sender.
3. The user opens the link or submits the OTP with the email address.
4. Authlier consumes the credential once and marks the address as verified.

## Use verification links

Links remain the default for backward compatibility:

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
`AutoSignInAfterVerification` creates the configured session when verification
succeeds.

## Choose where the email opens

By default the email opens
`{BaseURL}/api/auth/verify-email?token=...`, which lets the Authlier handler
consume the token directly. Set `VerificationURL` to a frontend page when your
application needs to show its own verification interface. That page reads the
token from its URL and submits it to the Authlier verification route; it must
not treat the token as verified by itself.

## Use email OTP

Select OTP delivery and send `message.Code` instead of `message.URL`:

```go
type verificationSender struct{}

func (verificationSender) SendVerification(
	ctx context.Context,
	message emailverification.Message,
) error {
	return mailer.Send(ctx, message.Email, "Verify your email", message.Code)
}

EmailVerification: authlier.EmailVerificationConfig{
	Enabled:                     true,
	Delivery:                    emailverification.DeliveryMethodOTP,
	OTPSecret:                   []byte(os.Getenv("AUTHLIER_EMAIL_OTP_SECRET")),
	Sender:                      verificationSender{},
	SendOnSignUp:                true,
	AutoSignInAfterVerification: true,
	AttemptGuard:                verificationAttempts,
},
```

OTP mode requires an `AttemptGuard`. A six-digit code has a deliberately small
input space for usability, so the guard must limit repeated verification by the
normalized email and trusted request source. Return
`emailverification.ErrAttemptBlocked` when the attempt should be rejected. Use
shared storage for the guard when the application runs more than one server
instance.

`OTPSecret` must contain at least 32 bytes from application secret storage. Use
a dedicated cryptographically random value and keep it stable while issued
codes remain valid. Authlier uses it to create an HMAC proof; it is never sent
to the client or stored in the database.

The client verifies the code with the same email address that received it:

```http
POST /api/auth/verify-email
Content-Type: application/json

{"email":"person@example.com","code":"042731"}
```

OTP codes expire after ten minutes by default. Authlier stores only an HMAC
proof bound to the normalized email. A replacement request invalidates the
earlier code, and successful verification consumes the current code atomically.

## Routes

- `POST /api/auth/send-verification-email` accepts `{"email":"..."}` and
  returns `202 Accepted`.
- Link mode registers `GET /api/auth/verify-email?token=...`.
- OTP mode registers `POST /api/auth/verify-email` with `email` and `code`.

Link tokens expire after one hour by default. Both modes are single-use. The
sender receives the raw link token and URL or the raw OTP only for delivery. Do
not store or log any of those values.
