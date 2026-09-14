---
title: Email and password
description: Configure sign-up, sign-in, and password credential management.
icon: Key
---

Email and password authentication gives the client routes to create an account,
sign in, and manage the account's password. A successful sign-up or sign-in
creates the session configured by your Go server.

## Configure the Go server

Enable the method in the same root configuration that contains `BaseURL` and
`Database`:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled: true,
},
```

Authlier normalizes email addresses and hashes new passwords securely. New
passwords use Argon2id by default. Existing bcrypt hashes can also be verified
when an application is migrating accounts, and a successful sign-in can replace
an older supported hash with the current format.

## Sign up and sign in

```http
POST /api/auth/sign-up/email
Content-Type: application/json

{"email":"person@example.com","password":"correct horse battery staple"}
```

```http
POST /api/auth/sign-in/email
Content-Type: application/json

{"email":"person@example.com","password":"correct horse battery staple"}
```

The client sends these requests to the Authlier handler mounted in your Go
server. Successful authentication creates a cookie or bearer session according
to `Session.Mode`. Required email verification may pause sign-in, and TOTP may
return a second-factor challenge instead of the completed session.

## Password rules

The application owns its password policy. Return an error when a password does
not meet that policy:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled: true,
	ValidatePassword: func(value string) error {
		if len(value) < 12 {
			return errors.New("password must contain at least 12 characters")
		}
		return nil
	},
},
```

Authlier converts validation failures into the stable `invalid_password` or
`invalid_request` response used by the relevant route.

## Change a password

An authenticated user can change a password:

```http
POST /api/auth/change-password
Content-Type: application/json

{
  "currentPassword":"old password",
  "newPassword":"new secure password",
  "revokeOtherSessions":true
}
```

An account created through another method can add a password with
`POST /api/auth/set-password`. That operation requires a recent session.
Removing a password uses `POST /api/auth/remove-password` and cannot remove the
account's last sign-in method.

For a production password flow, continue with
[Email verification](/docs/email-verification) and
[Password recovery](/docs/password-recovery). [HTTP routes](/docs/http-routes)
contains the complete request and response reference.
