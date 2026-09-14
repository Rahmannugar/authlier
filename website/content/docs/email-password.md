---
title: Email and password
description: Configure sign-up, sign-in, and password credential management.
icon: Key
---

Enable email and password authentication in the root configuration:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled: true,
},
```

Authlier normalizes email addresses and hashes new passwords securely. The
password package uses Argon2id by default and also supports bcrypt when an
application needs compatibility with existing hashes. After a successful
sign-in, Authlier can replace an older supported hash with the current format.

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

Successful authentication creates a session unless verified email or TOTP adds
another required step.

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

Add [email verification](/docs/email-verification) and
[password recovery](/docs/password-recovery) for a complete password flow.
