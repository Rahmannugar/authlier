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
passwords use Argon2id by default. The default applies to sign-up, setting or
changing a password, password recovery, and automatic hash upgrades.

## Choose Argon2id or bcrypt

Most applications should keep Argon2id, either by omitting the setting or by
selecting it explicitly:

```go
import "github.com/Rahmannugar/authlier/password"

EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled:               true,
	PasswordHashAlgorithm: password.Argon2id,
},
```

Select bcrypt only when an existing system must continue reading newly written
password credentials during a staged migration:

```go
EmailAndPassword: authlier.EmailAndPasswordConfig{
	Enabled:               true,
	PasswordHashAlgorithm: password.Bcrypt,
},
```

Authlier rejects an unsupported algorithm when the server starts. Bcrypt has a
72-byte password input limit; attempts to hash a longer password fail rather
than being silently truncated. Argon2id does not have that bcrypt-specific
limit.

## Migrate existing password hashes

Authlier recognizes the format encoded in each stored password hash and can
verify both Argon2id and bcrypt regardless of the configured write algorithm.
A hash cannot be converted directly because password hashing is one-way.
Instead, Authlier upgrades a credential after a successful sign-in:

1. Authlier verifies the submitted password against the stored hash.
2. If the credential needs an upgrade, Authlier hashes the submitted password
   with the configured algorithm and current parameters.
3. Authlier replaces the stored hash only if it still matches the value that
   was verified. This conditional write prevents a concurrent password change
   or reset from being overwritten.

With the Argon2id default, a successful bcrypt sign-in replaces that credential
with Argon2id. Argon2id hashes using older supported parameters are also
refreshed. Accounts that never sign in remain unchanged until the user signs in,
changes the password, or completes password recovery.

Selecting bcrypt writes bcrypt for new or deliberately replaced passwords and
refreshes bcrypt hashes with an outdated cost. It never downgrades an existing
Argon2id credential to bcrypt. This lets an application keep temporary legacy
compatibility without weakening credentials that already use Argon2id.

## Sign up and sign in

```http
POST /api/auth/sign-up
Content-Type: application/json

{"email":"person@example.com","password":"correct horse battery staple"}
```

```http
POST /api/auth/sign-in
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
