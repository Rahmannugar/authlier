# Authlier

Authlier is a framework-neutral authentication library for Go applications.

## Installation

```bash
go get github.com/Rahmannugar/authlier
```

## Architecture

Authlier is split into packages for passwords, sessions, and tokens. The host
application connects them to storage and handles web requests and permissions.
See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the package boundaries.

## Email and password authentication

The `emailpassword` package handles registration, login, old password-hash
upgrades, abuse checks, and security events. The host application provides the
storage implementation and password rules.

## Email verification and password recovery

The `emailverification` and `passwordreset` packages send expiring, one-time
tokens through application-provided mail senders. Authlier stores only token
hashes. Request handlers must return the same public response whether the email
exists or not.

## Passwords

The `password` package supports Argon2id by default and bcrypt for compatibility.

```go
encodedHash, err := password.Hash(plainPassword)
if err != nil {
	return err
}

verification, err := password.Verify(plainPassword, encodedHash)
if err != nil {
	return err
}
if !verification.Matches {
	return errors.New("invalid credentials")
}
```

Applications remain responsible for password policy. Passwords and password
hashes must never be logged.

## Google authentication

The `googleoauth` package handles the server-side Authorization Code flow with
state, nonce, and S256 PKCE. Google accounts are linked by Google's stable
account ID (`sub`), not by email, so changing a Google email address does not
break sign-in. A user must sign in before linking Google to an existing local
account.

## Sessions

Authlier supports two ways to manage authenticated sessions:

- Opaque server-side sessions through `sessiontoken`.
- Ed25519 JWT access tokens through `accesstoken`, paired with rotating opaque
  refresh tokens through `refreshtoken`.

Applications store only hashes of opaque session and refresh tokens. The
durable session store determines whether a session is active or revoked.
The session manager also supports listing a subject's sessions and revoking
all sessions for an account, with cache invalidation after durable revocation.

## Security

Security reports should be submitted privately according to
[`SECURITY.md`](SECURITY.md).

## License

Authlier is licensed under the Apache License 2.0.
