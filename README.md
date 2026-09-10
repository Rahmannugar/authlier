# Authlier

Authlier is an authentication library for Go applications. It provides secure authentication capabilities through a clear, composable API.

## Installation

```bash
go get github.com/Rahmannugar/authlier
```

## Passwords

The password package supports Argon2id and bcrypt. Argon2id is the default.
Stored hashes are self-describing, use algorithm-appropriate secure parameters,
and can be verified without separately storing the selected algorithm.
Verification reports when a matching hash should be replaced with the preferred
algorithm or current work factor.

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

Applications that require bcrypt can select it explicitly:

```go
encodedHash, err := password.HashWithAlgorithm(plainPassword, password.Bcrypt)
verification, err := password.VerifyWithAlgorithm(
	plainPassword,
	encodedHash,
	password.Bcrypt,
)
```

Applications remain responsible for password policy. Passwords and password
hashes must never be logged.

## Tokens and sessions

Authlier supports two application-selected credential models:

- Opaque server-side sessions through `sessiontoken`.
- Ed25519 JWT access tokens through `accesstoken`, paired with rotating opaque
  refresh tokens through `refreshtoken`.

The `token` package generates 256-bit opaque tokens and hashes them for durable
storage. Applications persist only token hashes.

The session-token package defines storage-neutral durable and cache contracts
for creation, resolution, rotation, expiry, and revocation. Cache misses and
cache outages fall back to durable storage. Optional session extension is
disabled unless an extension threshold and absolute lifetime are configured.

Access-token verification checks the signature, signing algorithm, key ID,
issuer, audience, timing claims, session ID, and subject. It also resolves the
durable session so revocation is not deferred until JWT expiry.

Refresh tokens retain their original absolute expiry across rotation. Reusing
a rotated token must atomically revoke its durable session and every attached
refresh token. Concrete adapters must preserve the package contracts.

Raw bearer tokens must never be persisted or logged.

## Security

Security reports should be submitted privately according to
[`SECURITY.md`](SECURITY.md).

## License

Authlier is licensed under the Apache License 2.0.
