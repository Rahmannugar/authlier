---
title: Custom storage
description: Implement Authlier's behavioral storage contracts for another database.
icon: Package
---

Use a custom adapter when Authlier does not include your database. The adapter
is application-side Go code that teaches Authlier how to persist every enabled
capability; Authlier does not send records to a separate service.

Start with the root contract:

```go
type Database interface {
	Migrate(ctx context.Context) error
	Stores() authlier.Stores
}
```

`Migrate` prepares whatever schema, indexes, or other database structures the
adapter needs. `Stores` returns one implementation for each enabled Authlier
capability. The root `authlier.New` function selects those stores from the
adapter; normal application handlers do not call them.

For example, `EmailPassword` must implement user and password-credential
storage, `Passkeys` must implement the passkey store, and `TOTP` must implement
the TOTP store. Cookie mode requires `Sessions`. Bearer mode requires both
`AccessSessions` and `RefreshTokens`. A field may be `nil` only when the
corresponding feature is disabled.

Implement the behavior described by each package interface, not only matching
method signatures. In particular, the adapter must preserve:

- unique users and provider identities;
- atomic creation and consumption of one-time tokens and protocol state;
- safe concurrent passkey counter updates;
- session rotation, expiry, and account-wide revocation;
- atomic creation and revocation of bearer access sessions and refresh tokens;
- refresh-token rotation and reuse detection.

Unit tests can check mapping and error behavior, but the adapter also needs
integration tests against the real database. Only the real engine can prove
its transaction, uniqueness, and concurrency behavior.

Read [`storage.go`](https://github.com/Rahmannugar/authlier/blob/main/storage.go)
for the aggregate contract, then follow the interfaces in the packages for the
features you enable. Pass the completed adapter to `Config.Database` in exactly
the same way as an official adapter.
