---
title: Custom storage
description: Implement Authlier's behavioral storage contracts for another database.
icon: Package
---

Use a custom adapter only when an official adapter does not support your
database. Authlier's root storage contract is intentionally small:

```go
type Database interface {
	Migrate(ctx context.Context) error
	Stores() authlier.Stores
}
```

`Stores` is the set of concrete persistence implementations exposed by your
adapter. Each field corresponds to an Authlier capability, such as
`EmailPassword`, `Passkeys`, or `TOTP`. Cookie mode requires `Sessions`.
Bearer mode requires both `AccessSessions` and `RefreshTokens`. A field may be
`nil` only while the corresponding capability is disabled.

Implement the behavior described by each package interface, not only matching
method signatures. In particular, the adapter must preserve:

- unique users and provider identities;
- atomic creation and consumption of one-time tokens and protocol state;
- safe concurrent passkey counter updates;
- session rotation, expiry, and account-wide revocation;
- atomic creation and revocation of bearer access sessions and refresh tokens;
- refresh-token rotation and reuse detection.

Test those behaviors against the real database. An in-memory mock cannot prove
the transaction, uniqueness, or concurrency guarantees of a storage engine.

Read [`storage.go`](https://github.com/Rahmannugar/authlier/blob/main/storage.go)
for the aggregate contract, then follow the interface in each enabled package.
