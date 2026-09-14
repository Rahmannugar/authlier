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

`Stores` contains one interface for each authentication capability. Sessions
are always required. A store for another capability may be `nil` while that
capability is disabled.

Implement the behavior described by each package interface, not only matching
method signatures. In particular, the adapter must preserve:

- unique users and provider identities;
- atomic creation and consumption of one-time tokens and protocol state;
- safe concurrent passkey counter updates;
- session rotation, expiry, and account-wide revocation;
- refresh-token reuse detection when the lower-level token packages are used.

Test those behaviors against the real database. An in-memory mock cannot prove
the transaction, uniqueness, or concurrency guarantees of a storage engine.

Read [`storage.go`](https://github.com/Rahmannugar/authlier/blob/main/storage.go)
for the aggregate contract, then follow the interface in each enabled package.
