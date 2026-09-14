---
title: Storage
description: Configure an official Authlier database adapter.
icon: Database
---

Authlier needs a database for authentication records: users, credentials,
sessions, provider identities, and short-lived records such as verification
tokens and protocol challenges. A storage adapter translates Authlier's
database operations to the database your Go server already uses.

The setup always has the same three steps:

1. Open the database client or connection pool.
2. Create an Authlier adapter and call its `Migrate` method.
3. Pass that adapter as `authlier.Config.Database`.

```go
database, err := postgres.New(pool, postgres.Config{})
if err != nil {
	return err
}
if err := database.Migrate(ctx); err != nil {
	return err
}

auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://server.example.com",
	Database: database,
	// Enable the sign-in methods this server uses.
})
```

The adapter implements `authlier.Database`. `Migrate` prepares the schema or
indexes. `Stores` gives Authlier the capability-specific stores it uses
internally; applications using an official adapter do not call `Stores`
themselves.

## Choose a database

Choose the database your application already operates:

- [PostgreSQL](/docs/postgresql)
- [MySQL](/docs/mysql)
- [MongoDB](/docs/mongodb)
- [Redis](/docs/redis), either as the primary database or as a session cache

All four official adapters are complete primary databases. Redis is not limited
to caching.

## What migrations create

PostgreSQL and MySQL migrations create the complete Authlier schema, including
empty tables for authentication methods that are not enabled. MongoDB migration
creates the required indexes. Redis migration verifies the connection because
Redis does not use a separate schema.

The complete SQL schema means enabling another Authlier method later does not
require choosing a second migration set. Empty tables do not activate features;
the `authlier.Config` still decides which methods and routes exist.

Authlier creates UUIDv7 user IDs. Each user also receives a separate random
WebAuthn handle for passkeys. That handle is intentionally not an email address
or the application's user ID.

## How each adapter behaves

### PostgreSQL

The `storage/postgres` package is a complete adapter. Its migration creates the
complete Authlier schema, including tables for sign-in methods you have not yet
enabled. Empty tables use little space, and enabling another method later does
not require selecting another migration set.

Authlier creates UUIDv7 user IDs. Each user also receives a separate random
WebAuthn user handle for passkeys; that handle is not an email address or user
ID.

### Redis

The `storage/redis` package provides a complete database adapter and a separate
optional session cache. Use `redis.New` when Redis is Authlier's database. Use
`redis.NewSessionCache` when another adapter remains the database.

A primary Redis deployment needs persistence, replication, backups, and tested
recovery. Authlier does not change those Redis server settings.

### MySQL

The `storage/mysql` package is a complete adapter. Its migration is repeatable
because MySQL commits schema statements even when they run inside a transaction.

### MongoDB

The `storage/mongodb` package is a complete adapter. `Migrate` creates its
indexes. Connect it to a replica set or sharded cluster because authentication
operations that change several documents use MongoDB transactions.

## Supported versions

The official adapters support:

- PostgreSQL 17 and 18.
- Redis 7.4 and 8.
- MySQL 8.4 and the current MySQL 9 release.
- MongoDB 7 and 8.

## Encrypt TOTP secrets

When TOTP is enabled, pass the adapter a `SecretCodec`. Its `Encrypt` and
`Decrypt` methods keep authenticator secrets encrypted at rest; the application
owns the encryption keys and their rotation. The database-specific pages show
where the codec is passed.

Recovery codes, session tokens, reset tokens, verification tokens, and refresh
tokens are different: Authlier stores hashes because it only needs to compare
the presented value, not recover the original value.

## Custom databases

Applications can support another database by implementing `authlier.Database`
and the stores returned by `authlier.Stores`. Operations documented as atomic
must remain atomic. For example, two requests must not consume the same reset
token successfully. See [Custom storage](/docs/custom-storage) before implementing
an adapter.
