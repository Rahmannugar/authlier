# Storage

Pass a supported database adapter to `authlier.Config`. The adapter stores
users, credentials, sessions, and the temporary records used by enabled sign-in
methods.

## PostgreSQL

The `storage/postgres` package is the first complete adapter. Its migration creates the
complete Authlier schema, including tables for sign-in methods you have not yet
enabled. Empty tables use little space, and enabling another method later does
not require selecting another migration set.

Authlier creates UUIDv7 user IDs. Each user also receives a separate random
WebAuthn user handle for passkeys; that handle is not an email address or user
ID.

## Redis

The current `storage/redis` package provides an optional session cache. PostgreSQL is
still the durable session authority when this cache is used.

A complete Redis database adapter is planned separately. It will allow Redis to
be the primary Authlier database when Redis persistence, replication, and
backups are configured appropriately.

## MySQL

The `storage/mysql` package is a complete adapter. Its migration is repeatable
because MySQL commits schema statements even when they run inside a transaction.

## MongoDB

A complete MongoDB adapter is planned. It will use the same top-level Authlier
configuration as PostgreSQL and MySQL.

## Supported versions

CI runs each completed adapter against two database versions:

- PostgreSQL 17 and 18.
- Redis 7.4 and 8.
- MySQL 8.4 and the current MySQL 9 release.
- MongoDB will receive two-version coverage with its adapter.

## Secrets

The PostgreSQL TOTP store requires a `SecretCodec`. The application supplies
the encryption keys and controls key rotation. Authlier stores recovery codes,
session tokens, reset tokens, and verification tokens as hashes rather than raw
values.

## Custom databases

Applications can support another database by implementing `authlier.Database`
and the stores returned by `authlier.Stores`. Operations documented as atomic
must remain atomic. For example, two requests must not consume the same reset
token successfully.
