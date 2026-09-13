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

The `storage/redis` package provides a complete database adapter and a separate
optional session cache. Use `redis.New` when Redis is Authlier's database. Use
`redis.NewSessionCache` when another adapter remains the database.

A primary Redis deployment needs persistence, replication, backups, and tested
recovery. Authlier does not change those Redis server settings.

## MySQL

The `storage/mysql` package is a complete adapter. Its migration is repeatable
because MySQL commits schema statements even when they run inside a transaction.

## MongoDB

The `storage/mongodb` package is a complete adapter. `Migrate` creates its
indexes. Connect it to a replica set or sharded cluster because authentication
operations that change several documents use MongoDB transactions.

## Supported versions

CI runs each completed adapter against two database versions:

- PostgreSQL 17 and 18.
- Redis 7.4 and 8.
- MySQL 8.4 and the current MySQL 9 release.
- MongoDB 7 and 8.

## Secrets

Each complete adapter's TOTP store requires a `SecretCodec`. The application
supplies the encryption keys and controls key rotation. Authlier stores
recovery codes, session tokens, reset tokens, and verification tokens as hashes
rather than raw values.

## Custom databases

Applications can support another database by implementing `authlier.Database`
and the stores returned by `authlier.Stores`. Operations documented as atomic
must remain atomic. For example, two requests must not consume the same reset
token successfully.
