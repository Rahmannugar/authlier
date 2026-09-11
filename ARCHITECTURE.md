# Architecture

## Purpose

Authlier handles reusable authentication rules. The host application handles
web requests, access permissions, password rules, storage, caching, and event
delivery.

## Package structure

```text
authlier/
  accesstoken/   Ed25519 JWT access-token issuance and verification
  emailpassword/ Email/password registration and login orchestration
  password/      Argon2id and bcrypt password hashing
  refreshtoken/  Opaque refresh-token rotation and reuse detection
  sessiontoken/  Opaque server-side session lifecycle and caching
  token/         Opaque token generation and hashing
```

## Sessions

### Opaque sessions

```text
raw session token
  -> token hash
  -> cache
  -> stored session
  -> authenticated user
```

The stored session determines whether a user is still signed in. If the session
is not cached or the cache is unavailable, Authlier reads it from storage. A
session can never be extended beyond its configured maximum lifetime.

### JWT access and refresh tokens

```text
JWT access token
  -> validate signature and claims
  -> check stored session
  -> authenticated user

opaque refresh token
  -> token hash
  -> replace once
  -> new refresh token
```

After validating a JWT, Authlier checks the stored session so a revoked session
cannot authenticate. Reusing an old refresh token revokes the session and its
refresh tokens.

## Passwords

Argon2id is the default. Bcrypt supports compatible applications and migrations.

## Email and password authentication

Registration creates the user and password credential in one storage operation.
For an unknown email, login still verifies the password against a dummy hash so
the faster response does not reveal whether the email exists. During a password
hash upgrade, storage replaces the hash only if the password has not changed
since login began. The host application sets password rules, blocks abusive
attempts, and records security events.

## Persistence and caching

Storage adapters must enforce unique identities, ensure tokens can be used only
once, and handle concurrent requests safely. Token rotation must invalidate the
old token and create its replacement as one operation. Each database adapter
must be tested with the database it supports.

## Security boundaries

Do not log passwords or bearer tokens. Persist only opaque-token hashes. JWT
signing keys remain application-managed.
