# Architecture

## Purpose

Authlier is a framework-neutral authentication library. Applications compose
the capabilities they need and provide their own persistence, cache, delivery,
and telemetry adapters.

Authlier establishes identity. The application owns roles, permissions,
tenancy, billing, and every other authorization decision.

## Package structure

```text
authlier/
  accesstoken/   Ed25519 JWT access-token issuance and verification
  password/      Argon2id and bcrypt password hashing
  refreshtoken/  Opaque refresh-token rotation and reuse detection
  sessiontoken/  Opaque server-side session lifecycle and caching
  token/         Opaque token generation and hashing
```

## Credential models

Applications choose one of two models.

### Opaque sessions

```text
raw session token
  -> token hash
  -> bounded cache
  -> durable session store
  -> authenticated subject
```

Only the hash reaches storage. Durable state owns creation, expiry, extension,
rotation, and revocation. Cache misses and cache failures fall back to the
durable store.

Session extension is disabled by default. When enabled, an active session may
extend after a configured threshold but never beyond its absolute lifetime.

### JWT access and refresh tokens

```text
JWT access token
  -> Ed25519 signature and claim validation
  -> durable session resolution
  -> authenticated subject

opaque refresh token
  -> token hash
  -> atomic rotation
  -> replacement refresh token
```

Access tokens validate their algorithm, key ID, issuer, audience, timing
claims, session ID, and subject. Durable session resolution makes revocation
observable before JWT expiry.

Refresh tokens keep their original absolute expiry. Reuse invalidates the
durable session and all refresh tokens attached to it.

## Passwords

Argon2id is the default password algorithm. Bcrypt is available for compatible
applications and migrations. Stored hashes identify their algorithm and work
parameters. Verification reports when a matching hash should be replaced.

Untrusted Argon2id parameters are bounded before expensive work begins.

## Persistence and caching

Core packages depend on behavioral interfaces, not databases or cache
products. Adapters must preserve uniqueness, atomic rotation, single use,
expiry, revocation, and safe concurrent updates.

A database is supported only after its adapter has proved those guarantees
against the real database. A cache is never the durable session authority.

## Security boundaries

Raw passwords and bearer tokens must not be logged. Raw opaque tokens must not
be persisted. JWT signing keys remain application-managed secrets.

Authlier does not depend on an HTTP framework. The host owns cookie policy,
CSRF protection, rate limiting, request handling, and authorization.
