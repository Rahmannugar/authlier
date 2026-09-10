# Architecture

Authlier is organized around authentication capabilities. Each capability owns
its security rules, state transitions, and public contract. Applications compose
the capabilities they need and retain control of product authorization.

The core is independent of HTTP frameworks and infrastructure products.
Integration boundaries use narrow behavioral interfaces. Database, cache, mail,
telemetry, and identity-provider adapters implement those interfaces without
becoming dependencies of authentication behavior.

Persistence support is behavioral rather than nominal. An adapter must preserve
the uniqueness, atomicity, expiry, single-use, concurrency, rotation, and
revocation guarantees required by the capability it serves. SQL, NoSQL, and
cache products can be supported through separate adapters without changing the
core contracts.

The token package generates 256-bit opaque credentials and exposes only their
hashes to persistence boundaries. Raw session and refresh tokens exist only at
issuance and presentation.

Applications can use opaque server-side session tokens or short-lived JWT
access tokens with rotating opaque refresh tokens. Opaque sessions use durable
state as authority and may use a bounded cache with durable fallback. Session
extension is optional, threshold-based, and capped by an absolute lifetime.

JWT access tokens use Ed25519 signatures, explicit issuer and audience checks,
key identifiers, bounded lifetimes, and durable session resolution. Refresh
tokens rotate atomically. Reuse revokes their durable session and every refresh
token attached to it.

The password capability supports Argon2id and bcrypt behind one API. Argon2id is
the default. Hashes identify their algorithm and parameters, allowing
verification to select the correct implementation and identify hashes that
should migrate to the configured preference. Untrusted Argon2id parameters are
bounded before memory or CPU work begins.

Authentication establishes identity. Roles, permissions, policies, tenancy,
and other application authorization remain the responsibility of the
integrating application.
