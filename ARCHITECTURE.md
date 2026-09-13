# Architecture

## Purpose

Authlier handles reusable authentication rules and provides standard HTTP
routes through one configured handler. The host application supplies storage,
policy, and delivery hooks and owns access permissions.

## Package structure

```text
authlier/
  root package        Configuration, standard HTTP routes, and session lookup
  accesstoken/       Ed25519 JWT access-token issuance and verification
  emailaddress/      Shared email normalization
  emailpassword/     Email/password registration and login orchestration
  emailverification/ Email ownership verification
  googleoauth/       Google Authorization Code flow and account linking
  oidc/              Organization OpenID Connect authentication
  passkey/           WebAuthn passkey registration and sign-in
  password/          Argon2id and bcrypt password hashing
  passwordreset/     Password recovery
  refreshtoken/      Opaque refresh-token rotation and reuse detection
  saml/              Organization SAML Web SSO authentication
  sessiontoken/      Opaque server-side session lifecycle and caching
  token/             Opaque token generation and hashing
  totp/              Authenticator-app MFA and recovery codes
  storage/postgres/  PostgreSQL storage adapter and migrations
  storage/mysql/     MySQL storage adapter and migrations
  storage/mongodb/   MongoDB storage adapter and indexes
  storage/redis/     Redis storage and session caching
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
Applications can list a subject's durable sessions and revoke all of them in
one storage operation. Account-wide revocation then removes each affected
session from the optional cache; durable success is preserved if cache cleanup
needs retrying.

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
since login began. Password changes verify the current password and use the same
safe replacement. Adding a password requires recent authentication. Password
removal succeeds only when another sign-in method remains.

## Email verification and password recovery

Both flows email a random, expiring token and store only its hash. Sending a new
token replaces the earlier one. Email verification consumes the token and marks
the same email as verified in one storage operation. Password reset consumes
the token and replaces the password in one storage operation.

The public request endpoints return the same response whether an email exists
or not. Mail senders should hand delivery to a queue quickly.

## Google authentication

Google's `sub` claim identifies the linked account. Email is saved as profile
data and may change without changing which local user signs in. Linking Google
to an existing local account requires an authenticated user. Unlinking refuses
to remove the account's last sign-in method.

## Organization SSO

OIDC discovers the configured provider and validates state, nonce, PKCE, and
the returned ID token. SAML creates a signed service-provider request and
validates the response against the configured identity-provider metadata. Both
flows use short-lived one-time state and return an identity scoped to the
selected connection. The host application owns organization access.

## Authenticator-app MFA

Enrollment becomes active only after a valid authenticator code. Login uses a
short-lived challenge created after the primary credential succeeds. TOTP
counters and recovery codes can each authenticate only once.

## Passkeys

Passkey registration belongs to an authenticated user. Sign-in discovers the
user from the credential ID and stable WebAuthn user handle. Each ceremony is
short-lived, and credential updates consume the ceremony atomically. Removing a
passkey cannot remove the account's last sign-in method.

## Persistence and caching

Storage adapters must enforce unique identities, ensure tokens can be used only
once, and handle concurrent requests safely. Token rotation must invalidate the
old token and create its replacement as one operation. Each database adapter
must be tested with the database it supports.

## Security boundaries

Do not log passwords or bearer tokens. Persist only opaque-token hashes. JWT
signing keys remain application-managed.
