---
title: Sessions
description: Choose cookie or bearer sessions and configure their lifetime and revocation.
icon: Lock
---

Authlier supports two session modes. Use cookie sessions for browser
applications. Use bearer sessions for mobile, CLI, and API clients that send an
`Authorization` header.

Cookie mode is the default. A successful authentication creates an opaque
token, stores only its hash, and sends the raw token in an HttpOnly cookie.

```go
Session: authlier.SessionConfig{
	Lifetime: 7 * 24 * time.Hour,
	FreshAge: 15 * time.Minute,
},
```

`Lifetime` is how long a cookie session remains valid after it is created or
extended. `FreshAge` is the shorter period during which Authlier considers the
original authentication recent enough for sensitive actions, such as changing
a password or enabling MFA.

## Read the current session

Use `ResolveSession` in your Go server handlers:

```go
session, err := auth.ResolveSession(request)
if err != nil {
	http.Error(response, "not authenticated", http.StatusUnauthorized)
	return
}

userID := session.SubjectID
```

In cookie mode, `ResolveSession` reads the HttpOnly cookie. In bearer mode, it
reads `Authorization: Bearer <access-token>`. Both modes return the same
`Session`, so application authorization code does not depend on how the client
authenticated.

## Manage sessions

- `GET /api/auth/list-sessions` returns active sessions and marks the current
  one.
- `POST /api/auth/revoke-session` revokes one session owned by the current
  subject.
- `POST /api/auth/revoke-other-sessions` revokes the others and creates a new
  current session.
- `POST /api/auth/revoke-sessions` revokes every session for the subject.
- `POST /api/auth/sign-out` revokes the current session.

For browser clients, the browser supplies `Origin` and Authlier checks that it
matches `BaseURL` or `TrustedOrigins`. Native clients using bearer mode may omit
`Origin`.

## Extend cookie sessions

Extension gives an active cookie session a new expiry when it has been used for
long enough:

```go
Session: authlier.SessionConfig{
	Lifetime: 24 * time.Hour,
	Extension: &sessiontoken.ExtensionConfig{
		ExtendAfter:      12 * time.Hour,
		AbsoluteLifetime: 30 * 24 * time.Hour,
	},
},
```

In this example, a session starts with 24 hours of validity. After 12 hours of
use, Authlier may move its expiry to 24 hours from the current request. It can
do this again while the session remains active, but never beyond 30 days from
the original sign-in.

The absolute lifetime is the final boundary. It prevents a stolen cookie from
remaining useful forever simply because requests keep extending it. Users sign
in again after that boundary. `ExtendAfter` must be shorter than `Lifetime`, and
`AbsoluteLifetime` must be longer than `Lifetime`.

## Cache cookie sessions with Redis

Keep the configured database as the source of truth and add Redis as an
optional lookup cache:

```go
sessionCache, err := authlierredis.NewSessionCache(redisClient, "my-server")
if err != nil {
	return err
}

auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://server.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
	Session: authlier.SessionConfig{
		Cache:    sessionCache,
		CacheTTL: 5 * time.Minute,
	},
})
```

A cache miss or outage falls back to the configured database. Revocation is
written to the database before cached state is removed. Bearer sessions do not
use this cache; every access token is checked against its durable session so
revocation remains observable.

Continue with [Bearer tokens](/docs/bearer-tokens) when the client cannot use an
HttpOnly browser cookie.
