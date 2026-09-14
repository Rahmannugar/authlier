---
title: Sessions
description: Choose cookie or bearer sessions and configure their lifetime and revocation.
icon: Lock
---

A session connects a successful authentication to later requests. The client
proves that it owns the session on each request, and Authlier resolves that
credential to a session ID and stable subject ID.

Authlier supports two ways to carry the session credential:

| Mode | What the client receives | Good fit |
| --- | --- | --- |
| Cookie | An opaque token in an HttpOnly cookie | Browsers that want the browser to manage the credential |
| Bearer | A signed access token and rotating refresh token in JSON | Web, mobile, CLI, and server clients that manage credentials themselves |

Your Go handlers use the same `ResolveSession` method in either mode. The
session mode only changes how the client receives and sends its credential.

## Configure cookie sessions

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

You may omit `Mode` or set `Mode: authlier.SessionModeCookie` explicitly. Read
[Configuration](/docs/configuration#configure-cookie-sessions) for cookie name,
domain, and SameSite settings. Read [Bearer tokens](/docs/bearer-tokens) for the
complete bearer configuration.

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

## Let clients manage sessions

- `GET /api/auth/list-sessions` returns active sessions and marks the current
  one.
- `POST /api/auth/revoke-session` revokes one session owned by the current
  subject.
- `POST /api/auth/revoke-other-sessions` revokes the others and creates a new
  current session.
- `POST /api/auth/revoke-sessions` revokes every session for the subject.
- `POST /api/auth/sign-out` revokes the current session.

These are Authlier routes mounted inside your Go server. For browser clients,
the browser supplies `Origin` and Authlier checks that it matches `BaseURL` or
`TrustedOrigins`. Native and server clients using bearer mode may omit
`Origin`.

## Extend cookie sessions

By default, a cookie session expires `Lifetime` after sign-in even when the user
remains active. Extension lets active use move that expiry forward:

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

`AbsoluteLifetime` is necessary because extension would otherwise let the same
session continue forever. It is measured from the original sign-in and never
moves. After 30 days in this example, the user must authenticate again even if
the session was extended every day. `ExtendAfter` must be shorter than
`Lifetime`, and `AbsoluteLifetime` must be longer than `Lifetime`.

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

Continue with [Bearer tokens](/docs/bearer-tokens) when your application chooses
access and refresh tokens instead of an HttpOnly cookie.
