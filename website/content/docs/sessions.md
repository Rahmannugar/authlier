---
title: Sessions
description: Configure session cookies, expiration, caching, and revocation.
icon: Lock
---

Authlier creates an opaque session token after successful authentication. The
browser receives the raw token in an HttpOnly cookie. Storage receives only its
hash.

```go
Session: authlier.SessionConfig{
	Lifetime: 7 * 24 * time.Hour,
	FreshAge: 15 * time.Minute,
},
```

`Lifetime` controls when the session expires. `FreshAge` controls how recently
the user must have authenticated before changing credentials, enabling MFA, or
linking another sign-in method.

## Read the current session

Use `ResolveSession` inside application handlers:

```go
session, err := auth.ResolveSession(request)
if err != nil {
	http.Error(response, "not authenticated", http.StatusUnauthorized)
	return
}

userID := session.SubjectID
```

The application uses `userID` for authorization. Authlier does not assign
application roles or permissions.

The standard handler also exposes `GET /api/auth/session`.

## Session management routes

- `GET /api/auth/list-sessions` returns the active sessions and marks the
  current one.
- `POST /api/auth/revoke-session` accepts `{"sessionId":"..."}`.
- `POST /api/auth/revoke-other-sessions` removes the other sessions and replaces
  the current session.
- `POST /api/auth/revoke-sessions` removes every session, including the current
  one.
- `POST /api/auth/sign-out` removes the current session.

POST requests must include an allowed `Origin` header.

## Redis session cache

Keep the database adapter as the source of truth and add Redis as an optional
cache:

```go
redisClient := redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

sessionCache, err := authlierredis.NewSessionCache(redisClient, "my-app")
if err != nil {
	return err
}

auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://app.example.com",
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

Import the two Redis packages with distinct names:

```go
import (
	authlierredis "github.com/Rahmannugar/authlier/storage/redis"
	"github.com/redis/go-redis/v9"
)
```

A cache miss or cache outage falls back to the database. Revocation is written
to the database before cached state is removed.

## Session extension

Extension refreshes an active session after a chosen age while preserving an
absolute maximum lifetime:

```go
Session: authlier.SessionConfig{
	Lifetime: 24 * time.Hour,
	Extension: &sessiontoken.ExtensionConfig{
		After:            12 * time.Hour,
		AbsoluteLifetime: 30 * 24 * time.Hour,
	},
},
```

`After` must be shorter than `Lifetime`. `AbsoluteLifetime` must be longer than
`Lifetime`.
