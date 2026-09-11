# Getting started

Create a database adapter, configure Authlier once, and mount its handler in
your Go server.

## PostgreSQL

```go
pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
if err != nil {
	return err
}

database, err := postgres.New(pool, postgres.Config{})
if err != nil {
	return err
}
if err := database.Migrate(ctx); err != nil {
	return err
}
```

`Migrate` creates Authlier's tables. It is safe to call again on later starts.
Creating the adapter alone does not change the database.

## Configure Authlier

```go
auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://app.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
		ValidatePassword: func(password string) error {
			if len(password) < 12 {
				return errors.New("password must have at least 12 characters")
			}
			return nil
		},
	},
	Session: authlier.SessionConfig{
		Lifetime: 24 * time.Hour,
	},
})
if err != nil {
	return err
}

http.Handle("/api/auth/", auth.Handler())
```

The default routes are:

- `POST /api/auth/sign-up/email`
- `POST /api/auth/sign-in/email`
- `POST /api/auth/sign-out`
- `GET /api/auth/session`

Signup and signin accept JSON containing `email` and `password`. Authlier sets
an HttpOnly session cookie after either request succeeds. The cookie is Secure
when `BaseURL` uses HTTPS.

Browser requests that change authentication state must come from `BaseURL` or
an origin listed in `TrustedOrigins`.

## Read a session in application code

```go
session, err := auth.ResolveSession(r)
if err != nil {
	http.Error(w, "not authenticated", http.StatusUnauthorized)
	return
}

userID := session.SubjectID
```

The application uses the authenticated user ID for its own authorization. For
example, the application still decides which organizations and records that
user may access.

## Optional Redis session cache

```go
cache, err := authlierredis.NewSessionCache(redisClient, "acme")
if err != nil {
	return err
}

// Add these fields to SessionConfig.
Cache:    cache,
CacheTTL: 5 * time.Minute,
```

PostgreSQL remains the session authority in this setup. Redis only makes
session lookup faster.

The lower-level authentication managers remain public for applications that
need custom routes or flows.
