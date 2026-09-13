# Getting started

Install Authlier and the adapter for your database:

```bash
go get github.com/Rahmannugar/authlier
go get github.com/Rahmannugar/authlier/storage/postgres
```

Create Authlier once during application startup:

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

auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://app.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
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

The application now has these routes:

- `POST /api/auth/sign-up/email`
- `POST /api/auth/sign-in/email`
- `POST /api/auth/sign-out`
- `GET /api/auth/session`

Signup and signin accept `email` and `password` as JSON. Successful requests
set an HttpOnly session cookie. Authlier marks the cookie Secure when `BaseURL`
uses HTTPS.

Use the session in another handler:

```go
session, err := auth.ResolveSession(r)
if err != nil {
	http.Error(w, "not authenticated", http.StatusUnauthorized)
	return
}

userID := session.SubjectID
```

Your application uses `userID` for its own permissions and data access.

## Optional features

Email verification adds `/send-verification-email` and `/verify-email`.
Password recovery adds `/forgot-password` and `/reset-password`. Enable them in
the same `authlier.Config` and provide mail senders from your application.

Optional features use the same configuration. Authlier registers their routes
only when each feature is enabled.

See [storage.md](storage.md) for MySQL, MongoDB, Redis, migrations, and session
caching. SSO setup is documented separately because the application must map
the returned provider identity to one of its users.
