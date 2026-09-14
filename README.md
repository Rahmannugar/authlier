# Authlier

Authlier is a composable authentication library for Go applications. It brings
passwords, sessions, email verification and recovery, MFA, passkeys, Google
authentication, OIDC, and SAML into your Go server through one configurable
HTTP handler.

Authlier verifies identities and manages authentication records. Your
application keeps control of profiles, roles, permissions, and other product
data.

New passwords use Argon2id by default. Applications can select bcrypt when a
legacy credential system requires temporary write compatibility; verification
continues to recognize both formats for staged migration.

## Installation

```bash
go get github.com/Rahmannugar/authlier
```

## How it works

1. Connect one of the official PostgreSQL, MySQL, MongoDB, or Redis adapters.
2. Enable the authentication methods your application needs.
3. Mount `auth.Handler()` in your Go server.
4. Call `auth.ResolveSession(request)` from application routes that require an
   authenticated user.

With a connected `pgxpool.Pool`, a PostgreSQL setup looks like this:

```go
database, err := postgres.New(pool, postgres.Config{})
if err != nil {
	return err
}
if err := database.Migrate(ctx); err != nil {
	return err
}

auth, err := authlier.New(authlier.Config{
	AppName:  "Acme",
	BaseURL:  "https://server.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})
if err != nil {
	return err
}

http.Handle("/api/auth/", auth.Handler())
```

The complete [Getting started](website/content/docs/getting-started.md) guide
builds a working server and explains each part of this setup.

## Documentation

- [Basic usage](website/content/docs/basic-usage.md) connects a browser client
  to Authlier's routes.
- [Configuration](website/content/docs/configuration.md) covers route prefixes,
  browser origins, session modes, and authentication methods.
- [Bearer tokens](website/content/docs/bearer-tokens.md) covers web, mobile,
  CLI, and API clients that choose access and refresh tokens.
- [Storage](website/content/docs/storage.md) explains the official database
  adapters and custom storage contracts.
- [Authentication guides](website/content/docs/email-password.md) begin with
  email and password, then cover verification, recovery, Google, TOTP, and
  passkeys.
- [Single sign-on](website/content/docs/sso.md) explains the shared OIDC and
  SAML identity boundary.
- [HTTP routes](website/content/docs/http-routes.md) lists the request and
  response contract for the configured handler.
- [Security](website/content/docs/security.md) explains secure deployment and
  the controls that remain the application's responsibility.
- [Architecture](ARCHITECTURE.md) describes the internal package boundaries.

## Security

Security reports should be submitted privately according to
[`SECURITY.md`](SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) to report an issue, propose a change,
or open a pull request.

## License

Authlier is licensed under the Apache License 2.0.
