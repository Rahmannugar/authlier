---
title: PostgreSQL
description: Use PostgreSQL as Authlier's database.
icon: Database
---

This page replaces the database step in [Getting started](/docs/getting-started)
with the complete PostgreSQL setup. The resulting adapter is passed directly to
`authlier.Config.Database`.

Supported versions: PostgreSQL 17 and 18.

## Install the adapter

```bash
go get github.com/Rahmannugar/authlier/storage/postgres
go get github.com/jackc/pgx/v5
```

## Connect, migrate, and configure Authlier

Create one connection pool when the Go server starts. Build the Authlier
adapter around that pool, run its migrations, and pass the same adapter to
Authlier:

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
	BaseURL:  "https://server.example.com",
	Database: database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})
if err != nil {
	return err
}
```

Keep the pool open for the lifetime of the server and close it during graceful
shutdown.

## What migration does

`Migrate` creates a small migration ledger and the complete Authlier schema.
The schema includes empty tables for disabled authentication methods so enabling
a method later does not require choosing another migration set. Already applied
migrations are skipped.

## Enable TOTP encryption

When TOTP is enabled, pass your `postgres.SecretCodec` to the adapter so
authenticator secrets are encrypted before they reach PostgreSQL:

```go
database, err := postgres.New(pool, postgres.Config{
	Secrets: secretCodec,
})
```

The codec and its encryption keys belong to the application. See
[Storage](/docs/storage#encrypt-totp-secrets).
