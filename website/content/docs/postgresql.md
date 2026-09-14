---
title: PostgreSQL
description: Use PostgreSQL as Authlier's database.
icon: Database
---

Install the adapter and pgx:

```bash
go get github.com/Rahmannugar/authlier/storage/postgres
go get github.com/jackc/pgx/v5
```

Create a connection pool, then pass the adapter to Authlier:

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

`Migrate` creates a small migration ledger and the complete Authlier schema.
The schema includes empty tables for disabled authentication methods so enabling
a method later does not require choosing another migration set. Already applied
migrations are skipped.

PostgreSQL 17 and 18 are covered by Authlier's CI integration tests.

When TOTP is enabled, provide a `postgres.SecretCodec` through
`postgres.Config.Secrets` so authenticator secrets are encrypted before they
reach the database.
