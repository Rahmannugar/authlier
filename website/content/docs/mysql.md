---
title: MySQL
description: Use MySQL as Authlier's database.
icon: Database
---

Install the adapter and driver:

```bash
go get github.com/Rahmannugar/authlier/storage/mysql
go get github.com/go-sql-driver/mysql
```

Open the database with parsed time values and UTC timestamps:

```go
databaseHandle, err := sql.Open(
	"mysql",
	os.Getenv("MYSQL_DSN")+"?parseTime=true&loc=UTC",
)
if err != nil {
	return err
}

database, err := mysql.New(databaseHandle, mysql.Config{})
if err != nil {
	return err
}

if err := database.Migrate(ctx); err != nil {
	return err
}
```

Build the DSN with `mysql.Config` from the driver when the existing DSN may
already contain query parameters. Authlier expects timestamps to be scanned as
`time.Time` in UTC.

MySQL commits schema changes independently of surrounding transaction control.
Authlier records completed migrations and writes migration statements so they
can be retried safely after an interrupted run.

MySQL 8.4 and 9 are covered by Authlier's CI integration tests. Supply a
`mysql.SecretCodec` when enabling TOTP.
