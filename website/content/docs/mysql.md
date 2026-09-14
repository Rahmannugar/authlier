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

Parse the DSN first so existing options are preserved, then enable parsed time
values and UTC timestamps:

```go
driverConfig, err := mysqldriver.ParseDSN(os.Getenv("MYSQL_DSN"))
if err != nil {
	return err
}
driverConfig.ParseTime = true
driverConfig.Loc = time.UTC

databaseHandle, err := sql.Open("mysql", driverConfig.FormatDSN())
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

In this example, import `github.com/go-sql-driver/mysql` as `mysqldriver` to
distinguish it from Authlier's MySQL adapter. Authlier expects timestamps to be
scanned as `time.Time` in UTC.

MySQL commits schema changes independently of surrounding transaction control.
Authlier records completed migrations and writes migration statements so they
can be retried safely after an interrupted run.

Supported versions: MySQL 8.4 and 9. Supply a `mysql.SecretCodec` when enabling
TOTP.
