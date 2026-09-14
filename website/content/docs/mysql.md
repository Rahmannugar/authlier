---
title: MySQL
description: Use MySQL as Authlier's database.
icon: Database
---

This page replaces the database step in [Getting started](/docs/getting-started)
with the complete MySQL setup. The resulting adapter is passed directly to
`authlier.Config.Database`.

Supported versions: MySQL 8.4 and 9.

## Install the adapter

```bash
go get github.com/Rahmannugar/authlier/storage/mysql
go get github.com/go-sql-driver/mysql
```

## Connect, migrate, and configure Authlier

Parse the application's DSN first so its existing options remain intact. Then
enable parsed time values and UTC timestamps before opening the shared database
handle:

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

Keep `databaseHandle` open for the lifetime of the server and close it during
graceful shutdown. In this example, import `github.com/go-sql-driver/mysql` as `mysqldriver` to
distinguish it from Authlier's MySQL adapter. Authlier expects timestamps to be
scanned as `time.Time` in UTC.

## What migration does

MySQL commits schema changes independently of surrounding transaction control.
Authlier records completed migrations and writes migration statements so they
can be retried safely after an interrupted run.

## Enable TOTP encryption

When TOTP is enabled, pass your `mysql.SecretCodec` as
`mysql.Config{Secrets: secretCodec}`. The application owns that codec and its
encryption keys.
