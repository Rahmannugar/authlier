---
title: MongoDB
description: Use MongoDB as Authlier's database.
icon: Database
---

This page replaces the database step in [Getting started](/docs/getting-started)
with the complete MongoDB setup. The resulting adapter is passed directly to
`authlier.Config.Database`.

Supported versions: MongoDB 7 and 8.

## Install the adapter

```bash
go get github.com/Rahmannugar/authlier/storage/mongodb
go get go.mongodb.org/mongo-driver/v2
```

## Connect, migrate, and configure Authlier

Create the MongoDB client when the Go server starts, choose the database name
that will contain Authlier's collections, then migrate and configure Authlier:

```go
client, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
if err != nil {
	return err
}

database, err := mongodb.New(client, "my_application", mongodb.Config{})
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

Keep the client open for the lifetime of the server and disconnect it during
graceful shutdown.

## What migration does

For MongoDB, `Migrate` creates the indexes that protect unique identities,
single-use tokens, and session lookup. It does not create SQL-style tables.

## Deployment requirement

Use a replica set or sharded cluster. Several authentication operations update
multiple documents in one transaction, and standalone MongoDB servers do not
provide that transaction behavior.

## Enable TOTP encryption

When TOTP is enabled, pass your `mongodb.SecretCodec` as
`mongodb.Config{Secrets: secretCodec}`. The application owns that codec and its
encryption keys.
