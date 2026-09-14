---
title: MongoDB
description: Use MongoDB as Authlier's database.
icon: Database
---

Install the adapter and MongoDB driver:

```bash
go get github.com/Rahmannugar/authlier/storage/mongodb
go get go.mongodb.org/mongo-driver/v2
```

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
```

For MongoDB, `Migrate` creates the indexes that protect unique identities,
single-use tokens, and session lookup. It does not create SQL-style tables.

Use a replica set or sharded cluster. Several authentication operations update
multiple documents in one transaction, and standalone MongoDB servers do not
provide that transaction behavior.

MongoDB 7 and 8 are covered by Authlier's CI integration tests. Supply a
`mongodb.SecretCodec` when enabling TOTP.
