---
title: Redis
description: Use Redis as Authlier's database or as a session cache.
icon: Database
---

Redis can serve two separate roles. Choose `redis.New` when Redis will hold all
Authlier records as the primary database. Choose `redis.NewSessionCache` when
PostgreSQL, MySQL, MongoDB, or another adapter remains the database and Redis
only speeds up cookie-session lookup.

These roles are independent; using Redis does not mean it is only a session
cache. Supported versions are Redis 7.4 and 8.

## Redis as the database

Install the adapter and driver:

```bash
go get github.com/Rahmannugar/authlier/storage/redis
go get github.com/redis/go-redis/v9
```

Create the client, adapter, and Authlier instance when the Go server starts:

```go
client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

database, err := authlierredis.New(client, authlierredis.Config{
	KeyPrefix: "my-application",
})
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

Pass `database` as the one and only `Config.Database`; application code does
not pass the individual stores. `Migrate` verifies the Redis connection. The adapter uses a shared hash tag in
its keys so related operations can remain in one Redis Cluster slot.

When Redis is the only database, configure persistence, replication, backups,
and recovery in Redis itself. Authlier does not turn a cache-only Redis server
into durable storage.

## Redis as a session cache

Keep PostgreSQL, MySQL, or MongoDB as `Database`, then pass the cache separately:

```go
cache, err := authlierredis.NewSessionCache(client, "my-application")
if err != nil {
	return err
}

Session: authlier.SessionConfig{
	Cache:    cache,
	CacheTTL: 5 * time.Minute,
},
```

This cache works only with cookie sessions. The database remains authoritative. A cache miss or cache error falls back to
the database, while revocation updates the database before removing cached
state.

## Enable TOTP encryption

When Redis is the primary database and TOTP is enabled, pass your
`redis.SecretCodec` as `authlierredis.Config{Secrets: secretCodec}`. A Redis
instance used only as a session cache does not store TOTP secrets.
