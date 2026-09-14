---
title: Redis
description: Use Redis as Authlier's database or as a session cache.
icon: Database
---

Redis has two separate roles in Authlier. `redis.New` creates a complete primary
database adapter. `redis.NewSessionCache` adds a cache in front of another
durable session store.

## Redis as the database

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
```

`Migrate` verifies the Redis connection. The adapter uses a shared hash tag in
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

The database remains authoritative. A cache miss or cache error falls back to
the database, while revocation updates the database before removing cached
state.

Redis 7.4 and 8 are covered by Authlier's CI integration tests. Supply a
`redis.SecretCodec` when using Redis as the primary database with TOTP.
