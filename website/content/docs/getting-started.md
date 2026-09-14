---
title: Getting started
description: Add Authlier to a Go server and create your first authenticated session.
icon: Rocket
---

This guide adds email and password authentication to a small Go server. By the
end, a client can create an account and use the returned session to call a
protected server route.

The example uses PostgreSQL and Go's standard `net/http` package. Authlier also
has adapters for MySQL, MongoDB, and Redis, and it works with any Go router that
can mount an `http.Handler`.

## What you are building

Authlier is a library inside your Go server, not a separate authentication
service. A complete request passes through these parts:

1. A client calls an authentication route on your Go server.
2. The mounted Authlier handler verifies the request and creates a session.
3. The PostgreSQL adapter stores Authlier's users, credentials, and sessions in
   your database.
4. Your own server handlers call `ResolveSession` to learn which Authlier user
   made a request.

Authlier handles authentication. Your application still owns its profiles,
business data, roles, and permissions.

## Before you begin

You need Go 1.26 or newer and a PostgreSQL database that your server can reach.
Create a Go module if the application does not already have one:

```bash
go mod init example.com/acme
```

Install Authlier, its PostgreSQL adapter, and the PostgreSQL driver:

```bash
go get github.com/Rahmannugar/authlier
go get github.com/Rahmannugar/authlier/storage/postgres
go get github.com/jackc/pgx/v5
```

Set the connection string used by the example:

```bash
export DATABASE_URL='postgres://postgres:postgres@localhost:5432/example?sslmode=disable'
```

## 1. Connect the database

Create `main.go` and begin by opening a PostgreSQL connection:

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/storage/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	database, err := postgres.New(pool, postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
```

`postgres.New` creates the Authlier adapter around the connection pool.
`Migrate` creates the tables Authlier needs and records which migrations have
run. It is safe to call during later starts because completed migrations are
skipped.

## 2. Configure Authlier

Continue inside `main`:

```go
	auth, err := authlier.New(authlier.Config{
		AppName:  "Acme",
		BaseURL:  "http://localhost:8080",
		Database: database,
		EmailAndPassword: authlier.EmailAndPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
```

This configuration tells Authlier:

- `AppName` is the name shown by authentication features such as authenticator
  apps and passkeys.
- `BaseURL` is the public origin of this Go server. It is not a frontend URL.
- `Database` is the adapter Authlier will use for its own records.
- `EmailAndPassword.Enabled` adds the email sign-up and sign-in flows.

Cookie sessions are used because no other session mode was selected. The
default Authlier route prefix is `/api/auth`.

## 3. Mount Authlier and protect an application route

Finish `main`:

```go
	http.Handle("/api/auth/", auth.Handler())

	http.HandleFunc("GET /account", func(response http.ResponseWriter, request *http.Request) {
		session, err := auth.ResolveSession(request)
		if err != nil {
			http.Error(response, "not authenticated", http.StatusUnauthorized)
			return
		}

		_, _ = response.Write([]byte("Signed in as " + session.SubjectID))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

`auth.Handler()` serves Authlier's HTTP routes. The `/account` route belongs to
your application. It uses `ResolveSession` to reject signed-out requests and
obtain the stable Authlier user ID from a valid session.

This example registers both handlers on Go's default `http.ServeMux`. If your
server already creates its own mux or uses another router, mount
`auth.Handler()` there at the same prefix.

## 4. Start the server

```bash
go run .
```

The server now exposes Authlier under `http://localhost:8080/api/auth` and the
application route at `http://localhost:8080/account`.

## 5. Create an account

Call the email sign-up route:

```bash
curl --include \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:8080' \
  --data '{"email":"person@example.com","password":"correct horse battery staple"}' \
  http://localhost:8080/api/auth/sign-up/email
```

The `Origin` header says which browser origin initiated a state-changing
request. Browsers add it automatically; this `curl` example supplies it because
`curl` is not a browser. Authlier accepts the server's own origin by default.

The response creates an HttpOnly session cookie and `--cookie-jar` saves it to
`cookies.txt`. Use that cookie to call the protected application route:

```bash
curl --cookie cookies.txt http://localhost:8080/account
```

The response contains the Authlier subject ID. A real application would use
that ID to load its profile or other business data.

## What Authlier did

For the sign-up request, Authlier normalized the email address, validated and
hashed the password, created the user, stored a hash of the session token, and
set the raw session token in an HttpOnly cookie. The raw token was not written
to the database.

You now have the complete server-side loop. Continue with
[Basic usage](/docs/basic-usage) to connect a browser client, then read
[Configuration](/docs/configuration) to choose the public URL, route prefix,
trusted client origins, session style, and additional sign-in methods.
