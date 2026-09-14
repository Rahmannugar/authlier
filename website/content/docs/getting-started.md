---
title: Getting started
description: Install Authlier and run a complete email and password setup.
icon: Rocket
---

This guide builds a small Go server with email and password authentication. It
uses PostgreSQL and Go's standard HTTP server, but the same Authlier
configuration works with MySQL, MongoDB, or Redis.

You need Go 1.26 or newer and a running PostgreSQL database.

## Install Authlier

```bash
go get github.com/Rahmannugar/authlier
go get github.com/Rahmannugar/authlier/storage/postgres
go get github.com/jackc/pgx/v5
```

Set the database connection used by your application:

```bash
export DATABASE_URL='postgres://postgres:postgres@localhost:5432/example?sslmode=disable'
```

## Create the server

Create `main.go`:

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

	auth, err := authlier.New(authlier.Config{
		AppName:  "Example",
		BaseURL:  "http://localhost:8080",
		Database: database,
		EmailAndPassword: authlier.EmailAndPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

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

Run the application:

```bash
go run .
```

The setup has four parts:

1. Connect to PostgreSQL.
2. Run Authlier's migrations.
3. Enable email and password authentication.
4. Mount the Authlier handler at `/api/auth/`, which matches the default
   `BasePath`.

This example uses Go's default `http.ServeMux`: `http.Handle` registers routes
on it, and passing `nil` to `http.ListenAndServe` tells the server to use it.
Applications that create their own `http.NewServeMux()` can register the same
handler on that mux instead.

`Migrate` creates Authlier's tables and records each applied migration. Calling
it again skips migrations already recorded.

## Create an account

```bash
curl --include \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:8080' \
  --data '{"email":"person@example.com","password":"correct horse battery staple"}' \
  http://localhost:8080/api/auth/sign-up/email
```

`curl` is not a browser, so the command includes `Origin` explicitly. A browser
adds that header automatically. The response contains the user and sets an
HttpOnly session cookie. Send that cookie to an authenticated route:

```bash
curl --cookie cookies.txt http://localhost:8080/account
```

## What just happened

The sign-up route normalized the email, validated and hashed the password,
created the Authlier user, created a server-side session, and set an HttpOnly
cookie. Only the token hash was written to the database.

The `/account` handler called `ResolveSession`. It received the authenticated
subject ID and can use that ID to load application data and enforce
permissions.

The handler also provides:

- `POST /api/auth/sign-in/email`
- `POST /api/auth/sign-out`
- `GET /api/auth/session`
- `GET /api/auth/list-sessions`
- session revocation routes

Only enabled features add their routes. Continue with
[Basic usage](/docs/basic-usage) to call these routes from a browser client,
[Configuration](/docs/configuration) to change the route prefix and other
defaults, [Bearer tokens](/docs/bearer-tokens) for mobile or CLI clients, or
[Storage](/docs/storage) to choose another database.
