---
title: Architecture
description: See how Authlier connects HTTP routes, authentication methods, sessions, and storage.
icon: Structure
---

Authlier is a Go library that your application compiles into its server. The
root `authlier` package creates the configured authentication methods, connects
them to storage, and exposes one `http.Handler` for the server to mount.

## Authentication requests

The client sends a request to a route beneath `BasePath`. The Authlier handler
validates the request and calls the manager for that authentication method. The
manager verifies the credential or provider response and writes the required
authentication records through the configured storage adapter.

Authlier creates a session only after every required authentication step has
succeeded. In cookie mode, it stores the opaque token hash and sends the raw
token to the browser in an HttpOnly cookie. In bearer mode, it returns a
short-lived access token and a rotating refresh token to the web, mobile, CLI,
or server client.

## Application requests

Your application routes remain in your Go server. When one of those routes
requires an authenticated account, call `auth.ResolveSession(request)`.
Authlier reads either the cookie or bearer access token, validates its durable
session, and returns the stable subject ID.

Use that subject ID to load the profile, organization membership, roles, and
permissions owned by your application. Those records do not become Authlier
data.

## Package boundaries

Each authentication method has a focused public package such as
`emailpassword`, `totp`, `passkey`, `googleoauth`, `oidc`, or `saml`. The root
package is the convenient composition layer used by most HTTP applications.
The lower-level packages remain public for another transport or a deliberately
different authentication workflow.

Official database implementations live under `storage/postgres`,
`storage/mysql`, `storage/mongodb`, and `storage/redis`. They implement the same
behavioral storage contracts, including the atomic operations required for
single-use tokens, state consumption, session revocation, and credential
updates.

See [Lower-level packages](/docs/lower-level-packages) before replacing the
configured HTTP handler, or read the repository's
[`ARCHITECTURE.md`](https://github.com/Rahmannugar/authlier/blob/main/ARCHITECTURE.md)
for the complete package map.
