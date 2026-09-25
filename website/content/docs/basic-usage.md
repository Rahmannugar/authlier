---
title: Basic usage
description: Call Authlier from a browser and use sessions in your Go server.
icon: Browser
---

This guide continues from the Go server created in
[Getting started](/docs/getting-started). That server mounted Authlier at
`/api/auth` and enabled cookie sessions with email and password sign-in.

There are two kinds of routes in that server:

- The browser calls Authlier routes such as `/api/auth/sign-in` to create,
  inspect, and end a session.
- The browser calls your application routes for the product itself. Those Go
  handlers use `auth.ResolveSession(request)` when they need an authenticated
  user.

The examples below are browser client code written in TypeScript. The same HTTP
requests can be made with plain JavaScript or another frontend framework.

## Choose the server URL

If the browser client and Go server share an origin, use relative URLs:

```ts
const serverURL = '';
```

If the frontend is served from `https://client.example.com` and the Go server
is `https://server.example.com`, use the full server origin:

```ts
const serverURL = 'https://server.example.com';
```

The separate-origin setup also requires `TrustedOrigins` in the Go server. The
next section shows that configuration.

## Configure a separate browser origin

Skip this section when the frontend and Go server share an origin. Otherwise,
add the frontend origin when creating Authlier:

```go
auth, err := authlier.New(authlier.Config{
	AppName:        "Acme",
	BaseURL:        "https://server.example.com",
	TrustedOrigins: []string{"https://client.example.com"},
	Database:       database,
	EmailAndPassword: authlier.EmailAndPasswordConfig{
		Enabled: true,
	},
})
```

The browser creates the `Origin` request header. Frontend code does not decide
which origins are trusted and should not try to set
`Access-Control-Allow-Origin`; Authlier sends that response header only after
the request origin matches `TrustedOrigins`.

Cookie requests across origins must also set `credentials: 'include'`. The
small helper below applies that option to every example:

```ts
function authRequest(path: string, init: RequestInit = {}) {
  return fetch(`${serverURL}/api/auth${path}`, {
    ...init,
    credentials: 'include',
  });
}
```

## Create an account

```ts
const response = await authRequest('/sign-up', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'person@example.com',
    password: 'correct horse battery staple',
  }),
});

if (!response.ok) {
  const { error } = await response.json();
  throw new Error(error.code);
}

const { user, session } = await response.json();
```

In cookie mode, Authlier sets an HttpOnly session cookie. Browser JavaScript
cannot read the raw credential, but the browser sends it with later requests
to the Go server.

## Sign in

```ts
const response = await authRequest('/sign-in', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

A successful sign-in replaces the browser's Authlier session cookie. If the
account has TOTP enabled, the response contains a short-lived challenge instead
of a completed session. [TOTP](/docs/totp) explains that second step.

## Read the current session

The browser can ask Authlier for the current session:

```ts
const response = await authRequest('/session');

if (response.status === 401) {
  // Render the signed-out state.
} else {
  const { session } = await response.json();
  console.log(session.subjectId);
}
```

This route is useful for initializing frontend state. It does not replace the
server-side check on a protected application route.

## Protect your own server routes

Inside a Go handler, resolve the session before returning private application
data:

```go
http.HandleFunc("GET /account", func(response http.ResponseWriter, request *http.Request) {
	session, err := auth.ResolveSession(request)
	if err != nil {
		http.Error(response, "not authenticated", http.StatusUnauthorized)
		return
	}

	profile, err := profiles.FindByAuthlierSubject(request.Context(), session.SubjectID)
	// Handle err, then write the application response.
})
```

Authlier answers which subject authenticated. Your application decides which
profile that ID belongs to and what the user may access.

## Sign out

```ts
await authRequest('/sign-out', { method: 'POST' });
```

Authlier revokes the durable session and expires the cookie.

## Handle errors

Authlier errors use one JSON shape:

```json
{
  "error": {
    "code": "invalid_credentials"
  }
}
```

Use `error.code` to choose the client state or message. Do not expose internal
server errors. [HTTP routes](/docs/http-routes) lists the routes, request
bodies, success responses, and error codes.

This guide used cookie sessions, which are the usual browser default. A web
application may instead choose access and refresh tokens, just like a mobile,
CLI, or server client. Read [Configuration](/docs/configuration) first, then
[Bearer tokens](/docs/bearer-tokens) for that setup.
