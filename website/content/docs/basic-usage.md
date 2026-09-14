---
title: Basic usage
description: Connect a browser interface to Authlier's standard HTTP routes.
icon: Browser
---

Authlier runs inside your Go application. The browser calls the mounted
authentication routes, and Authlier replies with JSON or redirects to an
identity provider when required.

The examples below assume the default `/api/auth` base path.

## Create an account

```js
const response = await fetch('/api/auth/sign-up/email', {
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

const { user } = await response.json();
```

On success, Authlier sets an HttpOnly session cookie. Browser JavaScript cannot
read that cookie, which is intentional. The browser sends it automatically on
later same-origin requests.

## Sign in

```js
const response = await fetch('/api/auth/sign-in/email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

If TOTP is enabled for the account, this route returns a short-lived challenge
instead of creating a session. See [TOTP](totp.md) for the second step.

## Read the session

```js
const response = await fetch('/api/auth/session');

if (response.status === 401) {
  // Show the signed-out state.
} else {
  const { session } = await response.json();
  console.log(session.subjectId);
}
```

Server-side Go handlers should call `auth.ResolveSession(request)` directly.
See [Sessions](sessions.md).

## Sign out

```js
await fetch('/api/auth/sign-out', { method: 'POST' });
```

For a frontend on another allowed origin, add that origin to `TrustedOrigins`
and use `credentials: 'include'` in each request. See
[Configuration](configuration.md#browser-origins).

## Handle errors

Errors use one stable JSON shape:

```json
{
  "error": {
    "code": "invalid_credentials"
  }
}
```

Use the code to choose the interface state. Do not show raw server errors to
the user. The complete list is in [HTTP routes](http-routes.md).
