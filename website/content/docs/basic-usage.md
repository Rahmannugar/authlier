---
title: Basic usage
description: Connect a browser client to Authlier's HTTP routes.
icon: Browser
---

Authlier runs inside your Go server. The browser client calls its mounted
authentication routes. Authlier replies with JSON or redirects the browser to
an identity provider when required.

The examples below assume the default `/api/auth` base path.

## Create an account

```ts
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

```ts
const response = await fetch('/api/auth/sign-in/email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

If TOTP is enabled for the account, this route returns a short-lived challenge
instead of creating a session. See [TOTP](/docs/totp) for the second step.

## Read the session

```ts
const response = await fetch('/api/auth/session');

if (response.status === 401) {
  // Show the signed-out state.
} else {
  const { session } = await response.json();
  console.log(session.subjectId);
}
```

Server-side Go handlers should call `auth.ResolveSession(request)` directly.
See [Sessions](/docs/sessions).

## Sign out

```ts
await fetch('/api/auth/sign-out', { method: 'POST' });
```

For a browser client on another origin, add the client origin to
`TrustedOrigins` and use `credentials: 'include'` in each request. The browser
adds the `Origin` request header itself; frontend code cannot declare an origin
trusted. Authlier checks that header and sends the response headers that allow
the browser to receive the result. See
[Configuration](/docs/configuration#browser-origins).

Mobile, CLI, and server-to-server clients should use
[bearer-token sessions](/docs/bearer-tokens) instead of browser cookies.

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
the user. The complete list is in [HTTP routes](/docs/http-routes).
