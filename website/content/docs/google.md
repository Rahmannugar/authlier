---
title: Google authentication
description: Add Google sign-in and safely link Google accounts.
icon: Google
---

Google authentication lets a browser authenticate with a Google account and
receive an Authlier cookie session. Authlier handles the OAuth authorization
code flow, while your application supplies the Google client credentials and
the frontend page to open afterward.

The flow is:

1. The browser asks your Go server to start Google sign-in.
2. Authlier returns a Google authorization URL.
3. Google redirects the browser to the Authlier callback on your Go server.
4. Authlier verifies the response, finds or creates the linked Authlier user,
   creates the cookie session, and redirects to your frontend.

## Configure Google Cloud

Create an OAuth 2.0 web application in Google Cloud. Register this authorized
redirect URI:

```text
https://server.example.com/api/auth/google/callback
```

Use the Go server's public origin and the configured Authlier base path. This
must match the callback Google receives exactly.

## Configure Google

```go
Google: authlier.GoogleConfig{
	Enabled:            true,
	ClientID:           os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret:       os.Getenv("GOOGLE_CLIENT_SECRET"),
	SuccessRedirectURL: "https://client.example.com/account",
},
```

`ClientID` and `ClientSecret` come from Google Cloud and stay in server-side
configuration. `SuccessRedirectURL` is the frontend page Authlier opens after
creating the cookie session. Authlier derives the provider callback from
`BaseURL` and `BasePath`; set `RedirectURL` only when Google is registered with
another callback.

## Start sign-in

```ts
const response = await fetch('/api/auth/google', { method: 'POST' });
const { url } = await response.json();
window.location.assign(url);
```

This example uses a same-origin browser client. A separate frontend origin uses
the full Go server URL and must appear in `TrustedOrigins`.

Google redirects to Authlier. Authlier validates state, nonce, PKCE, and the
returned identity, creates the session, then redirects to the configured
frontend page.

Google authentication is available only in cookie mode in this release; see
[Bearer tokens](/docs/bearer-tokens#browser-provider-flows).

Google accounts are identified by Google's stable `sub` value, not by email.
Changing the Google account's email address does not break the link.

## Link and unlink

An already authenticated user starts linking with
`POST /api/account/google`. This requires a recent session. Each user may link
one Google identity. Unlink it with:

```http
DELETE /api/account/google
```

Authlier refuses to unlink the account's last sign-in method.
