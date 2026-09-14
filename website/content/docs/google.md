---
title: Google authentication
description: Add Google sign-in and safely link Google accounts.
icon: Google
---

Create an OAuth 2.0 web application in Google Cloud. Add this authorized
redirect URI:

```text
https://server.example.com/api/auth/callback/google
```

Use your application's public origin and Authlier base path.

## Configure Google

```go
Google: authlier.GoogleConfig{
	Enabled:            true,
	ClientID:           os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret:       os.Getenv("GOOGLE_CLIENT_SECRET"),
	SuccessRedirectURL: "https://client.example.com/account",
},
```

`SuccessRedirectURL` is the browser-client page Authlier opens after creating
the cookie session. Authlier derives the provider callback from `BaseURL`; set
`RedirectURL` only when Google is configured with another callback.

## Start sign-in

```ts
const response = await fetch('/api/auth/sign-in/google', { method: 'POST' });
const { url } = await response.json();
window.location.assign(url);
```

Google redirects to Authlier. Authlier validates state, nonce, PKCE, and the
returned identity, creates the session, then redirects to the configured client
page.

Google authentication is available only in cookie mode in this release; see
[Bearer tokens](/docs/bearer-tokens#browser-provider-flows).

Google accounts are identified by Google's stable `sub` value, not by email.
Changing the Google account's email address does not break the link.

## Link and unlink

An already authenticated user starts linking with
`POST /api/auth/link-account/google`. This requires a recent session. List the
linked accounts with `GET /api/auth/list-accounts/google`, then unlink one with:

```http
POST /api/auth/unlink-account/google
Content-Type: application/json

{"providerSubject":"Google sub value"}
```

Authlier refuses to unlink the account's last sign-in method.
