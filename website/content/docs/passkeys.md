---
title: Passkeys
description: Configure WebAuthn registration, discoverable sign-in, and credential removal.
icon: Fingerprint
---

Passkeys use WebAuthn to authenticate with a device credential instead of a
password. Authlier creates the WebAuthn options, stores one-time ceremony state,
verifies the browser response, stores the public credential, and creates the
session. The browser or device keeps the private key.

## Configure the Go server

```go
Passkeys: authlier.PasskeyConfig{
	Enabled: true,
},
```

The relying party is the site for which a passkey is valid. By default,
`RelyingPartyID` is the hostname from `BaseURL`, `RelyingPartyName` is
`AppName`, and allowed `Origins` contain `BaseURL` and `TrustedOrigins`. Set
these fields explicitly when the browser-facing WebAuthn domain differs from
the Go server URL.

WebAuthn requires HTTPS outside localhost.

## Register a passkey

Registration adds a passkey to an existing Authlier user, so it requires a
recent session. The browser client first requests options from the Go server,
asks WebAuthn to create the credential, and returns the response with Authlier's
ceremony token:

```js
const started = await fetch('/api/auth/passkey/register/options', {
  method: 'POST',
}).then((response) => response.json());

const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
  started.options.publicKey,
);

const credential = await navigator.credentials.create({ publicKey });

await fetch('/api/auth/passkey/register/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    ceremonyToken: started.ceremonyToken,
    response: credential,
  }),
});
```

The WebAuthn JSON convenience methods are available in current browsers but
may be missing on older devices. Use a tested WebAuthn JSON compatibility
helper when supporting those browsers.

## Sign in with a passkey

```js
const started = await fetch('/api/auth/passkey/sign-in/options', {
  method: 'POST',
}).then((response) => response.json());

const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
  started.options.publicKey,
);

const credential = await navigator.credentials.get({ publicKey });

await fetch('/api/auth/passkey/sign-in/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    ceremonyToken: started.ceremonyToken,
    response: credential,
  }),
});
```

Unlike registration, discoverable passkey sign-in starts without a session.
Successful verification identifies the Authlier user and creates the configured
session.

List credentials with `GET /api/auth/passkey/list`. Remove one by sending its
returned `credentialId` to `POST /api/auth/passkey/remove`. Removal requires a
recent session and cannot delete the account's last sign-in method.
