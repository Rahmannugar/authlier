---
title: Passkeys
description: Configure WebAuthn registration, discoverable sign-in, and credential removal.
icon: Fingerprint
---

Passkeys use WebAuthn. Authlier creates the server options, stores one-time
ceremony state, verifies the browser response, and stores the complete
credential record.

```go
Passkeys: authlier.PasskeyConfig{
	Enabled: true,
},
```

By default, the relying-party ID comes from `BaseURL`, the relying-party name
comes from `AppName`, and allowed origins include `BaseURL` and
`TrustedOrigins`. Set those fields explicitly when the public WebAuthn origin
differs from the application URL.

WebAuthn requires HTTPS outside localhost.

## Register a passkey

Registration requires a recent session. Request options, ask the browser to
create a credential, and return that credential with the ceremony token:

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

Successful verification creates the Authlier session.

List credentials with `GET /api/auth/passkey/list`. Remove one by sending its
returned `credentialId` to `POST /api/auth/passkey/remove`. Removal requires a
recent session and cannot delete the account's last sign-in method.
