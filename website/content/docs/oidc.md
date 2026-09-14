---
title: OIDC SSO
description: Configure an OpenID Connect provider connection and identity resolver.
icon: Buildings
---

Register this callback URL with the identity provider:

```text
https://server.example.com/api/auth/sso/oidc/callback
```

Each connection supplies its own issuer, client credentials, callback URL, and
scopes:

```go
type oidcConnections struct {
	connections map[string]oidc.Connection
}

func (source oidcConnections) Find(
	ctx context.Context,
	connectionID string,
) (oidc.Connection, error) {
	connection, ok := source.connections[connectionID]
	if !ok {
		return oidc.Connection{}, oidc.ErrNotFound
	}
	return connection, nil
}
```

```go
connections := oidcConnections{connections: map[string]oidc.Connection{
	"acme": {
		ID:                   "acme",
		Issuer:               "https://idp.example.com",
		ClientID:             os.Getenv("ACME_OIDC_CLIENT_ID"),
		ClientSecret:         os.Getenv("ACME_OIDC_CLIENT_SECRET"),
		RedirectURL:          "https://server.example.com/api/auth/sso/oidc/callback",
		Scopes:               []string{"openid", "profile", "email"},
		RequireVerifiedEmail: true,
	},
}}
```

Connect the source and resolve the verified provider subject:

```go
OIDC: authlier.OIDCConfig{
	Enabled:     true,
	Connections: connections,
	ResolveIdentity: func(ctx context.Context, identity oidc.Identity) (string, error) {
		return ssoMappings.FindSubject(
			ctx,
			identity.ConnectionID,
			identity.ProviderSubject,
		)
	},
	SuccessRedirectURL: "https://client.example.com/account",
},
```

## Start sign-in

```ts
const response = await fetch('/api/auth/sso/oidc/sign-in', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ connectionId: 'acme' }),
});

const { url } = await response.json();
window.location.assign(url);
```

Authlier discovers the provider, uses state, nonce, and S256 PKCE, validates the
ID token, calls the resolver, and creates a session.

`SuccessRedirectURL` is the browser-client page opened after Authlier creates
the cookie session. OIDC is available only in cookie mode in this release; see
[Bearer tokens](/docs/bearer-tokens#browser-provider-flows).
