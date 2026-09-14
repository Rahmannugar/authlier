---
title: SAML SSO
description: Configure SAML Web SSO metadata, signing keys, and identity resolution.
icon: Buildings
---

Authlier acts as the SAML service provider. A SAML connection supplies the
identity-provider metadata and the service-provider signing certificate.

```go
type samlConnections struct {
	connections map[string]saml.Connection
}

func (source samlConnections) Find(
	ctx context.Context,
	connectionID string,
) (saml.Connection, error) {
	connection, ok := source.connections[connectionID]
	if !ok {
		return saml.Connection{}, saml.ErrNotFound
	}
	return connection, nil
}
```

```go
saml.Connection{
	ID:               "acme",
	EntityID:         "https://server.example.com/api/auth/sso/saml/metadata?connectionId=acme",
	ACSURL:           "https://server.example.com/api/auth/sso/saml/callback",
	IDPMetadata:      metadataXML,
	PrivateKey:       signingKey,
	Certificate:      signingCertificate,
	EmailAttribute:   "email",
	NameAttribute:    "name",
	RequireEmail:     true,
}
```

With `SubjectAttribute` left empty, Authlier requires the identity provider to
return a persistent NameID and uses it as the stable provider subject. If the
provider cannot return a persistent NameID, set `SubjectAttribute` to the name
of an immutable identifier attribute supplied by that provider. Do not use an
email address as the subject because email addresses can change.

`IDPMetadata` can contain fetched and validated metadata. Set `MetadataURL`
instead when Authlier should retrieve it while handling the flow. Keep private
keys outside source control.

Configure Authlier with the connection source and a resolver:

```go
SAML: authlier.SAMLConfig{
	Enabled:     true,
	Connections: connections,
	ResolveIdentity: func(ctx context.Context, identity saml.Identity) (string, error) {
		return ssoMappings.FindSubject(
			ctx,
			identity.ConnectionID,
			identity.ProviderSubject,
		)
	},
	SuccessRedirectURL: "https://client.example.com/account",
},
```

## Provider setup

Give the identity provider the connection-specific metadata URL:

```text
GET https://server.example.com/api/auth/sso/saml/metadata?connectionId=acme
```

The assertion consumer service URL is:

```text
POST https://server.example.com/api/auth/sso/saml/callback
```

Start sign-in by posting `{"connectionId":"acme"}` to
`/api/auth/sso/saml/sign-in`, then redirect the browser to the returned `url`.
The identity provider posts its response to the callback. Authlier validates
the response and request state before calling your resolver.

`SuccessRedirectURL` is the browser-client page opened after Authlier creates
the cookie session. SAML is available only in cookie mode in this release; see
[Bearer tokens](/docs/bearer-tokens#browser-provider-flows).
