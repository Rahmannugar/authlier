---
title: SAML SSO
description: Configure SAML Web SSO metadata, signing keys, and identity resolution.
icon: Buildings
---

SAML Web SSO lets an organization authenticate through a SAML identity
provider. Authlier acts as the service provider: it creates the authentication
request, validates the posted SAML response, resolves the verified identity,
and creates the cookie session.

Before configuring this page, decide how your application stores organization
connections and maps a stable provider identity to an Authlier subject ID. The
[Single sign-on overview](/docs/sso) explains that boundary.

## Provide a connection source

The browser submits a connection ID. Authlier uses the source to load trusted
identity-provider metadata and service-provider keys from server-side storage:

Each returned connection contains the provider and service-provider settings:

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

`IDPMetadata` can contain metadata that your application fetched and accepted.
Set `MetadataURL`
instead when Authlier should retrieve it while handling the flow. Keep private
keys outside source control.

## Map the verified identity

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

The resolver runs only after Authlier verifies the SAML response. It should use
both the connection ID and provider subject to find the Authlier user. Returning
an error denies sign-in.

## Configure the identity provider

Give the identity provider the connection-specific metadata URL:

```text
GET https://server.example.com/api/auth/sso/saml/metadata?connectionId=acme
```

The assertion consumer service URL is:

```text
POST https://server.example.com/api/auth/sso/saml/callback
```

## Start sign-in

The browser starts sign-in by posting `{"connectionId":"acme"}` to
`/api/auth/sso/saml/sign-in`, then redirect the browser to the returned `url`.
The identity provider posts its response to the callback. Authlier validates
the response and request state before calling your resolver.

`SuccessRedirectURL` is the frontend page opened after Authlier creates
the cookie session. SAML is available only in cookie mode in this release; see
[Bearer tokens](/docs/bearer-tokens#browser-provider-flows).
