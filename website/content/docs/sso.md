---
title: Single sign-on
description: Understand how Authlier connects OIDC and SAML identities to application users.
icon: Buildings
---

Single sign-on lets an organization use its existing identity provider to
authenticate users. Authlier supports the browser-based OIDC and SAML Web SSO
flows. Your application stores one named connection per organization or
customer and decides which verified provider identity maps to which Authlier
user.

Both protocols follow the same flow:

1. The browser chooses a connection ID.
2. Authlier loads that connection and starts the provider flow.
3. Authlier validates the callback and returns a verified provider identity.
4. Your identity resolver maps that identity to an Authlier subject ID.
5. Authlier creates the session.

Authlier owns protocol validation and session creation. Your application owns
connection records, organization entitlement, membership lookup, and the
decision to allow or deny the identity. This separation prevents a client from
choosing trusted provider settings and prevents Authlier from inventing your
organization model.

## Connection sources

OIDC and SAML each accept a `ConnectionSource`. Its `Find` method loads the
provider configuration for one connection ID. The source can read from your
database, secrets service, or static application configuration.

For example, the client may submit `connectionId: "acme"`. The source then
loads Acme's issuer, client credentials, certificate, or metadata from trusted
server-side storage. Do not accept those provider settings from the browser.

## Identity resolvers

The resolver runs after protocol verification. Look up the mapping using both
the connection ID and stable provider subject, then return the Authlier subject
ID only when the connection and application membership are active. Returning an
error denies sign-in.

Do not link an existing account automatically because an SSO email matches.

Continue with [OIDC](/docs/oidc) or [SAML](/docs/saml).
