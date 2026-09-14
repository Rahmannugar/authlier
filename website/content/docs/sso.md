---
title: Single sign-on
description: Understand how Authlier connects OIDC and SAML identities to application users.
icon: Buildings
---

Authlier supports organization SSO through OIDC and SAML Web SSO. Both flows
use the same application boundary:

1. The browser chooses a connection ID.
2. Authlier loads that connection and starts the provider flow.
3. Authlier validates the callback and returns a verified provider identity.
4. Your identity resolver maps that identity to an Authlier subject ID.
5. Authlier creates the session.

Authlier owns protocol validation. Your application owns connection records,
organization entitlement, membership lookup, and the decision to allow or deny
the identity.

## Connection sources

OIDC and SAML each accept a `ConnectionSource`. Its `Find` method loads the
provider configuration for one connection ID. The source can read from your
database, secrets service, or static application configuration.

Do not let a browser submit issuer URLs, client secrets, certificates, or
provider metadata directly. The browser submits only the connection ID.

## Identity resolvers

The resolver receives a verified identity. Look up the mapping using both the
connection ID and stable provider subject. Return the Authlier user ID only
when the connection and application membership are active.

Do not link an existing account automatically because an SSO email matches.

Continue with [OIDC](/docs/oidc) or [SAML](/docs/saml).
