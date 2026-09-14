---
title: Standards and dependencies
description: Security guidance, protocol standards, and established Go libraries used by Authlier.
icon: Books
---

Authlier does not invent password hashing, WebAuthn, OAuth, OIDC, SAML, or TOTP.
It builds its server-side authentication flows on published standards and
established Go libraries, then adds consistent configuration, storage, session
handling, and HTTP routes.

## Security guidance

Authlier uses the following OWASP material as engineering and verification
input:

- [Application Security Verification Standard 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Protocol Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

These references guide the implementation and review of Authlier. They do not
mean that OWASP has certified Authlier or that every application using the
library automatically satisfies ASVS. The [Security](/docs/security) guide
explains the controls that remain the application's responsibility.

## Protocol standards

- Passwordless authentication follows [Web Authentication: Level 3](https://www.w3.org/TR/webauthn-3/).
- Google authentication uses the OAuth 2.0 Authorization Code flow defined by [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749).
- Bearer access tokens use the JSON Web Token format defined by [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) and Ed25519 signatures defined by [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
- OIDC SSO follows [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).
- SAML SSO uses the [SAML 2.0 standard](https://www.oasis-open.org/standard/saml/).
- Authenticator codes follow [TOTP: Time-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc6238).

## Go libraries

Authlier uses focused libraries for protocol and cryptographic work:

- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) provides password-hashing primitives.
- [`golang-jwt/jwt`](https://github.com/golang-jwt/jwt) creates and validates JWT access tokens.
- [`coreos/go-oidc`](https://github.com/coreos/go-oidc) verifies OpenID Connect identities.
- [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) implements OAuth 2.0 client flows.
- [`go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) implements WebAuthn ceremonies and verification.
- [`crewjam/saml`](https://github.com/crewjam/saml) and [`goxmldsig`](https://github.com/russellhaering/goxmldsig) parse and verify SAML messages and XML signatures.
- [`pquerna/otp`](https://github.com/pquerna/otp) implements TOTP generation and validation.

Official storage adapters use the established PostgreSQL, MySQL, MongoDB, and
Redis Go drivers. The [Storage](/docs/storage) guide explains when to choose each
adapter.
