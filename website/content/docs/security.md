---
title: Security
description: Configure the application responsibilities around Authlier's authentication flows.
icon: Shield
---

Authlier handles authentication primitives, but secure deployment still
depends on the application and its infrastructure.

## OWASP guidance

Authlier uses [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
and relevant OWASP Cheat Sheets as engineering and verification inputs. The
authentication, session-management, password-storage, password-recovery, and
multifactor-authentication guidance informs the corresponding Authlier flows.

This is not a claim that OWASP has certified Authlier or that the library has
completed every ASVS requirement. Applications must still assess the controls
required by their own environment and threat model. See
[Standards and dependencies](references.md) for the specific references and Go
libraries used by Authlier.

## Use HTTPS

Set `BaseURL` to the public HTTPS origin in production. Authlier then marks the
session cookie as Secure. Passkeys also require a secure browser context outside
localhost.

## Protect secrets

Keep provider client secrets, signing keys, database credentials, and TOTP
encryption keys outside source control. Do not log passwords, raw session
tokens, recovery codes, verification tokens, reset tokens, OAuth codes, or SAML
responses.

## Add abuse protection

Authentication methods accept feature-specific `AttemptGuard` implementations.
Use them to limit repeated attempts by operation, account identifier, and
trusted client address. Configure `TrustedProxies` only for proxies you operate;
otherwise a caller may forge the forwarded address used by the guard.

## Deliver security events

Feature configurations accept `SecurityEvents` sinks. Send meaningful events
to the application's audit or notification system without including secrets.
Recording should be bounded and should not expose authentication timing to the
caller.

## Preserve account recovery

Authlier prevents password, Google, or passkey removal when that credential is
the last available sign-in method. The application should also require a recent
session before sensitive enrollment, linking, or credential replacement.

## Keep dependencies current

Authlier delegates password hashing and authentication protocols to established
libraries. Review Authlier releases and dependency advisories regularly rather
than assuming a pinned dependency remains safe indefinitely.

Report suspected vulnerabilities through the private process in
[`SECURITY.md`](https://github.com/Rahmannugar/authlier/blob/main/SECURITY.md).
