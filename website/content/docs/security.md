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
[Standards and dependencies](/docs/references) for the specific references and
Go libraries used by Authlier.

## Use HTTPS

Set `BaseURL` to the public HTTPS origin in production. Authlier then marks the
session cookie as Secure. Passkeys also require a secure browser context outside
localhost.

## Protect secrets

Keep provider client secrets, signing keys, database credentials, and TOTP
encryption keys outside source control. Do not log passwords, raw session
tokens, recovery codes, verification tokens, reset tokens, OAuth codes, or SAML
responses.

In bearer mode, keep the Ed25519 private key in server secret storage and use a
distinct `KeyID` when rotating it. Native clients should keep refresh tokens in
the operating system's protected credential storage. A browser application
using bearer mode must account for script injection and should avoid persistent
JavaScript-readable refresh-token storage where possible. Never put refresh
tokens in URLs, logs, analytics, or crash reports.

Bearer access tokens are short-lived, but Authlier also checks their durable
session on every request. Preserve that check by using `ResolveSession` rather
than trusting decoded JWT claims on their own.

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

## Prefer Argon2id for passwords

Authlier uses Argon2id for new passwords by default. Keep that default for new
applications. Select bcrypt only when a legacy system must remain compatible
with newly written credentials during a staged migration. Authlier can verify
both formats, upgrades bcrypt credentials to Argon2id after successful sign-in
when Argon2id is selected, and never automatically downgrades an existing
Argon2id credential to bcrypt. See [Email and password](/docs/email-password)
for the complete migration behavior.

## Keep dependencies current

Authlier delegates password hashing and authentication protocols to established
libraries. Review Authlier releases and dependency advisories regularly rather
than assuming a pinned dependency remains safe indefinitely.

Report suspected vulnerabilities through the private process in
[`SECURITY.md`](https://github.com/Rahmannugar/authlier/blob/main/SECURITY.md).
