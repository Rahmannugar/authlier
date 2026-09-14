---
title: Lower-level packages
description: Compose Authlier managers directly when the standard HTTP handler does not fit.
icon: Package
---

Most applications should begin with `authlier.New` and `auth.Handler()`. That
path connects configuration, storage, cookies, session creation, and the
standard routes in one place.

The capability packages remain public for applications that need another
transport or a deliberately different workflow. For example, an application
can create an `emailpassword.Manager`, call it from an RPC method, and create a
session through `sessiontoken.Manager` after authentication succeeds.

Direct composition also transfers more responsibility to the application. It
must preserve the same ordering and security behavior as the standard handler,
including:

- origin or CSRF protection at the transport boundary;
- abuse checks and non-enumerating public responses;
- session creation only after every required authentication step succeeds;
- recent authentication before sensitive credential changes;
- secure cookie handling when opaque browser sessions are used;
- protected refresh-token storage and rotation when bearer sessions are used;
- stable error translation that does not expose internal failures.

Use lower-level packages because the application needs a different boundary,
not merely to rename Authlier's routes. The standard handler is easier to keep
correct when a browser client communicates with a Go server over HTTP.

The public `password` package also exposes `HashWithAlgorithm` and
`VerifyWithAlgorithm` for deliberately composed workflows. Applications using
the standard handler should select `EmailAndPassword.PasswordHashAlgorithm`
instead so sign-up, credential changes, recovery, dummy verification, and hash
upgrades share one policy.
