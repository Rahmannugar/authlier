---
title: Application data and authorization
description: Connect an Authlier identity to profiles, roles, and permissions owned by your application.
icon: User
---

Authlier answers one question: who authenticated? Your application answers what
that person can see or change.

Every Authlier user has a stable ID. A resolved session exposes it as
`SubjectID`:

```go
session, err := auth.ResolveSession(request)
if err != nil {
	http.Error(response, "not authenticated", http.StatusUnauthorized)
	return
}

profile, err := profiles.FindByAuthlierSubject(request.Context(), session.SubjectID)
```

Store the Authlier subject ID on the application profile or membership that it
belongs to. Keep display names, avatars, organizations, roles, permissions,
billing state, and suspension rules in the application database.

Google, OIDC, and SAML identities ultimately resolve to the same Authlier
subject ID. An email address is profile data and can change. Do not use an
email address as the durable key for a provider account.
