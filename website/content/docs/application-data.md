---
title: Application data and authorization
description: Connect an Authlier identity to profiles, roles, and permissions owned by your application.
icon: User
---

Authlier owns authentication records. It verifies a sign-in method and gives
each authenticated account a stable subject ID. Your application owns the
profile and decides what that subject may access.

For example, an application profile can store the relationship like this:

| Application profile field | Example |
| --- | --- |
| `id` | Your application's profile ID |
| `authlier_subject_id` | The stable Authlier user ID |
| `display_name` | Application data |
| `role` | Application authorization data |

Do not copy application roles or billing state into Authlier. Do not use an
email address as the relationship key because a user can change it.

## Load application data in a request

Every Authlier user has a stable ID. A resolved session exposes it as
`SubjectID`:

```go
session, err := auth.ResolveSession(request)
if err != nil {
	http.Error(response, "not authenticated", http.StatusUnauthorized)
	return
}

profile, err := profiles.FindByAuthlierSubject(request.Context(), session.SubjectID)
if err != nil {
	http.Error(response, "profile not found", http.StatusNotFound)
	return
}

if !profile.CanViewAccount {
	http.Error(response, "forbidden", http.StatusForbidden)
	return
}
```

`ResolveSession` proves that the request has a valid Authlier session. Looking
up the profile connects that authenticated identity to application data. The
final permission check remains application behavior.

## Create the relationship

Email-and-password sign-up returns `user.id`; store that value as the Authlier
subject ID when creating the application's profile. Google sign-in links a
Google account to an Authlier user. OIDC and SAML use the identity resolver you
provide to return an existing application subject ID.

Google, OIDC, and SAML identities ultimately resolve to the same Authlier
subject ID. An email address is profile data and can change. Do not use an
email address as the durable key for a provider account.
