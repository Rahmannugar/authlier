# Contributing

Authlier requires Go 1.26 or newer.

Keep each change focused on one behavior. Add tests when the change protects
real authentication or storage behavior.

Run the standard checks before opening a pull request:

```bash
test -z "$(gofmt -l .)"
go test ./...
go vet ./...
go build ./...
```

Database behavior must also be tested against the real database. CI covers
PostgreSQL 17 and 18, MySQL 8.4 and 9, MongoDB 7 and 8, and Redis 7.4 and 8.
The adapter integration tests explain the environment variable each local test
uses.

Keep reusable authentication behavior in the package that owns it. The root
package connects enabled features to the standard HTTP handler. Database code
belongs under `storage/<database>`. Do not add application-specific roles,
organizations, billing, or authorization rules.

Never include passwords, raw tokens, provider secrets, or private signing keys
in tests, logs, issues, or pull requests. Report security problems privately as
described in [SECURITY.md](SECURITY.md).
