# Contributing

Authlier requires Go 1.26 or newer.

## Before you begin

Search the existing issues before opening a new one. Open an issue for a bug,
feature request, or significant design change so the behavior can be agreed on
before implementation. Do not open a public issue for a suspected security
problem; follow the private process in [SECURITY.md](SECURITY.md).

## Make a change

1. Fork the repository and create a branch from `main`.
2. Keep the change focused on one behavior.
3. Add tests when they protect real authentication or storage behavior.
4. Update the relevant documentation when public behavior changes.

Keep reusable authentication behavior in the package that owns it. The root
package connects enabled features to the HTTP handler. Database code belongs
under `storage/<database>`. Do not add application-specific roles,
organizations, billing, or authorization rules.

Never include passwords, raw tokens, provider secrets, or private signing keys
in tests, logs, issues, or pull requests.

## Run the checks

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

For website changes, install dependencies with Bun and run:

```bash
cd website
bun run lint
bun run types:check
bun run build
```

## Open a pull request

Push the branch to your fork and open a pull request against `main`. Explain
what changed, why it changed, and how you tested it. Keep unrelated changes in
separate pull requests so each review has one clear purpose.
