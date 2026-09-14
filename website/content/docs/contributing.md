---
title: Contributing
description: Report issues, propose changes, and contribute code to Authlier.
icon: GitPullRequest
---

Authlier welcomes bug reports, feature proposals, documentation improvements,
and focused code contributions. Authentication changes can affect every
application using the library, so discuss significant behavior before building
it.

## Report a problem or propose a feature

Search the [existing GitHub issues](https://github.com/Rahmannugar/authlier/issues)
first. Open a new issue when the problem or proposal is not already covered.
Include the Authlier version, expected behavior, actual behavior, and a small
reproduction when possible.

Do not report a suspected vulnerability in a public issue. Follow the private
process in the repository's
[`SECURITY.md`](https://github.com/Rahmannugar/authlier/blob/main/SECURITY.md).

## Prepare a code change

1. Fork the [Authlier repository](https://github.com/Rahmannugar/authlier).
2. Create a focused branch from `main`.
3. Make one coherent change and add tests for meaningful behavior.
4. Update the relevant public guide when behavior or configuration changes.
5. Push the branch to your fork and open a pull request against `main`.

Keep reusable authentication behavior in the package that owns it. The root
package composes enabled features and provides the HTTP handler. Official
database code belongs under `storage/<database>`. Application-specific roles,
organizations, billing, and authorization do not belong in Authlier.

## Run the checks

Run the Go checks from the repository root:

```bash
test -z "$(gofmt -l .)"
go test ./...
go vet ./...
go build ./...
```

Storage changes also need integration tests against the real supported
database. An in-memory substitute cannot verify database transactions,
uniqueness, or concurrency behavior.

For documentation website changes, use Bun:

```bash
cd website
bun install --frozen-lockfile
bun run lint
bun run types:check
bun run build
```

## Open the pull request

Explain what changed, why the change is needed, and how it was tested. Keep
unrelated changes in separate pull requests. Never include real passwords,
tokens, personal data, provider secrets, or private signing keys in code,
tests, logs, issues, or pull requests.

The repository's
[`CONTRIBUTING.md`](https://github.com/Rahmannugar/authlier/blob/main/CONTRIBUTING.md)
is the canonical contributor policy.
