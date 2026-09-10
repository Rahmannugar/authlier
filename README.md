# Authlier

Authlier is an authentication library for Go applications. It provides secure authentication capabilities through a clear, composable API.

## Installation

```bash
go get github.com/Rahmannugar/authlier
```

## Passwords

The password package supports Argon2id and bcrypt. Argon2id is the default.
Stored hashes are self-describing, use algorithm-appropriate secure parameters,
and can be verified without separately storing the selected algorithm.
Verification reports when a matching hash should be replaced with the preferred
algorithm or current work factor.

```go
encodedHash, err := password.Hash(plainPassword)
if err != nil {
	return err
}

verification, err := password.Verify(plainPassword, encodedHash)
if err != nil {
	return err
}
if !verification.Matches {
	return errors.New("invalid credentials")
}
```

Applications that require bcrypt can select it explicitly:

```go
encodedHash, err := password.HashWithAlgorithm(plainPassword, password.Bcrypt)
verification, err := password.VerifyWithAlgorithm(
	plainPassword,
	encodedHash,
	password.Bcrypt,
)
```

Applications remain responsible for password policy. Passwords and password
hashes must never be logged.

## Security

Security reports should be submitted privately according to
[`SECURITY.md`](SECURITY.md).

## License

Authlier is licensed under the Apache License 2.0.
