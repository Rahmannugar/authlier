// Package token generates and hashes opaque bearer credentials.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const entropyBytes = 32

var ErrInvalidToken = errors.New("invalid token")

// Hash is the durable representation of an opaque token.
type Hash [sha256.Size]byte

// Generate creates a URL-safe token with 256 bits of CSPRNG entropy.
func Generate() (string, Hash, error) {
	random := make([]byte, entropyBytes)
	if _, err := rand.Read(random); err != nil {
		return "", Hash{}, err
	}
	return base64.RawURLEncoding.EncodeToString(random), sha256.Sum256(random), nil
}

// HashToken validates the canonical encoding and hashes an incoming token.
func HashToken(rawToken string) (Hash, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(rawToken)
	if err != nil || len(decoded) != entropyBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != rawToken {
		return Hash{}, ErrInvalidToken
	}
	return sha256.Sum256(decoded), nil
}
