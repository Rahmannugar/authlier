package password_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Rahmannugar/authlier/password"
	"golang.org/x/crypto/argon2"
)

func TestDefaultPasswordHashCannotAuthenticateAnotherPassword(t *testing.T) {
	encodedHash, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		t.Fatalf("default hash does not use Argon2id: %q", encodedHash)
	}

	correct, err := password.Verify("correct horse battery staple", encodedHash)
	if err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if !correct.Matches {
		t.Fatal("correct password did not match")
	}
	if correct.NeedsRehash {
		t.Fatal("new hash unexpectedly needs rehashing")
	}

	incorrect, err := password.Verify("incorrect password", encodedHash)
	if err != nil {
		t.Fatalf("verify incorrect password: %v", err)
	}
	if incorrect.Matches {
		t.Fatal("incorrect password matched")
	}
}

func TestPasswordHashesUseIndependentSalts(t *testing.T) {
	first, err := password.Hash("same password")
	if err != nil {
		t.Fatalf("hash first password: %v", err)
	}
	second, err := password.Hash("same password")
	if err != nil {
		t.Fatalf("hash second password: %v", err)
	}
	if first == second {
		t.Fatal("same password produced identical hashes")
	}
}

func TestBcryptCanBeSelected(t *testing.T) {
	encodedHash, err := password.HashWithAlgorithm("password", password.Bcrypt)
	if err != nil {
		t.Fatalf("hash password with bcrypt: %v", err)
	}

	verification, err := password.VerifyWithAlgorithm("password", encodedHash, password.Bcrypt)
	if err != nil {
		t.Fatalf("verify bcrypt password: %v", err)
	}
	if !verification.Matches {
		t.Fatal("bcrypt password did not match")
	}
	if verification.NeedsRehash {
		t.Fatal("new bcrypt hash unexpectedly needs rehashing")
	}
}

func TestDefaultVerificationRequestsMigrationFromBcrypt(t *testing.T) {
	encodedHash, err := password.HashWithAlgorithm("password", password.Bcrypt)
	if err != nil {
		t.Fatalf("hash password with bcrypt: %v", err)
	}

	verification, err := password.Verify("password", encodedHash)
	if err != nil {
		t.Fatalf("verify bcrypt password: %v", err)
	}
	if !verification.Matches || !verification.NeedsRehash {
		t.Fatalf("expected matching bcrypt hash to request default migration: %+v", verification)
	}
}

func TestBcryptRejectsPasswordsBeyondItsInputLimit(t *testing.T) {
	_, err := password.HashWithAlgorithm(strings.Repeat("a", 73), password.Bcrypt)
	if !errors.Is(err, password.ErrPasswordTooLong) {
		t.Fatalf("expected password-too-long error, got %v", err)
	}
}

func TestUnsupportedAlgorithmIsRejected(t *testing.T) {
	_, err := password.HashWithAlgorithm("password", password.Algorithm("unknown"))
	if !errors.Is(err, password.ErrUnsupportedAlgorithm) {
		t.Fatalf("expected unsupported-algorithm error, got %v", err)
	}
}

func TestPasswordHashPreservesArbitraryUTF8AndNullBytes(t *testing.T) {
	plainPassword := " ọrọ aṣínà 🔐\x00 "
	encodedHash, err := password.Hash(plainPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	verification, err := password.Verify(plainPassword, encodedHash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !verification.Matches {
		t.Fatal("password with Unicode and null byte did not match")
	}
}

func TestMalformedAndUnboundedHashesAreRejected(t *testing.T) {
	tests := map[string]string{
		"empty":                "",
		"wrong algorithm":      "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$a2V5",
		"unsupported version":  "$argon2id$v=16$m=19456,t=2,p=1$c2FsdA$a2V5",
		"excessive memory":     "$argon2id$v=19$m=999999999,t=2,p=1$c2FsdA$a2V5",
		"excessive iterations": "$argon2id$v=19$m=19456,t=999,p=1$c2FsdA$a2V5",
		"duplicate parameter":  "$argon2id$v=19$m=19456,m=2,p=1$c2FsdA$a2V5",
		"invalid salt":         "$argon2id$v=19$m=19456,t=2,p=1$***$a2V5",
		"malformed bcrypt":     "$2b$12$invalid",
	}

	for name, encodedHash := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := password.Verify("password", encodedHash)
			if !errors.Is(err, password.ErrInvalidHash) {
				t.Fatalf("expected invalid hash error, got %v", err)
			}
		})
	}
}

func TestOlderValidArgon2ParametersRequestRehash(t *testing.T) {
	encodedHash := legacyArgon2Hash("password")
	verification, err := password.Verify("password", encodedHash)
	if err != nil {
		t.Fatalf("verify legacy hash: %v", err)
	}
	if !verification.Matches {
		t.Fatal("legacy hash did not match")
	}
	if !verification.NeedsRehash {
		t.Fatal("legacy parameters did not request rehashing")
	}
}

func legacyArgon2Hash(plainPassword string) string {
	const (
		memory      uint32 = 12 * 1024
		iterations  uint32 = 3
		parallelism uint8  = 1
	)
	salt := []byte("legacy-salt-1234")
	key := argon2.IDKey([]byte(plainPassword), salt, iterations, memory, parallelism, 32)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		iterations,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func TestOversizedEncodedHashIsRejected(t *testing.T) {
	encodedHash := "$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("a", 600) + "$a2V5"
	_, err := password.Verify("password", encodedHash)
	if !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("expected invalid hash error, got %v", err)
	}
}
