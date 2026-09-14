package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type Algorithm string

const (
	Argon2id Algorithm = "argon2id"
	Bcrypt   Algorithm = "bcrypt"

	DefaultAlgorithm = Argon2id
	// BcryptMaximumPasswordLength is bcrypt's password input limit in bytes.
	BcryptMaximumPasswordLength = 72

	argon2Version            = argon2.Version
	argon2Memory      uint32 = 19 * 1024
	argon2Iterations  uint32 = 2
	argon2Parallelism uint8  = 1
	argon2SaltLength         = 16
	argon2KeyLength          = 32
	bcryptCost               = 12

	maximumEncodedLength     = 512
	maximumArgon2Memory      = 256 * 1024
	maximumArgon2Iterations  = 10
	maximumArgon2Parallelism = 16
	maximumArgon2SaltLength  = 64
	maximumArgon2KeyLength   = 64
)

var (
	ErrInvalidHash          = errors.New("invalid password hash")
	ErrPasswordTooLong      = errors.New("password is too long for the selected algorithm")
	ErrUnsupportedAlgorithm = errors.New("unsupported password algorithm")
)

type Verification struct {
	Matches     bool
	NeedsRehash bool
}

type argon2Parameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func Hash(plainPassword string) (string, error) {
	return HashWithAlgorithm(plainPassword, DefaultAlgorithm)
}

func HashWithAlgorithm(plainPassword string, algorithm Algorithm) (string, error) {
	switch algorithm {
	case Argon2id:
		return hashArgon2id(plainPassword)
	case Bcrypt:
		encodedHash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcryptCost)
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", ErrPasswordTooLong
		}
		if err != nil {
			return "", fmt.Errorf("hash password with bcrypt: %w", err)
		}
		return string(encodedHash), nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algorithm)
	}
}

func Verify(plainPassword, encodedHash string) (Verification, error) {
	return VerifyWithAlgorithm(plainPassword, encodedHash, DefaultAlgorithm)
}

func VerifyWithAlgorithm(
	plainPassword string,
	encodedHash string,
	preferredAlgorithm Algorithm,
) (Verification, error) {
	if !supported(preferredAlgorithm) {
		return Verification{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, preferredAlgorithm)
	}

	switch identify(encodedHash) {
	case Argon2id:
		verification, err := verifyArgon2id(plainPassword, encodedHash)
		if err != nil {
			return Verification{}, err
		}
		// A compatibility selection may write bcrypt, but it must never downgrade
		// an existing Argon2id credential after successful authentication.
		if preferredAlgorithm == Bcrypt {
			verification.NeedsRehash = false
		}
		return verification, nil
	case Bcrypt:
		return verifyBcrypt(plainPassword, encodedHash, preferredAlgorithm)
	default:
		return Verification{}, ErrInvalidHash
	}
}

func supported(algorithm Algorithm) bool {
	return algorithm == Argon2id || algorithm == Bcrypt
}

func identify(encodedHash string) Algorithm {
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		return Argon2id
	}
	if strings.HasPrefix(encodedHash, "$2a$") ||
		strings.HasPrefix(encodedHash, "$2b$") ||
		strings.HasPrefix(encodedHash, "$2y$") {
		return Bcrypt
	}
	return ""
}

func hashArgon2id(plainPassword string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(plainPassword),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	clear(key)

	return encoded, nil
}

func verifyArgon2id(plainPassword, encodedHash string) (Verification, error) {
	parsed, err := parseArgon2id(encodedHash)
	if err != nil {
		return Verification{}, err
	}

	candidate := argon2.IDKey(
		[]byte(plainPassword),
		parsed.salt,
		parsed.iterations,
		parsed.memory,
		parsed.parallelism,
		uint32(len(parsed.key)),
	)
	matches := subtle.ConstantTimeCompare(candidate, parsed.key) == 1
	clear(candidate)

	return Verification{
		Matches: matches,
		NeedsRehash: matches && (parsed.memory != argon2Memory ||
			parsed.iterations != argon2Iterations ||
			parsed.parallelism != argon2Parallelism ||
			len(parsed.salt) != argon2SaltLength ||
			len(parsed.key) != argon2KeyLength),
	}, nil
}

func verifyBcrypt(
	plainPassword string,
	encodedHash string,
	preferredAlgorithm Algorithm,
) (Verification, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(plainPassword))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return Verification{}, nil
	}
	if err != nil {
		return Verification{}, ErrInvalidHash
	}

	cost, err := bcrypt.Cost([]byte(encodedHash))
	if err != nil {
		return Verification{}, ErrInvalidHash
	}

	return Verification{
		Matches:     true,
		NeedsRehash: preferredAlgorithm != Bcrypt || cost != bcryptCost,
	}, nil
}

func parseArgon2id(encodedHash string) (argon2Parameters, error) {
	if len(encodedHash) == 0 || len(encodedHash) > maximumEncodedLength {
		return argon2Parameters{}, ErrInvalidHash
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != string(Argon2id) {
		return argon2Parameters{}, ErrInvalidHash
	}

	encodedVersion, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return argon2Parameters{}, ErrInvalidHash
	}
	parsedVersion, err := strconv.ParseUint(encodedVersion, 10, 32)
	if err != nil || parsedVersion != uint64(argon2Version) {
		return argon2Parameters{}, ErrInvalidHash
	}

	memoryValue, iterationValue, parallelismValue, err := parseArgon2Parameters(parts[3])
	if err != nil {
		return argon2Parameters{}, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > maximumArgon2SaltLength {
		return argon2Parameters{}, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) == 0 || len(key) > maximumArgon2KeyLength {
		return argon2Parameters{}, ErrInvalidHash
	}

	return argon2Parameters{
		memory:      memoryValue,
		iterations:  iterationValue,
		parallelism: parallelismValue,
		salt:        salt,
		key:         key,
	}, nil
}

func parseArgon2Parameters(encoded string) (uint32, uint32, uint8, error) {
	values := strings.Split(encoded, ",")
	if len(values) != 3 {
		return 0, 0, 0, ErrInvalidHash
	}

	parsed := make(map[string]uint64, len(values))
	for _, value := range values {
		key, raw, ok := strings.Cut(value, "=")
		if !ok || key == "" || raw == "" {
			return 0, 0, 0, ErrInvalidHash
		}
		if _, exists := parsed[key]; exists {
			return 0, 0, 0, ErrInvalidHash
		}

		number, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, 0, 0, ErrInvalidHash
		}
		parsed[key] = number
	}

	memoryValue, memoryExists := parsed["m"]
	iterationValue, iterationsExist := parsed["t"]
	parallelismValue, parallelismExists := parsed["p"]
	if !memoryExists || !iterationsExist || !parallelismExists || len(parsed) != 3 {
		return 0, 0, 0, ErrInvalidHash
	}
	if memoryValue == 0 || memoryValue > maximumArgon2Memory ||
		iterationValue == 0 || iterationValue > maximumArgon2Iterations ||
		parallelismValue == 0 || parallelismValue > maximumArgon2Parallelism {
		return 0, 0, 0, ErrInvalidHash
	}

	return uint32(memoryValue), uint32(iterationValue), uint8(parallelismValue), nil
}
