// Package emailaddress normalizes email identities.
package emailaddress

import (
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

const maximumLength = 254

var ErrInvalid = errors.New("invalid email address")

type Normalizer func(rawEmail string) (string, error)

func Normalize(rawEmail string) (string, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(rawEmail))
	if !Valid(normalizedEmail) {
		return "", ErrInvalid
	}
	return normalizedEmail, nil
}

func Valid(normalizedEmail string) bool {
	if normalizedEmail == "" || normalizedEmail != strings.TrimSpace(normalizedEmail) ||
		len(normalizedEmail) > maximumLength || !utf8.ValidString(normalizedEmail) {
		return false
	}
	parsed, err := mail.ParseAddress(normalizedEmail)
	return err == nil && parsed.Address == normalizedEmail
}
