package token_test

import (
	"errors"
	"testing"

	"github.com/Rahmannugar/authlier/token"
)

func TestGeneratedTokensAreRandomCanonicalValues(t *testing.T) {
	first, firstHash, err := token.Generate()
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}
	second, _, err := token.Generate()
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}
	if first == second {
		t.Fatal("independent generations produced the same token")
	}
	if len(first) != 43 {
		t.Fatalf("encoded 256-bit token length = %d, want 43", len(first))
	}
	computedHash, err := token.HashToken(first)
	if err != nil {
		t.Fatalf("hash generated token: %v", err)
	}
	if computedHash != firstHash {
		t.Fatal("generated token does not match its hash")
	}

	invalid := []string{"", "short", first + "=", first[:42] + "+"}
	for _, rawToken := range invalid {
		if _, err := token.HashToken(rawToken); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("HashToken(%q): got %v, want invalid token", rawToken, err)
		}
	}
}
