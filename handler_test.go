package authlier

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestSourceKeyUsesForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	handler := &httpHandler{trustedProxies: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}}

	trustedRequest := httptest.NewRequest("GET", "https://app.example.com", nil)
	trustedRequest.RemoteAddr = "10.0.0.2:443"
	trustedRequest.Header.Set("X-Forwarded-For", "203.0.113.20, 10.0.0.3")
	if source := handler.sourceKey(trustedRequest); source != "203.0.113.20" {
		t.Fatalf("trusted proxy source = %q", source)
	}

	untrustedRequest := httptest.NewRequest("GET", "https://app.example.com", nil)
	untrustedRequest.RemoteAddr = "198.51.100.4:443"
	untrustedRequest.Header.Set("X-Forwarded-For", "203.0.113.20")
	if source := handler.sourceKey(untrustedRequest); source != "198.51.100.4" {
		t.Fatalf("untrusted peer source = %q", source)
	}
}
