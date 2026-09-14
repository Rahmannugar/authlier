package saml

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	samllibrary "github.com/crewjam/saml"
)

var fixedTime = time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)

func TestWebSSOConsumesTheRequestAndReturnsAStableIdentity(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections(t)
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)

	started, err := manager.Begin(context.Background(), BeginInput{ConnectionID: "company-sso"})
	if err != nil {
		t.Fatalf("begin SAML authentication: %v", err)
	}
	request := store.latestRequest()
	if started.State == "" || provider.state != started.State || request.RequestID != "request-1" {
		t.Fatalf("unexpected authentication request: started=%+v stored=%+v", started, request)
	}
	provider.identity = providerIdentity{
		Issuer:          "https://idp.example.com/metadata",
		ProviderSubject: "provider-user-1",
		SubjectFormat:   string(samllibrary.PersistentNameIDFormat),
		Email:           " OWNER@Example.COM ",
		Name:            "Owner",
		SessionIndex:    "idp-session-1",
	}

	identity, err := manager.Complete(context.Background(), CompleteInput{
		State:        started.State,
		SAMLResponse: "encoded-response",
	})
	if err != nil {
		t.Fatalf("complete SAML authentication: %v", err)
	}
	if identity.ConnectionID != "company-sso" ||
		identity.ProviderSubject != "provider-user-1" ||
		identity.Email != "owner@example.com" || provider.completedRequestID != "request-1" {
		t.Fatalf("unexpected SAML identity: %+v", identity)
	}
	if _, err := manager.Complete(context.Background(), CompleteInput{
		State:        started.State,
		SAMLResponse: "encoded-response",
	}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replay SAML response: got %v, want invalid state", err)
	}

	metadata, err := manager.Metadata(context.Background(), "company-sso")
	if err != nil || string(metadata) != "service-provider-metadata" {
		t.Fatalf("create metadata: metadata=%q error=%v", metadata, err)
	}
}

func TestConnectionChangeInvalidatesPendingRequest(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections(t)
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)
	started, err := manager.Begin(context.Background(), BeginInput{ConnectionID: "company-sso"})
	if err != nil {
		t.Fatalf("begin SAML authentication: %v", err)
	}
	connection := connections.values["company-sso"]
	connection.SubjectAttribute = "immutable-user-id"
	connections.values[connection.ID] = connection

	_, err = manager.Complete(context.Background(), CompleteInput{
		State:        started.State,
		SAMLResponse: "encoded-response",
	})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("complete after connection change: got %v, want invalid state", err)
	}
	if provider.completeCalls != 0 {
		t.Fatal("changed connection reached assertion validation")
	}
}

func TestConcurrentCompletionConsumesRequestOnce(t *testing.T) {
	store := newMemoryStore()
	connections := newConnections(t)
	provider := &fakeProtocol{}
	manager := newTestManager(store, connections, provider)
	started, err := manager.Begin(context.Background(), BeginInput{ConnectionID: "company-sso"})
	if err != nil {
		t.Fatalf("begin SAML authentication: %v", err)
	}
	provider.identity = providerIdentity{
		Issuer:          "https://idp.example.com/metadata",
		ProviderSubject: "provider-user-1",
	}

	var successes atomic.Int32
	var rejected atomic.Int32
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := manager.Complete(context.Background(), CompleteInput{
				State:        started.State,
				SAMLResponse: "encoded-response",
			})
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ErrInvalidState) {
				rejected.Add(1)
			} else {
				t.Errorf("unexpected completion error: %v", err)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 || rejected.Load() != 1 {
		t.Fatalf("successes=%d rejected=%d, want one each", successes.Load(), rejected.Load())
	}
}

func TestAssertionUsesConfiguredStableSubjectAndRejectsTransientNameID(t *testing.T) {
	assertion := &samllibrary.Assertion{
		Issuer: samllibrary.Issuer{Value: "https://idp.example.com/metadata"},
		Subject: &samllibrary.Subject{NameID: &samllibrary.NameID{
			Format: string(samllibrary.TransientNameIDFormat),
			Value:  "temporary-user",
		}},
		AttributeStatements: []samllibrary.AttributeStatement{{
			Attributes: []samllibrary.Attribute{{
				Name:   "immutable-user-id",
				Values: []samllibrary.AttributeValue{{Value: "provider-user-1"}},
			}},
		}},
	}
	if _, err := identityFromAssertion(Connection{}, assertion); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("transient NameID: got %v, want invalid identity", err)
	}
	identity, err := identityFromAssertion(Connection{SubjectAttribute: "immutable-user-id"}, assertion)
	if err != nil || identity.ProviderSubject != "provider-user-1" {
		t.Fatalf("configured stable subject: identity=%+v error=%v", identity, err)
	}
	assertion.Subject = nil
	identity, err = identityFromAssertion(Connection{SubjectAttribute: "immutable-user-id"}, assertion)
	if err != nil || identity.ProviderSubject != "provider-user-1" {
		t.Fatalf("stable subject without NameID: identity=%+v error=%v", identity, err)
	}
}

func TestProtocolBuildsSignedRedirectAndServiceProviderMetadata(t *testing.T) {
	connection := newConnections(t).values["company-sso"]
	provider := samlProtocol{}
	authorizationURL, requestID, err := provider.Begin(connection, "state-token")
	if err != nil {
		t.Fatalf("build SAML redirect: %v", err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse SAML redirect: %v", err)
	}
	query := parsed.Query()
	if requestID == "" || query.Get("RelayState") != "state-token" ||
		query.Get("SAMLRequest") == "" || query.Get("SigAlg") == "" || query.Get("Signature") == "" {
		t.Fatalf("incomplete signed SAML redirect: %s", authorizationURL)
	}
	metadata, err := provider.Metadata(connection)
	if err != nil || !strings.Contains(string(metadata), connection.EntityID) {
		t.Fatalf("create service-provider metadata: metadata=%q error=%v", metadata, err)
	}
}

func newTestManager(store Store, connections ConnectionSource, provider protocol) *Manager {
	return &Manager{
		store:       store,
		connections: connections,
		protocol:    provider,
		lifetime:    time.Minute,
		now:         func() time.Time { return fixedTime },
	}
}

type connectionMemory struct {
	values map[string]Connection
}

func newConnections(t *testing.T) *connectionMemory {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "service.example.com"},
		NotBefore:    fixedTime.Add(-time.Hour),
		NotAfter:     fixedTime.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	return &connectionMemory{values: map[string]Connection{
		"company-sso": {
			ID:             "company-sso",
			EntityID:       "https://app.example.com/auth/saml/metadata",
			MetadataURL:    "https://app.example.com/auth/saml/metadata",
			ACSURL:         "https://app.example.com/auth/saml/acs",
			IDPMetadata:    testIDPMetadata(certificate),
			PrivateKey:     privateKey,
			Certificate:    certificate,
			EmailAttribute: "email",
			NameAttribute:  "name",
		},
	}}
}

func testIDPMetadata(certificate *x509.Certificate) []byte {
	return []byte(fmt.Sprintf(`
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, base64.StdEncoding.EncodeToString(certificate.Raw)))
}

func (connections *connectionMemory) Find(
	_ context.Context,
	connectionID string,
) (Connection, error) {
	connection, exists := connections.values[connectionID]
	if !exists {
		return Connection{}, ErrNotFound
	}
	connection.IDPMetadata = append([]byte(nil), connection.IDPMetadata...)
	return connection, nil
}

type memoryStore struct {
	mu       sync.Mutex
	requests map[StateHash]Request
	latest   StateHash
}

func newMemoryStore() *memoryStore {
	return &memoryStore{requests: make(map[StateHash]Request)}
}

func (store *memoryStore) CreateRequest(_ context.Context, request Request) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.requests[request.StateHash]; exists {
		return ErrConflict
	}
	store.requests[request.StateHash] = request
	store.latest = request.StateHash
	return nil
}

func (store *memoryStore) ConsumeRequest(
	_ context.Context,
	stateHash StateHash,
	consumedAt time.Time,
) (Request, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	request, exists := store.requests[stateHash]
	if !exists || !consumedAt.Before(request.ExpiresAt) {
		return Request{}, ErrNotFound
	}
	delete(store.requests, stateHash)
	return request, nil
}

func (store *memoryStore) latestRequest() Request {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.requests[store.latest]
}

type fakeProtocol struct {
	state              string
	completedRequestID string
	completeCalls      int
	identity           providerIdentity
}

func (provider *fakeProtocol) Begin(_ Connection, state string) (string, string, error) {
	provider.state = state
	return "https://idp.example.com/sso", "request-1", nil
}

func (provider *fakeProtocol) Complete(
	_ context.Context,
	_ Connection,
	requestID string,
	_ string,
) (providerIdentity, error) {
	provider.completeCalls++
	provider.completedRequestID = requestID
	return provider.identity, nil
}

func (*fakeProtocol) Metadata(Connection) ([]byte, error) {
	return []byte("service-provider-metadata"), nil
}
