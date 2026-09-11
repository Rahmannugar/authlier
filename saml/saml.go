// Package saml provides SAML Web SSO orchestration for service providers.
package saml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailaddress"
	"github.com/Rahmannugar/authlier/token"
	samllibrary "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/russellhaering/goxmldsig"
)

const (
	requestAttempts   = 3
	maxMetadataLength = 2 << 20
	maxResponseLength = 2 << 20
)

var (
	ErrAttemptBlocked  = errors.New("SAML attempt blocked")
	ErrConflict        = errors.New("SAML request conflict")
	ErrInactiveRequest = errors.New("SAML request is inactive")
	ErrInvalidConfig   = errors.New("invalid SAML configuration")
	ErrInvalidIdentity = errors.New("invalid SAML identity")
	ErrInvalidInput    = errors.New("invalid SAML input")
	ErrInvalidRecord   = errors.New("invalid SAML record")
	ErrInvalidResponse = errors.New("invalid SAML response")
	ErrInvalidState    = errors.New("invalid or expired SAML state")
	ErrNotFound        = errors.New("SAML record not found")
)

type StateHash token.Hash

type Connection struct {
	ID               string
	EntityID         string
	MetadataURL      string
	ACSURL           string
	IDPMetadata      []byte
	PrivateKey       crypto.Signer
	Certificate      *x509.Certificate
	SubjectAttribute string
	EmailAttribute   string
	NameAttribute    string
	RequireEmail     bool
	ForceAuthn       bool
}

type ConnectionSource interface {
	Find(ctx context.Context, connectionID string) (Connection, error)
}

type Request struct {
	StateHash      StateHash
	ConnectionID   string
	ConnectionHash [32]byte
	RequestID      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// Store creates and consumes each request in one operation.
type Store interface {
	CreateRequest(ctx context.Context, request Request) error
	ConsumeRequest(ctx context.Context, stateHash StateHash, consumedAt time.Time) (Request, error)
}

type Operation string

const (
	OperationBegin    Operation = "begin"
	OperationComplete Operation = "complete"
)

type Attempt struct {
	Operation    Operation
	ConnectionID string
	SourceKey    string
}

type AttemptGuard interface {
	Check(ctx context.Context, attempt Attempt) error
}

type EventType string

const (
	EventAuthenticationFailed    EventType = "saml_authentication_failed"
	EventAuthenticationSucceeded EventType = "saml_authentication_succeeded"
)

type SecurityEvent struct {
	Type            EventType
	ConnectionID    string
	ProviderSubject string
	SourceKey       string
	OccurredAt      time.Time
}

type SecurityEventSink interface {
	Record(ctx context.Context, event SecurityEvent)
}

type Config struct {
	RequestLifetime time.Duration
	AttemptGuard    AttemptGuard
	SecurityEvents  SecurityEventSink
	Now             func() time.Time
}

type Manager struct {
	store          Store
	connections    ConnectionSource
	protocol       protocol
	lifetime       time.Duration
	attemptGuard   AttemptGuard
	securityEvents SecurityEventSink
	now            func() time.Time
}

type BeginInput struct {
	ConnectionID string
	SourceKey    string
}

type Started struct {
	AuthorizationURL string
	State            string
	ExpiresAt        time.Time
}

type CompleteInput struct {
	State        string
	SAMLResponse string
	SourceKey    string
}

type Identity struct {
	ConnectionID    string
	Issuer          string
	ProviderSubject string
	SubjectFormat   string
	Email           string
	Name            string
	SessionIndex    string
}

func NewManager(store Store, connections ConnectionSource, config Config) (*Manager, error) {
	if store == nil || connections == nil {
		return nil, fmt.Errorf("%w: store and connections are required", ErrInvalidConfig)
	}
	if config.RequestLifetime <= 0 {
		return nil, fmt.Errorf("%w: request lifetime must be positive", ErrInvalidConfig)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		store:          store,
		connections:    connections,
		protocol:       samlProtocol{},
		lifetime:       config.RequestLifetime,
		attemptGuard:   config.AttemptGuard,
		securityEvents: config.SecurityEvents,
		now:            now,
	}, nil
}

func (manager *Manager) Begin(ctx context.Context, input BeginInput) (Started, error) {
	connectionID := strings.TrimSpace(input.ConnectionID)
	if connectionID == "" {
		return Started{}, ErrInvalidInput
	}
	if err := manager.checkAttempt(ctx, Attempt{
		Operation:    OperationBegin,
		ConnectionID: connectionID,
		SourceKey:    input.SourceKey,
	}); err != nil {
		return Started{}, err
	}
	connection, err := manager.findConnection(ctx, connectionID)
	if err != nil {
		return Started{}, err
	}
	connectionHash, err := hashConnection(connection)
	if err != nil {
		return Started{}, ErrInvalidConfig
	}

	for range requestAttempts {
		state, stateHash, err := token.Generate()
		if err != nil {
			return Started{}, fmt.Errorf("generate SAML state: %w", err)
		}
		authorizationURL, requestID, err := manager.protocol.Begin(connection, state)
		if err != nil {
			return Started{}, fmt.Errorf("create SAML authentication request: %w", err)
		}
		if strings.TrimSpace(requestID) == "" {
			return Started{}, ErrInvalidRecord
		}
		now := manager.now().UTC()
		request := Request{
			StateHash:      StateHash(stateHash),
			ConnectionID:   connection.ID,
			ConnectionHash: connectionHash,
			RequestID:      requestID,
			CreatedAt:      now,
			ExpiresAt:      now.Add(manager.lifetime),
		}
		if err := manager.store.CreateRequest(ctx, request); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return Started{}, fmt.Errorf("store SAML request: %w", err)
		}
		return Started{
			AuthorizationURL: authorizationURL,
			State:            state,
			ExpiresAt:        request.ExpiresAt,
		}, nil
	}
	return Started{}, fmt.Errorf("create unique SAML state: %w", ErrConflict)
}

func (manager *Manager) Complete(ctx context.Context, input CompleteInput) (Identity, error) {
	if err := manager.checkAttempt(ctx, Attempt{
		Operation: OperationComplete,
		SourceKey: input.SourceKey,
	}); err != nil {
		return Identity{}, err
	}
	stateHash, err := token.HashToken(strings.TrimSpace(input.State))
	if err != nil {
		manager.record(ctx, EventAuthenticationFailed, "", "", input.SourceKey)
		return Identity{}, ErrInvalidState
	}
	if strings.TrimSpace(input.SAMLResponse) == "" || len(input.SAMLResponse) > maxResponseLength {
		manager.record(ctx, EventAuthenticationFailed, "", "", input.SourceKey)
		return Identity{}, ErrInvalidResponse
	}
	now := manager.now().UTC()
	request, err := manager.store.ConsumeRequest(ctx, StateHash(stateHash), now)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveRequest) {
		manager.record(ctx, EventAuthenticationFailed, "", "", input.SourceKey)
		return Identity{}, ErrInvalidState
	}
	if err != nil {
		return Identity{}, fmt.Errorf("consume SAML request: %w", err)
	}
	if !validRequest(request, StateHash(stateHash), now) {
		return Identity{}, ErrInvalidRecord
	}
	connection, err := manager.findConnection(ctx, request.ConnectionID)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidConfig) {
		return Identity{}, ErrInvalidState
	}
	if err != nil {
		return Identity{}, err
	}
	connectionHash, err := hashConnection(connection)
	if err != nil || connectionHash != request.ConnectionHash {
		return Identity{}, ErrInvalidState
	}

	providerIdentity, err := manager.protocol.Complete(
		ctx,
		connection,
		request.RequestID,
		input.SAMLResponse,
	)
	if err != nil {
		manager.record(ctx, EventAuthenticationFailed, connection.ID, "", input.SourceKey)
		return Identity{}, ErrInvalidResponse
	}
	providerSubject := strings.TrimSpace(providerIdentity.ProviderSubject)
	if providerSubject == "" || strings.TrimSpace(providerIdentity.Issuer) == "" {
		return Identity{}, ErrInvalidIdentity
	}
	email := ""
	if strings.TrimSpace(providerIdentity.Email) != "" {
		email, err = emailaddress.Normalize(providerIdentity.Email)
		if err != nil {
			return Identity{}, ErrInvalidIdentity
		}
	}
	if connection.RequireEmail && email == "" {
		return Identity{}, ErrInvalidIdentity
	}
	identity := Identity{
		ConnectionID:    connection.ID,
		Issuer:          providerIdentity.Issuer,
		ProviderSubject: providerSubject,
		SubjectFormat:   providerIdentity.SubjectFormat,
		Email:           email,
		Name:            strings.TrimSpace(providerIdentity.Name),
		SessionIndex:    strings.TrimSpace(providerIdentity.SessionIndex),
	}
	manager.record(ctx, EventAuthenticationSucceeded, connection.ID, providerSubject, input.SourceKey)
	return identity, nil
}

func (manager *Manager) Metadata(ctx context.Context, connectionID string) ([]byte, error) {
	connection, err := manager.findConnection(ctx, strings.TrimSpace(connectionID))
	if err != nil {
		return nil, err
	}
	metadata, err := manager.protocol.Metadata(connection)
	if err != nil {
		return nil, fmt.Errorf("create SAML metadata: %w", err)
	}
	return metadata, nil
}

func (manager *Manager) findConnection(ctx context.Context, connectionID string) (Connection, error) {
	if connectionID == "" {
		return Connection{}, ErrInvalidInput
	}
	connection, err := manager.connections.Find(ctx, connectionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Connection{}, ErrNotFound
		}
		return Connection{}, fmt.Errorf("find SAML connection: %w", err)
	}
	connection, err = normalizeConnection(connection)
	if err != nil || connection.ID != connectionID {
		return Connection{}, ErrInvalidConfig
	}
	now := manager.now().UTC()
	if now.Before(connection.Certificate.NotBefore) || !now.Before(connection.Certificate.NotAfter) {
		return Connection{}, ErrInvalidConfig
	}
	return connection, nil
}

func (manager *Manager) checkAttempt(ctx context.Context, attempt Attempt) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, attempt); err != nil {
		return fmt.Errorf("check SAML attempt: %w", err)
	}
	return nil
}

func (manager *Manager) record(
	ctx context.Context,
	eventType EventType,
	connectionID string,
	providerSubject string,
	sourceKey string,
) {
	if manager.securityEvents == nil {
		return
	}
	manager.securityEvents.Record(ctx, SecurityEvent{
		Type:            eventType,
		ConnectionID:    connectionID,
		ProviderSubject: providerSubject,
		SourceKey:       sourceKey,
		OccurredAt:      manager.now().UTC(),
	})
}

func normalizeConnection(connection Connection) (Connection, error) {
	connection.ID = strings.TrimSpace(connection.ID)
	connection.EntityID = strings.TrimSpace(connection.EntityID)
	connection.MetadataURL = strings.TrimSpace(connection.MetadataURL)
	connection.ACSURL = strings.TrimSpace(connection.ACSURL)
	connection.SubjectAttribute = strings.TrimSpace(connection.SubjectAttribute)
	connection.EmailAttribute = strings.TrimSpace(connection.EmailAttribute)
	connection.NameAttribute = strings.TrimSpace(connection.NameAttribute)
	if connection.ID == "" || connection.EntityID == "" ||
		!validHTTPSURL(connection.MetadataURL) || !validHTTPSURL(connection.ACSURL) ||
		len(connection.IDPMetadata) == 0 || len(connection.IDPMetadata) > maxMetadataLength ||
		connection.PrivateKey == nil || !supportedKey(connection.PrivateKey) ||
		connection.Certificate == nil || !keyMatchesCertificate(connection.PrivateKey, connection.Certificate) {
		return Connection{}, ErrInvalidConfig
	}
	connection.IDPMetadata = bytes.Clone(connection.IDPMetadata)
	return connection, nil
}

func validHTTPSURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.Fragment == ""
}

func keyMatchesCertificate(key crypto.Signer, certificate *x509.Certificate) bool {
	keyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	return err == nil && bytes.Equal(keyBytes, certificate.RawSubjectPublicKeyInfo)
}

func supportedKey(key crypto.Signer) bool {
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return true
	default:
		return false
	}
}

func hashConnection(connection Connection) ([32]byte, error) {
	configuration := struct {
		ID               string
		EntityID         string
		MetadataURL      string
		ACSURL           string
		IDPMetadata      []byte
		Certificate      []byte
		SubjectAttribute string
		EmailAttribute   string
		NameAttribute    string
		RequireEmail     bool
		ForceAuthn       bool
	}{
		ID:               connection.ID,
		EntityID:         connection.EntityID,
		MetadataURL:      connection.MetadataURL,
		ACSURL:           connection.ACSURL,
		IDPMetadata:      connection.IDPMetadata,
		Certificate:      connection.Certificate.Raw,
		SubjectAttribute: connection.SubjectAttribute,
		EmailAttribute:   connection.EmailAttribute,
		NameAttribute:    connection.NameAttribute,
		RequireEmail:     connection.RequireEmail,
		ForceAuthn:       connection.ForceAuthn,
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validRequest(request Request, expectedHash StateHash, now time.Time) bool {
	return request.StateHash == expectedHash &&
		strings.TrimSpace(request.ConnectionID) != "" &&
		request.ConnectionHash != [32]byte{} &&
		strings.TrimSpace(request.RequestID) != "" &&
		!request.CreatedAt.IsZero() && request.ExpiresAt.After(request.CreatedAt) &&
		now.Before(request.ExpiresAt)
}

type providerIdentity struct {
	Issuer          string
	ProviderSubject string
	SubjectFormat   string
	Email           string
	Name            string
	SessionIndex    string
}

type protocol interface {
	Begin(connection Connection, state string) (authorizationURL string, requestID string, err error)
	Complete(
		ctx context.Context,
		connection Connection,
		requestID string,
		response string,
	) (providerIdentity, error)
	Metadata(connection Connection) ([]byte, error)
}

type samlProtocol struct{}

func (samlProtocol) Begin(connection Connection, state string) (string, string, error) {
	serviceProvider, err := serviceProvider(connection)
	if err != nil {
		return "", "", err
	}
	destination := serviceProvider.GetSSOBindingLocation(samllibrary.HTTPRedirectBinding)
	if strings.TrimSpace(destination) == "" {
		return "", "", ErrInvalidConfig
	}
	request, err := serviceProvider.MakeAuthenticationRequest(
		destination,
		samllibrary.HTTPRedirectBinding,
		samllibrary.HTTPPostBinding,
	)
	if err != nil {
		return "", "", err
	}
	redirect, err := request.Redirect(state, serviceProvider)
	if err != nil {
		return "", "", err
	}
	return redirect.String(), request.ID, nil
}

func (samlProtocol) Complete(
	ctx context.Context,
	connection Connection,
	requestID string,
	response string,
) (providerIdentity, error) {
	serviceProvider, err := serviceProvider(connection)
	if err != nil {
		return providerIdentity{}, err
	}
	form := url.Values{"SAMLResponse": []string{response}}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		connection.ACSURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return providerIdentity{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		return providerIdentity{}, err
	}
	assertion, err := serviceProvider.ParseResponse(request, []string{requestID})
	if err != nil {
		return providerIdentity{}, err
	}
	return identityFromAssertion(connection, assertion)
}

func (samlProtocol) Metadata(connection Connection) ([]byte, error) {
	serviceProvider, err := serviceProvider(connection)
	if err != nil {
		return nil, err
	}
	metadata, err := xml.MarshalIndent(serviceProvider.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), metadata...), nil
}

func serviceProvider(connection Connection) (*samllibrary.ServiceProvider, error) {
	metadata, err := samlsp.ParseMetadata(connection.IDPMetadata)
	if err != nil {
		return nil, err
	}
	metadataURL, err := url.Parse(connection.MetadataURL)
	if err != nil {
		return nil, err
	}
	acsURL, err := url.Parse(connection.ACSURL)
	if err != nil {
		return nil, err
	}
	forceAuthn := connection.ForceAuthn
	return &samllibrary.ServiceProvider{
		EntityID:          connection.EntityID,
		Key:               connection.PrivateKey,
		Certificate:       connection.Certificate,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		IDPMetadata:       metadata,
		AuthnNameIDFormat: samllibrary.PersistentNameIDFormat,
		ForceAuthn:        &forceAuthn,
		SignatureMethod:   signingMethod(connection.PrivateKey),
		AllowIDPInitiated: false,
	}, nil
}

func signingMethod(key crypto.Signer) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		return dsig.ECDSASHA256SignatureMethod
	default:
		return ""
	}
}

func identityFromAssertion(
	connection Connection,
	assertion *samllibrary.Assertion,
) (providerIdentity, error) {
	if assertion == nil {
		return providerIdentity{}, ErrInvalidIdentity
	}
	var subject string
	var subjectFormat string
	if connection.SubjectAttribute != "" {
		subject = attribute(assertion, connection.SubjectAttribute)
		subjectFormat = "attribute:" + connection.SubjectAttribute
	} else {
		if assertion.Subject == nil || assertion.Subject.NameID == nil {
			return providerIdentity{}, ErrInvalidIdentity
		}
		nameID := assertion.Subject.NameID
		subject = strings.TrimSpace(nameID.Value)
		subjectFormat = strings.TrimSpace(nameID.Format)
		if subjectFormat != string(samllibrary.PersistentNameIDFormat) {
			return providerIdentity{}, ErrInvalidIdentity
		}
	}
	if subject == "" {
		return providerIdentity{}, ErrInvalidIdentity
	}
	sessionIndex := ""
	if len(assertion.AuthnStatements) > 0 {
		sessionIndex = assertion.AuthnStatements[0].SessionIndex
	}
	return providerIdentity{
		Issuer:          strings.TrimSpace(assertion.Issuer.Value),
		ProviderSubject: subject,
		SubjectFormat:   subjectFormat,
		Email:           attribute(assertion, connection.EmailAttribute),
		Name:            attribute(assertion, connection.NameAttribute),
		SessionIndex:    sessionIndex,
	}, nil
}

func attribute(assertion *samllibrary.Assertion, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	for _, statement := range assertion.AttributeStatements {
		for _, candidate := range statement.Attributes {
			if candidate.Name != name && candidate.FriendlyName != name {
				continue
			}
			for _, value := range candidate.Values {
				if value := strings.TrimSpace(value.Value); value != "" {
					return value
				}
			}
		}
	}
	return ""
}
