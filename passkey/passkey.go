// Package passkey manages WebAuthn passkey registration and authentication.
package passkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/token"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlibrary "github.com/go-webauthn/webauthn/webauthn"
)

const ceremonyAttempts = 3

var (
	ErrAttemptBlocked   = errors.New("passkey attempt blocked")
	ErrConflict         = errors.New("passkey conflict")
	ErrInactiveCeremony = errors.New("passkey ceremony is inactive")
	ErrInvalidCeremony  = errors.New("invalid or expired passkey ceremony")
	ErrInvalidConfig    = errors.New("invalid passkey configuration")
	ErrInvalidInput     = errors.New("invalid passkey input")
	ErrInvalidRecord    = errors.New("invalid passkey record")
	ErrLastCredential   = errors.New("cannot remove the last sign-in method")
	ErrNotFound         = errors.New("passkey record not found")
	ErrVerification     = errors.New("passkey verification failed")
)

type CeremonyHash token.Hash
type Credential = webauthnlibrary.Credential

type User struct {
	SubjectID   string
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []Credential
}

func (user User) WebAuthnID() []byte                { return user.Handle }
func (user User) WebAuthnName() string              { return user.Name }
func (user User) WebAuthnDisplayName() string       { return user.DisplayName }
func (user User) WebAuthnCredentials() []Credential { return user.Credentials }

type CeremonyType string

const (
	CeremonyRegistration   CeremonyType = "registration"
	CeremonyAuthentication CeremonyType = "authentication"
)

type Ceremony struct {
	Type      CeremonyType
	TokenHash CeremonyHash
	SubjectID string
	Session   webauthnlibrary.SessionData
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store keeps complete credential records, consumes ceremonies with credential
// writes, and preserves another sign-in method when deleting a credential.
type Store interface {
	FindUserBySubject(ctx context.Context, subjectID string) (User, error)
	FindUserByCredential(ctx context.Context, credentialID, userHandle []byte) (User, error)
	CreateCeremony(ctx context.Context, ceremony Ceremony) error
	FindCeremony(ctx context.Context, ceremonyHash CeremonyHash) (Ceremony, error)
	CompleteRegistration(
		ctx context.Context,
		ceremonyHash CeremonyHash,
		subjectID string,
		credential Credential,
		completedAt time.Time,
	) error
	CompleteAuthentication(
		ctx context.Context,
		ceremonyHash CeremonyHash,
		subjectID string,
		previous Credential,
		updated Credential,
		completedAt time.Time,
	) error
	DeleteCredential(ctx context.Context, subjectID string, credentialID []byte, deletedAt time.Time) error
}

type Operation string

const (
	OperationRegister     Operation = "register"
	OperationAuthenticate Operation = "authenticate"
)

type Attempt struct {
	Operation Operation
	SubjectID string
	SourceKey string
}

type AttemptGuard interface {
	Check(ctx context.Context, attempt Attempt) error
}

type EventType string

const (
	EventRegistered           EventType = "passkey_registered"
	EventRegistrationFailed   EventType = "passkey_registration_failed"
	EventAuthenticated        EventType = "passkey_authenticated"
	EventAuthenticationFailed EventType = "passkey_authentication_failed"
	EventCloneWarning         EventType = "passkey_clone_warning"
	EventRemoved              EventType = "passkey_removed"
)

type SecurityEvent struct {
	Type       EventType
	SubjectID  string
	SourceKey  string
	OccurredAt time.Time
}

type SecurityEventSink interface {
	Record(ctx context.Context, event SecurityEvent)
}

type Config struct {
	RelyingPartyID   string
	RelyingPartyName string
	Origins          []string
	CeremonyLifetime time.Duration
	AttemptGuard     AttemptGuard
	SecurityEvents   SecurityEventSink
	Now              func() time.Time
}

type Manager struct {
	store          Store
	protocol       ceremonyProtocol
	lifetime       time.Duration
	attemptGuard   AttemptGuard
	securityEvents SecurityEventSink
	now            func() time.Time
}

type RegistrationStarted struct {
	Token     string
	Options   *protocol.CredentialCreation
	ExpiresAt time.Time
}

type AuthenticationStarted struct {
	Token     string
	Options   *protocol.CredentialAssertion
	ExpiresAt time.Time
}

type CompleteInput struct {
	CeremonyToken string
	Response      []byte
	SourceKey     string
}

type Authentication struct {
	SubjectID    string
	CloneWarning bool
}

func NewManager(store Store, config Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if config.CeremonyLifetime <= 0 {
		return nil, fmt.Errorf("%w: ceremony lifetime must be positive", ErrInvalidConfig)
	}
	webAuthn, err := webauthnlibrary.New(&webauthnlibrary.Config{
		RPID:          strings.TrimSpace(config.RelyingPartyID),
		RPDisplayName: strings.TrimSpace(config.RelyingPartyName),
		RPOrigins:     append([]string(nil), config.Origins...),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthnlibrary.TimeoutsConfig{
			Login: webauthnlibrary.TimeoutConfig{
				Enforce: true,
				Timeout: config.CeremonyLifetime,
			},
			Registration: webauthnlibrary.TimeoutConfig{
				Enforce: true,
				Timeout: config.CeremonyLifetime,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		store:          store,
		protocol:       webAuthnProtocol{webAuthn: webAuthn},
		lifetime:       config.CeremonyLifetime,
		attemptGuard:   config.AttemptGuard,
		securityEvents: config.SecurityEvents,
		now:            now,
	}, nil
}

func (manager *Manager) BeginRegistration(
	ctx context.Context,
	subjectID string,
) (RegistrationStarted, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return RegistrationStarted{}, ErrInvalidInput
	}
	user, err := manager.store.FindUserBySubject(ctx, subjectID)
	if err != nil {
		return RegistrationStarted{}, fmt.Errorf("find user for passkey registration: %w", err)
	}
	if !validUser(user) || user.SubjectID != subjectID {
		return RegistrationStarted{}, ErrInvalidRecord
	}
	options, session, err := manager.protocol.BeginRegistration(user)
	if err != nil {
		return RegistrationStarted{}, fmt.Errorf("begin passkey registration: %w", err)
	}
	token, expiresAt, err := manager.storeCeremony(ctx, CeremonyRegistration, subjectID, session)
	if err != nil {
		return RegistrationStarted{}, err
	}
	return RegistrationStarted{Token: token, Options: options, ExpiresAt: expiresAt}, nil
}

func (manager *Manager) CompleteRegistration(
	ctx context.Context,
	input CompleteInput,
) (Credential, error) {
	ceremony, ceremonyHash, err := manager.findCeremony(ctx, input.CeremonyToken, CeremonyRegistration)
	if err != nil {
		return Credential{}, err
	}
	if err := manager.checkAttempt(ctx, OperationRegister, ceremony.SubjectID, input.SourceKey); err != nil {
		return Credential{}, err
	}
	user, err := manager.store.FindUserBySubject(ctx, ceremony.SubjectID)
	if err != nil {
		return Credential{}, fmt.Errorf("find user for passkey registration: %w", err)
	}
	if !validUser(user) || user.SubjectID != ceremony.SubjectID || !bytes.Equal(user.Handle, ceremony.Session.UserID) {
		return Credential{}, ErrInvalidRecord
	}
	credential, err := manager.protocol.FinishRegistration(user, ceremony.Session, input.Response)
	if err != nil {
		manager.record(ctx, EventRegistrationFailed, ceremony.SubjectID, input.SourceKey)
		return Credential{}, ErrVerification
	}
	if !validCredential(credential) {
		return Credential{}, ErrInvalidRecord
	}
	if err := manager.store.CompleteRegistration(
		ctx,
		ceremonyHash,
		ceremony.SubjectID,
		credential,
		manager.now().UTC(),
	); err != nil {
		return Credential{}, manager.completionError("register passkey", err)
	}
	manager.record(ctx, EventRegistered, ceremony.SubjectID, input.SourceKey)
	return credential, nil
}

func (manager *Manager) BeginAuthentication(ctx context.Context) (AuthenticationStarted, error) {
	options, session, err := manager.protocol.BeginAuthentication()
	if err != nil {
		return AuthenticationStarted{}, fmt.Errorf("begin passkey authentication: %w", err)
	}
	token, expiresAt, err := manager.storeCeremony(ctx, CeremonyAuthentication, "", session)
	if err != nil {
		return AuthenticationStarted{}, err
	}
	return AuthenticationStarted{Token: token, Options: options, ExpiresAt: expiresAt}, nil
}

func (manager *Manager) CompleteAuthentication(
	ctx context.Context,
	input CompleteInput,
) (Authentication, error) {
	ceremony, ceremonyHash, err := manager.findCeremony(ctx, input.CeremonyToken, CeremonyAuthentication)
	if err != nil {
		return Authentication{}, err
	}
	var foundUser User
	var callbackErr error
	lookup := func(credentialID, userHandle []byte) (User, error) {
		user, lookupErr := manager.store.FindUserByCredential(ctx, credentialID, userHandle)
		if lookupErr != nil {
			if !errors.Is(lookupErr, ErrNotFound) {
				callbackErr = fmt.Errorf("find passkey owner: %w", lookupErr)
			}
			return User{}, lookupErr
		}
		if !validUser(user) || !bytes.Equal(user.Handle, userHandle) {
			callbackErr = ErrInvalidRecord
			return User{}, ErrInvalidRecord
		}
		if guardErr := manager.checkAttempt(ctx, OperationAuthenticate, user.SubjectID, input.SourceKey); guardErr != nil {
			callbackErr = guardErr
			return User{}, guardErr
		}
		foundUser = user
		return user, nil
	}
	user, previous, updated, err := manager.protocol.FinishAuthentication(ceremony.Session, input.Response, lookup)
	if err != nil {
		if callbackErr != nil {
			return Authentication{}, callbackErr
		}
		manager.record(ctx, EventAuthenticationFailed, foundUser.SubjectID, input.SourceKey)
		return Authentication{}, ErrVerification
	}
	if !validUser(user) || !validCredential(previous) || !validCredential(updated) ||
		!bytes.Equal(previous.ID, updated.ID) {
		return Authentication{}, ErrInvalidRecord
	}
	if err := manager.store.CompleteAuthentication(
		ctx,
		ceremonyHash,
		user.SubjectID,
		previous,
		updated,
		manager.now().UTC(),
	); err != nil {
		return Authentication{}, manager.completionError("authenticate passkey", err)
	}
	manager.record(ctx, EventAuthenticated, user.SubjectID, input.SourceKey)
	if updated.Authenticator.CloneWarning {
		manager.record(ctx, EventCloneWarning, user.SubjectID, input.SourceKey)
	}
	return Authentication{
		SubjectID:    user.SubjectID,
		CloneWarning: updated.Authenticator.CloneWarning,
	}, nil
}

func (manager *Manager) Remove(
	ctx context.Context,
	subjectID string,
	credentialID []byte,
	sourceKey string,
) error {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" || len(credentialID) == 0 {
		return ErrInvalidInput
	}
	if err := manager.store.DeleteCredential(ctx, subjectID, credentialID, manager.now().UTC()); err != nil {
		if errors.Is(err, ErrLastCredential) {
			return err
		}
		return fmt.Errorf("remove passkey: %w", err)
	}
	manager.record(ctx, EventRemoved, subjectID, sourceKey)
	return nil
}

func (manager *Manager) storeCeremony(
	ctx context.Context,
	ceremonyType CeremonyType,
	subjectID string,
	session webauthnlibrary.SessionData,
) (string, time.Time, error) {
	for range ceremonyAttempts {
		rawToken, tokenHash, err := token.Generate()
		if err != nil {
			return "", time.Time{}, fmt.Errorf("generate passkey ceremony token: %w", err)
		}
		now := manager.now().UTC()
		expiresAt := now.Add(manager.lifetime)
		session.Expires = expiresAt
		ceremony := Ceremony{
			Type:      ceremonyType,
			TokenHash: CeremonyHash(tokenHash),
			SubjectID: subjectID,
			Session:   session,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		}
		if err := manager.store.CreateCeremony(ctx, ceremony); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return "", time.Time{}, fmt.Errorf("store passkey ceremony: %w", err)
		}
		return rawToken, expiresAt, nil
	}
	return "", time.Time{}, fmt.Errorf("create unique passkey ceremony: %w", ErrConflict)
}

func (manager *Manager) findCeremony(
	ctx context.Context,
	rawToken string,
	expectedType CeremonyType,
) (Ceremony, CeremonyHash, error) {
	tokenHash, err := token.HashToken(rawToken)
	if err != nil {
		return Ceremony{}, CeremonyHash{}, ErrInvalidCeremony
	}
	ceremonyHash := CeremonyHash(tokenHash)
	ceremony, err := manager.store.FindCeremony(ctx, ceremonyHash)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveCeremony) {
		return Ceremony{}, CeremonyHash{}, ErrInvalidCeremony
	}
	if err != nil {
		return Ceremony{}, CeremonyHash{}, fmt.Errorf("find passkey ceremony: %w", err)
	}
	if !validCeremony(ceremony, ceremonyHash, expectedType) {
		return Ceremony{}, CeremonyHash{}, ErrInvalidRecord
	}
	if !manager.now().UTC().Before(ceremony.ExpiresAt) {
		return Ceremony{}, CeremonyHash{}, ErrInvalidCeremony
	}
	return ceremony, ceremonyHash, nil
}

func (manager *Manager) completionError(operation string, err error) error {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInactiveCeremony) {
		return ErrInvalidCeremony
	}
	if errors.Is(err, ErrConflict) {
		return ErrConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (manager *Manager) checkAttempt(
	ctx context.Context,
	operation Operation,
	subjectID string,
	sourceKey string,
) error {
	if manager.attemptGuard == nil {
		return nil
	}
	if err := manager.attemptGuard.Check(ctx, Attempt{
		Operation: operation,
		SubjectID: subjectID,
		SourceKey: sourceKey,
	}); err != nil {
		return fmt.Errorf("check passkey attempt: %w", err)
	}
	return nil
}

func (manager *Manager) record(ctx context.Context, eventType EventType, subjectID, sourceKey string) {
	if manager.securityEvents == nil {
		return
	}
	manager.securityEvents.Record(ctx, SecurityEvent{
		Type:       eventType,
		SubjectID:  subjectID,
		SourceKey:  sourceKey,
		OccurredAt: manager.now().UTC(),
	})
}

func validUser(user User) bool {
	return strings.TrimSpace(user.SubjectID) != "" &&
		len(user.Handle) > 0 && len(user.Handle) <= 64 &&
		strings.TrimSpace(user.Name) != "" &&
		strings.TrimSpace(user.DisplayName) != ""
}

func validCredential(credential Credential) bool {
	return len(credential.ID) > 0 && len(credential.PublicKey) > 0
}

func validCeremony(ceremony Ceremony, expectedHash CeremonyHash, expectedType CeremonyType) bool {
	if ceremony.Type != expectedType || ceremony.TokenHash != expectedHash ||
		strings.TrimSpace(ceremony.Session.Challenge) == "" ||
		ceremony.CreatedAt.IsZero() || !ceremony.ExpiresAt.After(ceremony.CreatedAt) {
		return false
	}
	if expectedType == CeremonyRegistration {
		return strings.TrimSpace(ceremony.SubjectID) != "" && len(ceremony.Session.UserID) > 0
	}
	return ceremony.SubjectID == "" && len(ceremony.Session.UserID) == 0
}

type credentialLookup func(credentialID, userHandle []byte) (User, error)

type ceremonyProtocol interface {
	BeginRegistration(user User) (*protocol.CredentialCreation, webauthnlibrary.SessionData, error)
	FinishRegistration(user User, session webauthnlibrary.SessionData, response []byte) (Credential, error)
	BeginAuthentication() (*protocol.CredentialAssertion, webauthnlibrary.SessionData, error)
	FinishAuthentication(session webauthnlibrary.SessionData, response []byte, lookup credentialLookup) (User, Credential, Credential, error)
}

type webAuthnProtocol struct {
	webAuthn *webauthnlibrary.WebAuthn
}

func (engine webAuthnProtocol) BeginRegistration(
	user User,
) (*protocol.CredentialCreation, webauthnlibrary.SessionData, error) {
	options, session, err := engine.webAuthn.BeginRegistration(
		user,
		webauthnlibrary.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthnlibrary.WithExclusions(webauthnlibrary.Credentials(user.Credentials).CredentialDescriptors()),
	)
	if err != nil {
		return nil, webauthnlibrary.SessionData{}, err
	}
	return options, *session, nil
}

func (engine webAuthnProtocol) FinishRegistration(
	user User,
	session webauthnlibrary.SessionData,
	response []byte,
) (Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Credential{}, err
	}
	credential, err := engine.webAuthn.CreateCredential(user, session, parsed)
	if err != nil {
		return Credential{}, err
	}
	return *credential, nil
}

func (engine webAuthnProtocol) BeginAuthentication() (
	*protocol.CredentialAssertion,
	webauthnlibrary.SessionData,
	error,
) {
	options, session, err := engine.webAuthn.BeginDiscoverableLogin(
		webauthnlibrary.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, webauthnlibrary.SessionData{}, err
	}
	return options, *session, nil
}

func (engine webAuthnProtocol) FinishAuthentication(
	session webauthnlibrary.SessionData,
	response []byte,
	lookup credentialLookup,
) (User, Credential, Credential, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return User{}, Credential{}, Credential{}, err
	}
	var loaded User
	handler := func(credentialID, userHandle []byte) (webauthnlibrary.User, error) {
		user, lookupErr := lookup(credentialID, userHandle)
		if lookupErr != nil {
			return nil, lookupErr
		}
		loaded = user
		return user, nil
	}
	validatedUser, updated, err := engine.webAuthn.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		return User{}, Credential{}, Credential{}, err
	}
	user, ok := validatedUser.(User)
	if !ok || user.SubjectID != loaded.SubjectID {
		return User{}, Credential{}, Credential{}, ErrInvalidRecord
	}
	for _, credential := range user.Credentials {
		if bytes.Equal(credential.ID, updated.ID) {
			return user, credential, *updated, nil
		}
	}
	return User{}, Credential{}, Credential{}, ErrInvalidRecord
}
