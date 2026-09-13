// Package mongodb provides Authlier storage backed by MongoDB.
package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Rahmannugar/authlier"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var ErrInvalidConfig = errors.New("invalid MongoDB adapter configuration")

type SecretCodec interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type Config struct {
	Secrets SecretCodec
}

type Adapter struct {
	client   *mongo.Client
	database *mongo.Database
	secrets  SecretCodec
}

const (
	usersCollection              = "authlier_users"
	passwordsCollection          = "authlier_password_credentials"
	googleIdentitiesCollection   = "authlier_google_identities"
	emailVerificationsCollection = "authlier_email_verifications"
	passwordResetsCollection     = "authlier_password_resets"
	sessionsCollection           = "authlier_sessions"
	accessSessionsCollection     = "authlier_access_sessions"
	refreshTokensCollection      = "authlier_refresh_tokens"
	googleChallengesCollection   = "authlier_google_challenges"
	oidcChallengesCollection     = "authlier_oidc_challenges"
	samlRequestsCollection       = "authlier_saml_requests"
	totpEnrollmentsCollection    = "authlier_totp_enrollments"
	totpCredentialsCollection    = "authlier_totp_credentials"
	totpRecoveryCodesCollection  = "authlier_totp_recovery_codes"
	totpChallengesCollection     = "authlier_totp_challenges"
	passkeyCredentialsCollection = "authlier_passkey_credentials"
	passkeyCeremoniesCollection  = "authlier_passkey_ceremonies"
)

func New(client *mongo.Client, databaseName string, config Config) (*Adapter, error) {
	if client == nil || strings.TrimSpace(databaseName) == "" {
		return nil, fmt.Errorf("%w: client and database name are required", ErrInvalidConfig)
	}
	return &Adapter{client: client, database: client.Database(databaseName), secrets: config.Secrets}, nil
}

func (adapter *Adapter) Stores() authlier.Stores {
	return authlier.Stores{
		EmailPassword:     adapter.EmailPassword(),
		EmailVerification: adapter.EmailVerification(),
		Google:            adapter.Google(),
		OIDC:              adapter.OIDC(),
		Passkeys:          adapter.Passkeys(),
		PasswordReset:     adapter.PasswordReset(),
		RefreshTokens:     adapter.RefreshTokens(),
		SAML:              adapter.SAML(),
		Sessions:          adapter.Sessions(),
		TOTP:              adapter.TOTP(),
		AccessSessions:    adapter.AccessSessions(),
	}
}

func (adapter *Adapter) Migrate(ctx context.Context) error {
	indexes := map[string][]mongo.IndexModel{
		"authlier_users": {
			{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "webauthn_handle", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"authlier_google_identities": {
			{Keys: bson.D{{Key: "user_id", Value: 1}}},
		},
		"authlier_email_verifications": {{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)}},
		"authlier_password_resets":     {{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)}},
		"authlier_sessions":            {{Keys: bson.D{{Key: "subject_id", Value: 1}, {Key: "created_at", Value: -1}}}},
		"authlier_refresh_tokens":      {{Keys: bson.D{{Key: "session_id", Value: 1}}}},
		"authlier_totp_recovery_codes": {{Keys: bson.D{{Key: "subject_id", Value: 1}, {Key: "code_hash", Value: 1}}, Options: options.Index().SetUnique(true)}},
		"authlier_passkey_credentials": {{Keys: bson.D{{Key: "subject_id", Value: 1}}}},
	}
	for collection, models := range indexes {
		if _, err := adapter.database.Collection(collection).Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("create %s indexes: %w", collection, err)
		}
	}
	return nil
}

func duplicateKey(err error) bool { return mongo.IsDuplicateKeyError(err) }

func (adapter *Adapter) collection(name string) *mongo.Collection {
	return adapter.database.Collection(name)
}

func (adapter *Adapter) transaction(ctx context.Context, operation func(context.Context) error) error {
	session, err := adapter.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		return nil, operation(transactionContext)
	})
	return err
}

var _ authlier.Database = (*Adapter)(nil)
