package mongodb_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier"
	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/googleoauth"
	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/passkey"
	"github.com/Rahmannugar/authlier/passwordreset"
	"github.com/Rahmannugar/authlier/refreshtoken"
	"github.com/Rahmannugar/authlier/saml"
	"github.com/Rahmannugar/authlier/sessiontoken"
	authliermongodb "github.com/Rahmannugar/authlier/storage/mongodb"
	"github.com/Rahmannugar/authlier/totp"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestMongoDBAdapter(t *testing.T) {
	uri := os.Getenv("AUTHLIER_MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("AUTHLIER_MONGODB_TEST_URI is not set")
	}
	ctx := context.Background()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect MongoDB: %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(ctx) })
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatalf("ping MongoDB: %v", err)
	}
	database := client.Database("authlier_test")
	if err := database.Drop(ctx); err != nil {
		t.Fatalf("clean MongoDB: %v", err)
	}
	adapter, err := authliermongodb.New(client, database.Name(), authliermongodb.Config{Secrets: testCodec{}})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}

	t.Run("registration uses UUIDv7 and a private user handle", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{
			Email: "owner@example.com", PasswordHash: "encoded-password-hash", CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		userID, err := uuid.Parse(user.ID)
		if err != nil || userID.Version() != 7 {
			t.Fatalf("user ID %q is not UUIDv7", user.ID)
		}
		var document struct {
			Handle []byte `bson:"webauthn_handle"`
		}
		if err := database.Collection("authlier_users").FindOne(ctx, bson.M{"_id": user.ID}).Decode(&document); err != nil {
			t.Fatalf("read user handle: %v", err)
		}
		if len(document.Handle) != 64 {
			t.Fatalf("user handle length = %d, want 64", len(document.Handle))
		}
	})

	t.Run("mounted handler signs up and resolves a session", func(t *testing.T) {
		configured, err := authlier.New(authlier.Config{
			AppName: "Authlier test", BaseURL: "https://app.example.com", Database: adapter,
			EmailAndPassword: authlier.EmailAndPasswordConfig{Enabled: true},
			Session:          authlier.SessionConfig{Lifetime: 24 * time.Hour},
		})
		if err != nil {
			t.Fatalf("configure Authlier: %v", err)
		}
		signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email", bytes.NewBufferString(`{"email":"new@example.com","password":"correct horse battery staple"}`))
		signUp.Header.Set("Origin", "https://app.example.com")
		response := httptest.NewRecorder()
		configured.Handler().ServeHTTP(response, signUp)
		if response.Code != http.StatusCreated {
			t.Fatalf("sign up status = %d, body = %s", response.Code, response.Body.String())
		}
		cookies := response.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure {
			t.Fatalf("unexpected session cookie: %#v", cookies)
		}
		request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		configured.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("session status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("verification issue replaces the previous token", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{Email: "verify@example.com", PasswordHash: "hash", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		now := time.Now().UTC()
		first := emailverification.Record{UserID: user.ID, Email: user.Email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		first.TokenHash[0] = 1
		second := first
		second.TokenHash[0] = 2
		if err := adapter.EmailVerification().Issue(ctx, first); err != nil {
			t.Fatalf("issue first verification: %v", err)
		}
		if err := adapter.EmailVerification().Issue(ctx, second); err != nil {
			t.Fatalf("replace verification: %v", err)
		}
		verified, err := adapter.EmailVerification().Verify(ctx, second.TokenHash, now)
		if err != nil || !verified.Verified {
			t.Fatalf("verify: user=%#v err=%v", verified, err)
		}
	})

	t.Run("password reset replaces the credential and consumes the token", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{Email: "reset@example.com", PasswordHash: "old-hash", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		now := time.Now().UTC()
		record := passwordreset.Record{UserID: user.ID, Email: user.Email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		record.TokenHash[0] = 10
		if err := adapter.PasswordReset().Issue(ctx, record); err != nil {
			t.Fatalf("issue password reset: %v", err)
		}
		if _, err := adapter.PasswordReset().ResetPassword(ctx, record.TokenHash, "new-hash", now); err != nil {
			t.Fatalf("reset password: %v", err)
		}
		_, credential, err := adapter.EmailPassword().FindBySubject(ctx, user.ID)
		if err != nil || credential.PasswordHash != "new-hash" {
			t.Fatalf("credential=%#v err=%v", credential, err)
		}
		if _, err := adapter.PasswordReset().ResetPassword(ctx, record.TokenHash, "another-hash", now); !errors.Is(err, passwordreset.ErrNotFound) {
			t.Fatalf("replayed password reset error = %v", err)
		}
	})

	t.Run("Google identity follows the permanent provider subject", func(t *testing.T) {
		first, err := adapter.Google().ResolveIdentity(ctx, googleoauth.IdentityResolution{ProviderSubject: "google-account-id", Email: "first@example.com"})
		if err != nil {
			t.Fatalf("resolve first identity: %v", err)
		}
		second, err := adapter.Google().ResolveIdentity(ctx, googleoauth.IdentityResolution{ProviderSubject: "google-account-id", Email: "changed@example.com"})
		if err != nil || second.ID != first.ID {
			t.Fatalf("resolved user=%#v err=%v, want subject %q", second, err, first.ID)
		}
	})

	t.Run("session extension and account-wide revocation are atomic", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		var hash sessiontoken.TokenHash
		hash[0] = 3
		record := sessiontoken.Record{SubjectID: "session-user", TokenHash: hash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := adapter.Sessions().Create(ctx, record); err != nil {
			t.Fatalf("create session: %v", err)
		}
		extended, err := adapter.Sessions().Extend(ctx, hash, now.Add(time.Minute), now.Add(2*time.Hour))
		if err != nil || !extended.ExpiresAt.Equal(now.Add(2*time.Hour)) {
			t.Fatalf("extend: record=%#v err=%v", extended, err)
		}
		revoked, err := adapter.Sessions().RevokeAll(ctx, record.SubjectID, now.Add(2*time.Minute))
		if err != nil || len(revoked) != 1 || revoked[0].RevokedAt == nil {
			t.Fatalf("revoke all: records=%#v err=%v", revoked, err)
		}
	})

	t.Run("refresh-token reuse revokes the access session", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		access := authlier.AccessSession{ID: "access-session", SubjectID: "refresh-user", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := adapter.AccessSessions().Create(ctx, access); err != nil {
			t.Fatalf("create access session: %v", err)
		}
		var currentHash, replacementHash refreshtoken.TokenHash
		currentHash[0], replacementHash[0] = 11, 12
		current := refreshtoken.Record{SessionID: access.ID, TokenHash: currentHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		replacement := refreshtoken.Record{SessionID: access.ID, TokenHash: replacementHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := adapter.RefreshTokens().Create(ctx, current); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}
		if err := adapter.RefreshTokens().Rotate(ctx, currentHash, replacement, now.Add(time.Minute)); err != nil {
			t.Fatalf("rotate refresh token: %v", err)
		}
		if err := adapter.RefreshTokens().Rotate(ctx, currentHash, replacement, now.Add(2*time.Minute)); !errors.Is(err, refreshtoken.ErrReuseDetected) {
			t.Fatalf("reuse error = %v", err)
		}
		if _, err := adapter.AccessSessions().ResolveSession(ctx, access.ID); err == nil {
			t.Fatal("reused refresh token left access session active")
		}
	})

	t.Run("TOTP enrollment and challenge enforce one-time use", func(t *testing.T) {
		now := time.Now().UTC()
		if err := adapter.TOTP().BeginEnrollment(ctx, totp.Enrollment{SubjectID: "totp-user", Secret: "secret", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("begin enrollment: %v", err)
		}
		if err := adapter.TOTP().Enable(ctx, "totp-user", 1, nil, now); err != nil {
			t.Fatalf("enable TOTP: %v", err)
		}
		if enabled, err := adapter.TOTP().IsEnabled(ctx, "totp-user"); err != nil || !enabled {
			t.Fatalf("TOTP enabled status: enabled=%t err=%v", enabled, err)
		}
		var challengeHash totp.ChallengeHash
		challengeHash[0] = 5
		if err := adapter.TOTP().CreateChallenge(ctx, totp.Challenge{SubjectID: "totp-user", TokenHash: challengeHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("create challenge: %v", err)
		}
		if _, err := adapter.TOTP().CompleteCode(ctx, challengeHash, 2, now); err != nil {
			t.Fatalf("complete code: %v", err)
		}
		if _, err := adapter.TOTP().CompleteCode(ctx, challengeHash, 3, now); !errors.Is(err, totp.ErrInactiveChallenge) {
			t.Fatalf("replayed challenge error = %v", err)
		}
	})

	t.Run("passkey registration consumes its ceremony", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{Email: "passkey@example.com", PasswordHash: "hash", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		now := time.Now().UTC()
		var ceremonyHash passkey.CeremonyHash
		ceremonyHash[0] = 6
		ceremony := passkey.Ceremony{Type: passkey.CeremonyRegistration, TokenHash: ceremonyHash, SubjectID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
		if err := adapter.Passkeys().CreateCeremony(ctx, ceremony); err != nil {
			t.Fatalf("create ceremony: %v", err)
		}
		credential := passkey.Credential{ID: []byte("credential-id")}
		if err := adapter.Passkeys().CompleteRegistration(ctx, ceremonyHash, user.ID, credential, now); err != nil {
			t.Fatalf("complete registration: %v", err)
		}
		if err := adapter.Passkeys().CompleteRegistration(ctx, ceremonyHash, user.ID, credential, now); !errors.Is(err, passkey.ErrInactiveCeremony) {
			t.Fatalf("replayed ceremony error = %v", err)
		}
	})

	t.Run("SAML request state is consumed once", func(t *testing.T) {
		now := time.Now().UTC()
		var request saml.Request
		request.StateHash[0], request.ConnectionHash[0] = 7, 8
		request.ConnectionID, request.RequestID, request.CreatedAt, request.ExpiresAt = "organization", "request", now, now.Add(time.Minute)
		if err := adapter.SAML().CreateRequest(ctx, request); err != nil {
			t.Fatalf("create SAML request: %v", err)
		}
		if _, err := adapter.SAML().ConsumeRequest(ctx, request.StateHash, now); err != nil {
			t.Fatalf("consume SAML request: %v", err)
		}
		if _, err := adapter.SAML().ConsumeRequest(ctx, request.StateHash, now); !errors.Is(err, saml.ErrNotFound) {
			t.Fatalf("replayed SAML request error = %v", err)
		}
	})

	t.Run("OIDC state is consumed once under concurrency", func(t *testing.T) {
		var stateHash oidc.StateHash
		stateHash[0] = 9
		now := time.Now().UTC()
		if err := adapter.OIDC().CreateChallenge(ctx, oidc.Challenge{StateHash: stateHash, ConnectionID: "organization", Issuer: "https://idp.example.com", ClientID: "client", RedirectURL: "https://app.example.com/callback", Scopes: []string{"openid"}, Nonce: "nonce", CodeVerifier: "verifier", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("create challenge: %v", err)
		}
		var consumed, rejected atomic.Int32
		var wait sync.WaitGroup
		for range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := adapter.OIDC().ConsumeChallenge(ctx, stateHash, now)
				if err == nil {
					consumed.Add(1)
				} else if errors.Is(err, oidc.ErrNotFound) {
					rejected.Add(1)
				} else {
					t.Errorf("consume challenge: %v", err)
				}
			}()
		}
		wait.Wait()
		if consumed.Load() != 1 || rejected.Load() != 1 {
			t.Fatalf("consumed=%d rejected=%d, want one each", consumed.Load(), rejected.Load())
		}
	})
}

type testCodec struct{}

func (testCodec) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (testCodec) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}
