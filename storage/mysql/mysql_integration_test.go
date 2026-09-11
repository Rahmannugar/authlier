package mysql_test

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/passkey"
	"github.com/Rahmannugar/authlier/saml"
	"github.com/Rahmannugar/authlier/sessiontoken"
	authliermysql "github.com/Rahmannugar/authlier/storage/mysql"
	"github.com/Rahmannugar/authlier/totp"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

func TestMySQLAdapter(t *testing.T) {
	dsn := os.Getenv("AUTHLIER_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("AUTHLIER_MYSQL_TEST_DSN is not set")
	}
	ctx := context.Background()
	database, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open MySQL: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("connect MySQL: %v", err)
	}
	adapter, err := authliermysql.New(database, authliermysql.Config{Secrets: testCodec{}})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	cleanDatabase(t, database)

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
		var handle []byte
		if err := database.QueryRowContext(ctx,
			"SELECT webauthn_handle FROM authlier_users WHERE id = ?", user.ID).Scan(&handle); err != nil {
			t.Fatalf("read user handle: %v", err)
		}
		if len(handle) != 64 {
			t.Fatalf("user handle length = %d, want 64", len(handle))
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
		signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
			bytes.NewBufferString(`{"email":"new@example.com","password":"correct horse battery staple"}`))
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
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{
			Email: "verify@example.com", PasswordHash: "hash", CreatedAt: time.Now().UTC(),
		})
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

	t.Run("session extension and account-wide revocation are atomic", func(t *testing.T) {
		now := time.Now().UTC()
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

	t.Run("TOTP enrollment and challenge enforce one-time use", func(t *testing.T) {
		now := time.Now().UTC()
		if err := adapter.TOTP().BeginEnrollment(ctx, totp.Enrollment{
			SubjectID: "totp-user", Secret: "secret", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("begin enrollment: %v", err)
		}
		var recovery totp.RecoveryCodeHash
		recovery[0] = 4
		if err := adapter.TOTP().Enable(ctx, "totp-user", 1, []totp.RecoveryCodeHash{recovery}, now); err != nil {
			t.Fatalf("enable TOTP: %v", err)
		}
		var challengeHash totp.ChallengeHash
		challengeHash[0] = 5
		if err := adapter.TOTP().CreateChallenge(ctx, totp.Challenge{
			SubjectID: "totp-user", TokenHash: challengeHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		}); err != nil {
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
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{
			Email: "passkey@example.com", PasswordHash: "hash", CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		now := time.Now().UTC()
		var ceremonyHash passkey.CeremonyHash
		ceremonyHash[0] = 6
		ceremony := passkey.Ceremony{Type: passkey.CeremonyRegistration, TokenHash: ceremonyHash,
			SubjectID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
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
		request.StateHash[0] = 7
		request.ConnectionHash[0] = 8
		request.ConnectionID = "organization"
		request.RequestID = "request"
		request.CreatedAt = now
		request.ExpiresAt = now.Add(time.Minute)
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
		stateHash[0] = 1
		now := time.Now().UTC()
		if err := adapter.OIDC().CreateChallenge(ctx, oidc.Challenge{
			StateHash: stateHash, ConnectionID: "organization", Issuer: "https://idp.example.com",
			ClientID: "client", RedirectURL: "https://app.example.com/callback", Scopes: []string{"openid"},
			Nonce: "nonce", CodeVerifier: "verifier", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		}); err != nil {
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

func cleanDatabase(t *testing.T, database *sql.DB) {
	t.Helper()
	tables := []string{"authlier_passkey_credentials", "authlier_passkey_ceremonies",
		"authlier_totp_recovery_codes", "authlier_totp_credentials", "authlier_totp_enrollments",
		"authlier_totp_challenges", "authlier_saml_requests", "authlier_oidc_challenges",
		"authlier_google_challenges", "authlier_refresh_tokens", "authlier_access_sessions",
		"authlier_sessions", "authlier_password_resets", "authlier_email_verifications",
		"authlier_google_identities", "authlier_password_credentials", "authlier_users"}
	if _, err := database.Exec("SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		t.Fatalf("disable foreign keys: %v", err)
	}
	for _, table := range tables {
		if _, err := database.Exec("TRUNCATE TABLE " + table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	if _, err := database.Exec("SET FOREIGN_KEY_CHECKS = 1"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}
}
