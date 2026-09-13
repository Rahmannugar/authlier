package redis_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	authlierredis "github.com/Rahmannugar/authlier/storage/redis"
	"github.com/Rahmannugar/authlier/totp"
	"github.com/google/uuid"
	redislibrary "github.com/redis/go-redis/v9"
)

func TestRedisAdapter(t *testing.T) {
	address := os.Getenv("AUTHLIER_REDIS_TEST_ADDRESS")
	if address == "" {
		t.Skip("AUTHLIER_REDIS_TEST_ADDRESS is not set")
	}
	ctx := context.Background()
	client := redislibrary.NewClient(&redislibrary.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush Redis: %v", err)
	}
	adapter, err := authlierredis.New(client, authlierredis.Config{KeyPrefix: "authlier-test", Secrets: testCodec{}})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("check Redis: %v", err)
	}

	t.Run("registration uses UUIDv7 and a private user handle", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{Email: "owner@example.com", PasswordHash: "encoded-password-hash", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		userID, err := uuid.Parse(user.ID)
		if err != nil || userID.Version() != 7 {
			t.Fatalf("user ID %q is not UUIDv7", user.ID)
		}
		encoded, err := client.HGet(ctx, "{authlier-test}:users", user.ID).Bytes()
		if err != nil {
			t.Fatalf("read user: %v", err)
		}
		var stored struct{ WebAuthnHandle []byte }
		if err := json.Unmarshal(encoded, &stored); err != nil || len(stored.WebAuthnHandle) != 64 {
			t.Fatalf("user handle length = %d, error=%v", len(stored.WebAuthnHandle), err)
		}
	})

	t.Run("mounted handler signs up and resolves a session", func(t *testing.T) {
		configured, err := authlier.New(authlier.Config{
			AppName: "Authlier test", BaseURL: "https://app.example.com", Database: adapter,
			EmailAndPassword: authlier.EmailAndPasswordConfig{Enabled: true}, Session: authlier.SessionConfig{Lifetime: 24 * time.Hour},
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
		request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
		request.AddCookie(response.Result().Cookies()[0])
		response = httptest.NewRecorder()
		configured.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("session status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("verification and reset tokens are replaced and consumed", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{Email: "tokens@example.com", PasswordHash: "old-hash", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		now := time.Now().UTC()
		verification := emailverification.Record{UserID: user.ID, Email: user.Email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		verification.TokenHash[0] = 1
		if err := adapter.EmailVerification().Issue(ctx, verification); err != nil {
			t.Fatalf("issue verification: %v", err)
		}
		verified, err := adapter.EmailVerification().Verify(ctx, verification.TokenHash, now)
		if err != nil || !verified.Verified {
			t.Fatalf("verify: user=%#v err=%v", verified, err)
		}
		reset := passwordreset.Record{UserID: user.ID, Email: user.Email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		reset.TokenHash[0] = 2
		if err := adapter.PasswordReset().Issue(ctx, reset); err != nil {
			t.Fatalf("issue reset: %v", err)
		}
		if _, err := adapter.PasswordReset().ResetPassword(ctx, reset.TokenHash, "new-hash", now); err != nil {
			t.Fatalf("reset password: %v", err)
		}
		_, credential, err := adapter.EmailPassword().FindBySubject(ctx, user.ID)
		if err != nil || credential.PasswordHash != "new-hash" {
			t.Fatalf("credential=%#v err=%v", credential, err)
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

	t.Run("refresh-token reuse revokes the access session", func(t *testing.T) {
		now := time.Now().UTC()
		access := authlier.AccessSession{ID: "access-session", SubjectID: "refresh-user", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := adapter.AccessSessions().Create(ctx, access); err != nil {
			t.Fatalf("create access session: %v", err)
		}
		var currentHash, replacementHash refreshtoken.TokenHash
		currentHash[0], replacementHash[0] = 4, 5
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
		var recoveryCode totp.RecoveryCodeHash
		recoveryCode[0] = 11
		if err := adapter.TOTP().BeginEnrollment(ctx, totp.Enrollment{SubjectID: "totp-user", Secret: "secret", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("begin enrollment: %v", err)
		}
		if err := adapter.TOTP().Enable(ctx, "totp-user", 1, []totp.RecoveryCodeHash{recoveryCode}, now); err != nil {
			t.Fatalf("enable TOTP: %v", err)
		}
		if enabled, err := adapter.TOTP().IsEnabled(ctx, "totp-user"); err != nil || !enabled {
			t.Fatalf("TOTP enabled status: enabled=%t err=%v", enabled, err)
		}
		var challengeHash totp.ChallengeHash
		challengeHash[0] = 6
		if err := adapter.TOTP().CreateChallenge(ctx, totp.Challenge{SubjectID: "totp-user", TokenHash: challengeHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("create challenge: %v", err)
		}
		if _, err := adapter.TOTP().CompleteCode(ctx, challengeHash, 2, now); err != nil {
			t.Fatalf("complete code: %v", err)
		}
		if _, err := adapter.TOTP().CompleteCode(ctx, challengeHash, 3, now); !errors.Is(err, totp.ErrInactiveChallenge) {
			t.Fatalf("replayed challenge error = %v", err)
		}
		challengeHash[0] = 12
		if err := adapter.TOTP().CreateChallenge(ctx, totp.Challenge{SubjectID: "totp-user", TokenHash: challengeHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("create recovery challenge: %v", err)
		}
		if _, err := adapter.TOTP().CompleteRecovery(ctx, challengeHash, recoveryCode, now); err != nil {
			t.Fatalf("complete recovery: %v", err)
		}
		challengeHash[0] = 13
		if err := adapter.TOTP().CreateChallenge(ctx, totp.Challenge{SubjectID: "totp-user", TokenHash: challengeHash, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("create second recovery challenge: %v", err)
		}
		if _, err := adapter.TOTP().CompleteRecovery(ctx, challengeHash, recoveryCode, now); !errors.Is(err, totp.ErrInvalidCode) {
			t.Fatalf("reused recovery code error = %v", err)
		}
	})

	t.Run("passkey registration consumes its ceremony", func(t *testing.T) {
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{Email: "passkey@example.com", PasswordHash: "hash", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		now := time.Now().UTC()
		var ceremonyHash passkey.CeremonyHash
		ceremonyHash[0] = 7
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
		request.StateHash[0], request.ConnectionHash[0] = 8, 9
		request.ConnectionID, request.RequestID, request.CreatedAt, request.ExpiresAt = "organization", "request", now, now.Add(time.Minute)
		if err := adapter.SAML().CreateRequest(ctx, request); err != nil {
			t.Fatalf("create request: %v", err)
		}
		if _, err := adapter.SAML().ConsumeRequest(ctx, request.StateHash, now); err != nil {
			t.Fatalf("consume request: %v", err)
		}
		if _, err := adapter.SAML().ConsumeRequest(ctx, request.StateHash, now); !errors.Is(err, saml.ErrNotFound) {
			t.Fatalf("replayed request error = %v", err)
		}
	})

	t.Run("OIDC state is consumed once under concurrency", func(t *testing.T) {
		var stateHash oidc.StateHash
		stateHash[0] = 10
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

func TestSessionCache(t *testing.T) {
	address := os.Getenv("AUTHLIER_REDIS_TEST_ADDRESS")
	if address == "" {
		t.Skip("AUTHLIER_REDIS_TEST_ADDRESS is not set")
	}
	ctx := context.Background()
	client := redislibrary.NewClient(&redislibrary.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush Redis: %v", err)
	}
	cache, err := authlierredis.NewSessionCache(client, "authlier-test")
	if err != nil {
		t.Fatalf("create cache: %v", err)
	}
	var tokenHash sessiontoken.TokenHash
	tokenHash[0] = 1
	now := time.Now().UTC()
	record := sessiontoken.Record{
		SubjectID: "user",
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := cache.Set(ctx, record, time.Minute); err != nil {
		t.Fatalf("set session: %v", err)
	}
	found, err := cache.Get(ctx, tokenHash)
	if err != nil || found.SubjectID != record.SubjectID || found.TokenHash != tokenHash {
		t.Fatalf("get session: record=%+v error=%v", found, err)
	}
	if err := cache.Delete(ctx, tokenHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if _, err := cache.Get(ctx, tokenHash); !errors.Is(err, sessiontoken.ErrCacheMiss) {
		t.Fatalf("cache miss: got %v", err)
	}
}
