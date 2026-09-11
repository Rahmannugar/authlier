package postgres_test

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
	"github.com/Rahmannugar/authlier/oidc"
	"github.com/Rahmannugar/authlier/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAdapter(t *testing.T) {
	dsn := os.Getenv("AUTHLIER_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("AUTHLIER_POSTGRES_TEST_DSN is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(pool.Close)
	adapter, err := postgres.New(pool, postgres.Config{})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	cleanDatabase(t, pool)

	t.Run("registration uses UUIDv7 and a private user handle", func(t *testing.T) {
		createdAt := time.Now().UTC()
		user, err := adapter.EmailPassword().Register(ctx, emailpassword.Registration{
			Email:        "owner@example.com",
			PasswordHash: "encoded-password-hash",
			CreatedAt:    createdAt,
		})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		userID, err := uuid.Parse(user.ID)
		if err != nil || userID.Version() != 7 {
			t.Fatalf("user ID %q is not UUIDv7", user.ID)
		}
		var handle []byte
		if err := pool.QueryRow(ctx,
			"SELECT webauthn_handle FROM authlier_users WHERE id = $1", user.ID,
		).Scan(&handle); err != nil {
			t.Fatalf("read user handle: %v", err)
		}
		if len(handle) != 64 {
			t.Fatalf("user handle length = %d, want 64", len(handle))
		}
	})

	t.Run("mounted handler signs up and resolves a session", func(t *testing.T) {
		configured, err := authlier.New(authlier.Config{
			AppName:          "Authlier test",
			BaseURL:          "https://app.example.com",
			Database:         adapter,
			EmailAndPassword: authlier.EmailAndPasswordConfig{Enabled: true},
			Session:          authlier.SessionConfig{Lifetime: 24 * time.Hour},
		})
		if err != nil {
			t.Fatalf("configure Authlier: %v", err)
		}

		signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
			bytes.NewBufferString(`{"email":"new@example.com","password":"correct horse battery staple"}`))
		signUp.Header.Set("Origin", "https://app.example.com")
		signUpResponse := httptest.NewRecorder()
		configured.Handler().ServeHTTP(signUpResponse, signUp)
		if signUpResponse.Code != http.StatusCreated {
			t.Fatalf("sign up status = %d, body = %s", signUpResponse.Code, signUpResponse.Body.String())
		}
		cookies := signUpResponse.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != "authlier_session" || !cookies[0].HttpOnly || !cookies[0].Secure {
			t.Fatalf("unexpected session cookie: %#v", cookies)
		}

		currentSession := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
		currentSession.AddCookie(cookies[0])
		sessionResponse := httptest.NewRecorder()
		configured.Handler().ServeHTTP(sessionResponse, currentSession)
		if sessionResponse.Code != http.StatusOK {
			t.Fatalf("session status = %d, body = %s", sessionResponse.Code, sessionResponse.Body.String())
		}
	})

	t.Run("OIDC state is consumed once under concurrency", func(t *testing.T) {
		var stateHash oidc.StateHash
		stateHash[0] = 1
		now := time.Now().UTC()
		err := adapter.OIDC().CreateChallenge(ctx, oidc.Challenge{
			StateHash:    stateHash,
			ConnectionID: "organization",
			Issuer:       "https://idp.example.com",
			ClientID:     "client",
			RedirectURL:  "https://app.example.com/callback",
			Scopes:       []string{"openid"},
			Nonce:        "nonce",
			CodeVerifier: "verifier",
			CreatedAt:    now,
			ExpiresAt:    now.Add(time.Minute),
		})
		if err != nil {
			t.Fatalf("create challenge: %v", err)
		}
		var consumed atomic.Int32
		var rejected atomic.Int32
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

func cleanDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `TRUNCATE
		authlier_passkey_credentials,
		authlier_passkey_ceremonies,
		authlier_totp_recovery_codes,
		authlier_totp_credentials,
		authlier_totp_enrollments,
		authlier_totp_challenges,
		authlier_saml_requests,
		authlier_oidc_challenges,
		authlier_google_challenges,
		authlier_refresh_tokens,
		authlier_access_sessions,
		authlier_sessions,
		authlier_password_resets,
		authlier_email_verifications,
		authlier_google_identities,
		authlier_password_credentials,
		authlier_users CASCADE`)
	if err != nil {
		t.Fatalf("clean database: %v", err)
	}
}
