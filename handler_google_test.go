package authlier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Rahmannugar/authlier/googleoauth"
)

func TestGoogleRoutesCompleteAuthenticationWithTheStableProviderSubject(t *testing.T) {
	googleStore := &handlerGoogleStore{}
	sessions := newSessionStore(time.Now().UTC())
	provider := &handlerGoogleProvider{store: googleStore}
	auth, err := New(Config{
		AppName: "Acme",
		BaseURL: "https://app.example.com",
		Database: handlerDatabase{stores: Stores{
			Google:   googleStore,
			Sessions: sessions,
		}},
		Google: GoogleConfig{
			Enabled:  true,
			ClientID: "google-client-id",
			Provider: provider,
		},
	})
	if err != nil {
		t.Fatalf("create Authlier: %v", err)
	}

	startedResponse := httptest.NewRecorder()
	auth.Handler().ServeHTTP(
		startedResponse,
		newAuthRequest("/api/auth/google", `{}`),
	)
	if startedResponse.Code != http.StatusOK {
		t.Fatalf("begin Google sign in: status=%d body=%s", startedResponse.Code, startedResponse.Body.String())
	}
	var started authorizationURLResponse
	if err := json.Unmarshal(startedResponse.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode authorization URL: %v", err)
	}
	authorizationURL, err := url.Parse(started.URL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}

	callback := httptest.NewRecorder()
	auth.Handler().ServeHTTP(callback, httptest.NewRequest(
		http.MethodGet,
		"/api/auth/google/callback?state="+url.QueryEscape(authorizationURL.Query().Get("state"))+"&code=provider-code",
		nil,
	))
	if callback.Code != http.StatusOK || sessions.created != 1 {
		t.Fatalf("complete Google sign in: status=%d sessions=%d body=%s", callback.Code, sessions.created, callback.Body.String())
	}
	if googleStore.resolution.ProviderSubject != "google-account-123" ||
		googleStore.resolution.Email != "owner@example.com" {
		t.Fatalf("unexpected identity resolution: %+v", googleStore.resolution)
	}
}

type handlerGoogleStore struct {
	challenge  googleoauth.Challenge
	nonce      string
	resolution googleoauth.IdentityResolution
}

func (store *handlerGoogleStore) CreateChallenge(
	_ context.Context,
	challenge googleoauth.Challenge,
) error {
	store.challenge = challenge
	store.nonce = challenge.Nonce
	return nil
}

func (store *handlerGoogleStore) ConsumeChallenge(
	_ context.Context,
	stateHash [32]byte,
	consumedAt time.Time,
) (googleoauth.Challenge, error) {
	if stateHash != store.challenge.StateHash || !consumedAt.Before(store.challenge.ExpiresAt) {
		return googleoauth.Challenge{}, googleoauth.ErrNotFound
	}
	challenge := store.challenge
	store.challenge = googleoauth.Challenge{}
	return challenge, nil
}

func (store *handlerGoogleStore) ResolveIdentity(
	_ context.Context,
	resolution googleoauth.IdentityResolution,
) (googleoauth.User, error) {
	store.resolution = resolution
	return googleoauth.User{ID: "user_123"}, nil
}

func (*handlerGoogleStore) UnlinkIdentity(
	context.Context,
	string,
	time.Time,
) error {
	return nil
}

type handlerGoogleProvider struct {
	store *handlerGoogleStore
}

func (provider *handlerGoogleProvider) Exchange(
	_ context.Context,
	_ googleoauth.ExchangeInput,
) (googleoauth.Identity, error) {
	return googleoauth.Identity{
		ProviderSubject: "google-account-123",
		Email:           "owner@example.com",
		EmailVerified:   true,
		Nonce:           provider.store.nonce,
	}, nil
}
