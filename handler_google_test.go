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
		newAuthRequest("/api/auth/sign-in/google", `{}`),
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
		"/api/auth/callback/google?state="+url.QueryEscape(authorizationURL.Query().Get("state"))+"&code=provider-code",
		nil,
	))
	if callback.Code != http.StatusOK || sessions.created != 1 {
		t.Fatalf("complete Google sign in: status=%d sessions=%d body=%s", callback.Code, sessions.created, callback.Body.String())
	}
	if googleStore.resolution.ProviderSubject != "google-account-123" ||
		googleStore.resolution.Email != "owner@example.com" {
		t.Fatalf("unexpected identity resolution: %+v", googleStore.resolution)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/auth/list-accounts/google", nil)
	listRequest.AddCookie(callback.Result().Cookies()[0])
	listed := httptest.NewRecorder()
	auth.Handler().ServeHTTP(listed, listRequest)
	var accounts googleAccountsResponse
	if err := json.Unmarshal(listed.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("decode linked accounts: %v", err)
	}
	if listed.Code != http.StatusOK || len(accounts.Accounts) != 1 ||
		accounts.Accounts[0].ProviderSubject != "google-account-123" {
		t.Fatalf("linked accounts: status=%d accounts=%+v", listed.Code, accounts.Accounts)
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
	string,
	time.Time,
) error {
	return nil
}

func (*handlerGoogleStore) ListIdentities(
	_ context.Context,
	subjectID string,
) ([]googleoauth.LinkedIdentity, error) {
	if subjectID != "user_123" {
		return []googleoauth.LinkedIdentity{}, nil
	}
	return []googleoauth.LinkedIdentity{{
		ProviderSubject: "google-account-123",
		Email:           "owner@example.com",
		LinkedAt:        time.Now().UTC(),
	}}, nil
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
