package googleoauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	oidclibrary "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	googleIssuer          = "https://accounts.google.com"
	AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
)

type GoogleProviderConfig struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

type googleProvider struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
	mu           sync.Mutex
	discovery    *oidclibrary.Provider
}

func NewGoogleProvider(config GoogleProviderConfig) (Provider, error) {
	clientID := strings.TrimSpace(config.ClientID)
	clientSecret := strings.TrimSpace(config.ClientSecret)
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("%w: Google client ID and secret are required", ErrInvalidConfig)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &googleProvider{
		clientID: clientID, clientSecret: clientSecret, httpClient: httpClient,
	}, nil
}

func (provider *googleProvider) Exchange(ctx context.Context, input ExchangeInput) (Identity, error) {
	discovery, err := provider.openIDProvider(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx = oidclibrary.ClientContext(ctx, provider.httpClient)
	oauthConfig := oauth2.Config{
		ClientID:     provider.clientID,
		ClientSecret: provider.clientSecret,
		Endpoint:     discovery.Endpoint(),
		RedirectURL:  input.RedirectURL,
		Scopes:       []string{oidclibrary.ScopeOpenID, "email", "profile"},
	}
	token, err := oauthConfig.Exchange(ctx, input.Code, oauth2.VerifierOption(input.CodeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, ErrInvalidRecord
	}
	verified, err := discovery.Verifier(&oidclibrary.Config{ClientID: input.Audience}).Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify Google ID token: %w", err)
	}
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Nonce         string `json:"nonce"`
	}
	if err := verified.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read Google ID token claims: %w", err)
	}
	return Identity{
		ProviderSubject: claims.Subject,
		Email:           claims.Email,
		EmailVerified:   claims.EmailVerified,
		Nonce:           claims.Nonce,
	}, nil
}

func (provider *googleProvider) openIDProvider(ctx context.Context) (*oidclibrary.Provider, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.discovery != nil {
		return provider.discovery, nil
	}
	discovery, err := oidclibrary.NewProvider(
		oidclibrary.ClientContext(ctx, provider.httpClient),
		googleIssuer,
	)
	if err != nil {
		return nil, fmt.Errorf("discover Google OpenID provider: %w", err)
	}
	provider.discovery = discovery
	return discovery, nil
}
