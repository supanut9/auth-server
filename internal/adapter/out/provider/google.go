package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/supanut9/auth-server/internal/port"
)

type GoogleProvider struct {
	client       *http.Client
	clientID     string
	clientSecret string
	redirectURL  string
}

func NewGoogleProvider(clientID string, clientSecret string, redirectURL string) GoogleProvider {
	return GoogleProvider{
		client:       &http.Client{Timeout: 10 * time.Second},
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (p GoogleProvider) Name() string {
	return "google"
}

func (p GoogleProvider) ExchangeAuthorizationCode(ctx context.Context, code string, redirectURI string) (port.ProviderProfile, error) {
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", firstNonEmpty(redirectURI, p.redirectURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return port.ProviderProfile{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return port.ProviderProfile{}, fmt.Errorf("google token exchange failed: %s", resp.Status)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return port.ProviderProfile{}, err
	}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	userResp, err := p.client.Do(userReq)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	defer userResp.Body.Close()

	if userResp.StatusCode >= http.StatusBadRequest {
		return port.ProviderProfile{}, fmt.Errorf("google userinfo failed: %s", userResp.Status)
	}

	var profile struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&profile); err != nil {
		return port.ProviderProfile{}, err
	}

	return port.ProviderProfile{
		Name:          "google",
		AccountID:     profile.Sub,
		Email:         profile.Email,
		EmailVerified: profile.EmailVerified,
		DisplayName:   profile.Name,
		AvatarURL:     profile.Picture,
	}, nil
}
