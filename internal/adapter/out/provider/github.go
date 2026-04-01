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

type GitHubProvider struct {
	client       *http.Client
	clientID     string
	clientSecret string
	redirectURL  string
}

func NewGitHubProvider(clientID string, clientSecret string, redirectURL string) GitHubProvider {
	return GitHubProvider{
		client:       &http.Client{Timeout: 10 * time.Second},
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (p GitHubProvider) Name() string {
	return "github"
}

func (p GitHubProvider) ExchangeAuthorizationCode(ctx context.Context, code string, redirectURI string) (port.ProviderProfile, error) {
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", firstNonEmpty(redirectURI, p.redirectURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return port.ProviderProfile{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return port.ProviderProfile{}, fmt.Errorf("github token exchange failed: %s", resp.Status)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return port.ProviderProfile{}, err
	}

	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userReq.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	userReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	userResp, err := p.client.Do(userReq)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	defer userResp.Body.Close()

	if userResp.StatusCode >= http.StatusBadRequest {
		return port.ProviderProfile{}, fmt.Errorf("github user fetch failed: %s", userResp.Status)
	}

	var profile struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&profile); err != nil {
		return port.ProviderProfile{}, err
	}

	emailReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	emailReq.Header.Set("Accept", "application/vnd.github+json")
	emailReq.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	emailReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	emailResp, err := p.client.Do(emailReq)
	if err != nil {
		return port.ProviderProfile{}, err
	}
	defer emailResp.Body.Close()

	if emailResp.StatusCode >= http.StatusBadRequest {
		return port.ProviderProfile{}, fmt.Errorf("github email fetch failed: %s", emailResp.Status)
	}

	var emails []struct {
		Email      string `json:"email"`
		Primary    bool   `json:"primary"`
		Verified   bool   `json:"verified"`
		Visibility string `json:"visibility"`
	}
	if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
		return port.ProviderProfile{}, err
	}

	email, verified := pickGitHubEmail(emails)
	return port.ProviderProfile{
		Name:          "github",
		AccountID:     fmt.Sprintf("%d", profile.ID),
		Email:         email,
		EmailVerified: verified,
		DisplayName:   firstNonEmpty(profile.Name, profile.Login),
		AvatarURL:     profile.AvatarURL,
	}, nil
}

func pickGitHubEmail(emails []struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}) (string, bool) {
	for _, item := range emails {
		if item.Primary {
			return item.Email, item.Verified
		}
	}
	for _, item := range emails {
		if item.Verified {
			return item.Email, true
		}
	}
	if len(emails) == 0 {
		return "", false
	}
	return emails[0].Email, emails[0].Verified
}
