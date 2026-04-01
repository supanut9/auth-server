package domain

import "time"

type OAuthClient struct {
	ID               string
	ClientID         string
	ClientType       string
	ClientSecretHash string
	DisplayName      string
	RedirectURIs     string
	AllowedScopes    string
	Status           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
