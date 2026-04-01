package domain

import "time"

type AuthorizationRequest struct {
	ID                           string
	ClientID                     string
	AccountID                    *string
	SSOSessionID                 *string
	RedirectURI                  string
	RequestedScopes              string
	State                        string
	Nonce                        *string
	PKCECodeChallenge            string
	PKCECodeChallengeMethod      string
	PendingProviderName          string
	PendingProviderAccountID     string
	PendingProviderEmail         string
	PendingProviderEmailVerified bool
	PendingProviderDisplayName   string
	PendingProviderAvatarURL     string
	Stage                        string
	ExpiresAt                    time.Time
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
}

type AuthorizationCode struct {
	ID                      string
	CodeHash                string
	AuthorizationRequestID  string
	AccountID               string
	ClientID                string
	SSOSessionID            *string
	RedirectURI             string
	GrantedScopes           string
	PKCECodeChallenge       string
	PKCECodeChallengeMethod string
	AuthTime                time.Time
	ExpiresAt               time.Time
	ConsumedAt              *time.Time
	CreatedAt               time.Time
}

type ConsentGrant struct {
	ID            string
	AccountID     string
	ClientID      string
	GrantedScopes string
	GrantedAt     time.Time
	LastUsedAt    time.Time
	RevokedAt     *time.Time
}

type SSOSession struct {
	ID              string
	AccountID       string
	Status          string
	LoginMethod     string
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
