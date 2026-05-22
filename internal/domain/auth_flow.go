package domain

import "time"

type AuthorizationCode struct {
	ID                      string
	CodeHash                string
	AuthorizationRequestID  *string
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
