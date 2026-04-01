package domain

import "time"

type AccessTokenRecord struct {
	ID           string
	JTI          string
	SID          string
	AccountID    *string
	ClientID     string
	SSOSessionID *string
	Audience     string
	Scope        string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Status       string
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

type RefreshTokenChain struct {
	ID                string
	AccountID         string
	ClientID          string
	SSOSessionID      string
	Scope             string
	DeviceSessionID   string
	Status            string
	AbsoluteExpiresAt time.Time
	InactiveExpiresAt time.Time
	LastUsedAt        time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type RefreshToken struct {
	ID                  string
	RefreshTokenChainID string
	TokenHash           string
	IssuedAt            time.Time
	ExpiresAt           time.Time
	UsedAt              *time.Time
	ReplacedByTokenID   *string
	RevokedAt           *time.Time
}
