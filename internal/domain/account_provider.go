package domain

import "time"

type AccountProvider struct {
	ID                    string
	AccountID             string
	Provider              string
	ProviderAccountID     string
	ProviderEmail         string
	ProviderEmailVerified bool
	ProfileName           string
	ProfileAvatarURL      string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
