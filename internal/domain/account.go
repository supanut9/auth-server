package domain

import "time"

type Account struct {
	ID                   string
	PrimaryVerifiedEmail string
	DisplayName          string
	AvatarURL            string
	Status               string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}
