package domain

import "time"

type OTPChallenge struct {
	ID                     string
	AuthorizationRequestID *string
	Email                  string
	Purpose                string
	CodeHash               string
	AttemptCount           int
	ResendCount            int
	ExpiresAt              time.Time
	VerifiedAt             *time.Time
	CreatedAt              time.Time
}
