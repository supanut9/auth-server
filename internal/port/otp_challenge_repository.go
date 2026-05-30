package port

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
)

type OTPChallengeRepository interface {
	Create(ctx context.Context, challenge domain.OTPChallenge) (domain.OTPChallenge, error)
	FindActiveByRequestAndEmail(ctx context.Context, requestID string, email string) (domain.OTPChallenge, error)
	FindByID(ctx context.Context, id string) (domain.OTPChallenge, error)
	Update(ctx context.Context, challenge domain.OTPChallenge) (domain.OTPChallenge, error)
	// FindLatestActiveByEmail returns the most recent unverified, unexpired
	// challenge for the given email. Used only by the non-production test-hint
	// endpoint (INT-244). Returns gorm.ErrRecordNotFound when none exists.
	FindLatestActiveByEmail(ctx context.Context, email string) (domain.OTPChallenge, error)
}
