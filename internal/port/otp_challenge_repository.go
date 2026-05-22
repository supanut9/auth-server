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
}
