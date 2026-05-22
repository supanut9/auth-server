package port

import (
	"context"
	"time"

	"github.com/supanut9/auth-server/internal/domain"
)

type AuthorizationCodeRepository interface {
	Create(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error)
	FindByCodeHash(ctx context.Context, codeHash string) (domain.AuthorizationCode, error)
	Update(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error)
}

// SignedStateJTIRepository tracks consumed envelope JTIs (replay protection for
// the OAuth `state` we sign and send to external providers).
type SignedStateJTIRepository interface {
	Insert(ctx context.Context, jti string, expiresAt time.Time) error
	PruneExpired(ctx context.Context, now time.Time) error
}

type ConsentGrantRepository interface {
	FindByAccountAndClient(ctx context.Context, accountID string, clientID string) (domain.ConsentGrant, error)
	Upsert(ctx context.Context, grant domain.ConsentGrant) (domain.ConsentGrant, error)
}

type SSOSessionRepository interface {
	Create(ctx context.Context, session domain.SSOSession) (domain.SSOSession, error)
	FindByID(ctx context.Context, id string) (domain.SSOSession, error)
	Update(ctx context.Context, session domain.SSOSession) (domain.SSOSession, error)
	RevokeByID(ctx context.Context, id string) error
}
