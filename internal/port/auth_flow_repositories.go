package port

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
)

type AuthorizationRequestRepository interface {
	Create(ctx context.Context, request domain.AuthorizationRequest) (domain.AuthorizationRequest, error)
	FindByID(ctx context.Context, id string) (domain.AuthorizationRequest, error)
	Update(ctx context.Context, request domain.AuthorizationRequest) (domain.AuthorizationRequest, error)
}

type AuthorizationCodeRepository interface {
	Create(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error)
	FindByCodeHash(ctx context.Context, codeHash string) (domain.AuthorizationCode, error)
	Update(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error)
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
