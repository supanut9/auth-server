package port

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
)

type AccessTokenRepository interface {
	Create(ctx context.Context, record domain.AccessTokenRecord) (domain.AccessTokenRecord, error)
}

type RefreshTokenChainRepository interface {
	Create(ctx context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error)
	FindByID(ctx context.Context, id string) (domain.RefreshTokenChain, error)
	Update(ctx context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error)
	RevokeByID(ctx context.Context, id string) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token domain.RefreshToken) (domain.RefreshToken, error)
	FindByTokenHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error)
	Update(ctx context.Context, token domain.RefreshToken) (domain.RefreshToken, error)
	RevokeByChainID(ctx context.Context, chainID string) error
}
