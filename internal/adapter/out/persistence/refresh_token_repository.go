package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type RefreshTokenRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
}

func NewRefreshTokenRepository(db *gorm.DB, idGenerator port.IDGenerator) RefreshTokenRepository {
	return RefreshTokenRepository{
		db:          db,
		idGenerator: idGenerator,
	}
}

func (r RefreshTokenRepository) Create(ctx context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	if token.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.RefreshToken{}, err
		}
		token.ID = id
	}

	model := RefreshTokenModel{
		ID:                  token.ID,
		RefreshTokenChainID: token.RefreshTokenChainID,
		TokenHash:           token.TokenHash,
		IssuedAt:            token.IssuedAt,
		ExpiresAt:           token.ExpiresAt,
		UsedAt:              token.UsedAt,
		ReplacedByTokenID:   token.ReplacedByTokenID,
		RevokedAt:           token.RevokedAt,
	}

	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.RefreshToken{}, err
	}

	return mapRefreshTokenModel(model), nil
}

func (r RefreshTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	var model RefreshTokenModel
	if err := r.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&model).Error; err != nil {
		return domain.RefreshToken{}, err
	}

	return mapRefreshTokenModel(model), nil
}

func (r RefreshTokenRepository) Update(ctx context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	model := RefreshTokenModel{
		ID:                  token.ID,
		RefreshTokenChainID: token.RefreshTokenChainID,
		TokenHash:           token.TokenHash,
		IssuedAt:            token.IssuedAt,
		ExpiresAt:           token.ExpiresAt,
		UsedAt:              token.UsedAt,
		ReplacedByTokenID:   token.ReplacedByTokenID,
		RevokedAt:           token.RevokedAt,
	}

	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.RefreshToken{}, err
	}

	return mapRefreshTokenModel(model), nil
}

func (r RefreshTokenRepository) RevokeByChainID(ctx context.Context, chainID string) error {
	return r.db.WithContext(ctx).
		Model(&RefreshTokenModel{}).
		Where("refresh_token_chain_id = ?", chainID).
		Update("revoked_at", gorm.Expr("NOW()")).Error
}

func mapRefreshTokenModel(model RefreshTokenModel) domain.RefreshToken {
	return domain.RefreshToken{
		ID:                  model.ID,
		RefreshTokenChainID: model.RefreshTokenChainID,
		TokenHash:           model.TokenHash,
		IssuedAt:            model.IssuedAt,
		ExpiresAt:           model.ExpiresAt,
		UsedAt:              model.UsedAt,
		ReplacedByTokenID:   model.ReplacedByTokenID,
		RevokedAt:           model.RevokedAt,
	}
}
