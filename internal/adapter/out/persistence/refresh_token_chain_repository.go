package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type RefreshTokenChainRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewRefreshTokenChainRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) RefreshTokenChainRepository {
	return RefreshTokenChainRepository{
		db:          db,
		idGenerator: idGenerator,
		clock:       clock,
	}
}

func (r RefreshTokenChainRepository) Create(ctx context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	now := r.clock.Now().UTC()

	if chain.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.RefreshTokenChain{}, err
		}
		chain.ID = id
	}

	if chain.Status == "" {
		chain.Status = domain.RefreshTokenChainStatusActive
	}
	if chain.CreatedAt.IsZero() {
		chain.CreatedAt = now
	}
	if chain.UpdatedAt.IsZero() {
		chain.UpdatedAt = now
	}

	model := RefreshTokenChainModel{
		ID:                chain.ID,
		AccountID:         chain.AccountID,
		ClientID:          chain.ClientID,
		SSOSessionID:      chain.SSOSessionID,
		Scope:             chain.Scope,
		DeviceSessionID:   chain.DeviceSessionID,
		Status:            chain.Status,
		AbsoluteExpiresAt: chain.AbsoluteExpiresAt,
		InactiveExpiresAt: chain.InactiveExpiresAt,
		LastUsedAt:        chain.LastUsedAt,
		RevokedAt:         chain.RevokedAt,
		CreatedAt:         chain.CreatedAt,
		UpdatedAt:         chain.UpdatedAt,
	}

	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.RefreshTokenChain{}, err
	}

	return mapRefreshTokenChainModel(model), nil
}

func (r RefreshTokenChainRepository) FindByID(ctx context.Context, id string) (domain.RefreshTokenChain, error) {
	var model RefreshTokenChainModel
	if err := r.db.WithContext(ctx).
		Where("id = ?", id).
		First(&model).Error; err != nil {
		return domain.RefreshTokenChain{}, err
	}

	return mapRefreshTokenChainModel(model), nil
}

func (r RefreshTokenChainRepository) Update(ctx context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	chain.UpdatedAt = r.clock.Now().UTC()

	model := RefreshTokenChainModel{
		ID:                chain.ID,
		AccountID:         chain.AccountID,
		ClientID:          chain.ClientID,
		SSOSessionID:      chain.SSOSessionID,
		Scope:             chain.Scope,
		DeviceSessionID:   chain.DeviceSessionID,
		Status:            chain.Status,
		AbsoluteExpiresAt: chain.AbsoluteExpiresAt,
		InactiveExpiresAt: chain.InactiveExpiresAt,
		LastUsedAt:        chain.LastUsedAt,
		RevokedAt:         chain.RevokedAt,
		CreatedAt:         chain.CreatedAt,
		UpdatedAt:         chain.UpdatedAt,
	}

	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.RefreshTokenChain{}, err
	}

	return mapRefreshTokenChainModel(model), nil
}

func (r RefreshTokenChainRepository) RevokeByID(ctx context.Context, id string) error {
	now := r.clock.Now().UTC()
	return r.db.WithContext(ctx).
		Model(&RefreshTokenChainModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":     domain.RefreshTokenChainStatusRevoked,
			"revoked_at": now,
			"updated_at": now,
		}).Error
}

func mapRefreshTokenChainModel(model RefreshTokenChainModel) domain.RefreshTokenChain {
	return domain.RefreshTokenChain{
		ID:                model.ID,
		AccountID:         model.AccountID,
		ClientID:          model.ClientID,
		SSOSessionID:      model.SSOSessionID,
		Scope:             model.Scope,
		DeviceSessionID:   model.DeviceSessionID,
		Status:            model.Status,
		AbsoluteExpiresAt: model.AbsoluteExpiresAt,
		InactiveExpiresAt: model.InactiveExpiresAt,
		LastUsedAt:        model.LastUsedAt,
		RevokedAt:         model.RevokedAt,
		CreatedAt:         model.CreatedAt,
		UpdatedAt:         model.UpdatedAt,
	}
}
