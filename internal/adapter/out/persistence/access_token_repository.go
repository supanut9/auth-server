package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type AccessTokenRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewAccessTokenRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) AccessTokenRepository {
	return AccessTokenRepository{
		db:          db,
		idGenerator: idGenerator,
		clock:       clock,
	}
}

func (r AccessTokenRepository) Create(ctx context.Context, record domain.AccessTokenRecord) (domain.AccessTokenRecord, error) {
	now := r.clock.Now().UTC()

	if record.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.AccessTokenRecord{}, err
		}
		record.ID = id
	}

	if record.Status == "" {
		record.Status = domain.AccessTokenStatusActive
	}

	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}

	model := AccessTokenModel{
		ID:           record.ID,
		JTI:          record.JTI,
		SID:          record.SID,
		AccountID:    record.AccountID,
		ClientID:     record.ClientID,
		SSOSessionID: record.SSOSessionID,
		Audience:     record.Audience,
		Scope:        record.Scope,
		IssuedAt:     record.IssuedAt,
		ExpiresAt:    record.ExpiresAt,
		Status:       record.Status,
		RevokedAt:    record.RevokedAt,
		CreatedAt:    record.CreatedAt,
	}

	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.AccessTokenRecord{}, err
	}

	return mapAccessTokenModel(model), nil
}

func mapAccessTokenModel(model AccessTokenModel) domain.AccessTokenRecord {
	return domain.AccessTokenRecord{
		ID:           model.ID,
		JTI:          model.JTI,
		SID:          model.SID,
		AccountID:    model.AccountID,
		ClientID:     model.ClientID,
		SSOSessionID: model.SSOSessionID,
		Audience:     model.Audience,
		Scope:        model.Scope,
		IssuedAt:     model.IssuedAt,
		ExpiresAt:    model.ExpiresAt,
		Status:       model.Status,
		RevokedAt:    model.RevokedAt,
		CreatedAt:    model.CreatedAt,
	}
}
