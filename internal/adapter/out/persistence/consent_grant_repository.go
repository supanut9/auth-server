package persistence

import (
	"context"
	"errors"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type ConsentGrantRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewConsentGrantRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) ConsentGrantRepository {
	return ConsentGrantRepository{db: db, idGenerator: idGenerator, clock: clock}
}

func (r ConsentGrantRepository) FindByAccountAndClient(ctx context.Context, accountID string, clientID string) (domain.ConsentGrant, error) {
	var model ConsentGrantModel
	if err := r.db.WithContext(ctx).
		Where("account_id = ? AND client_id = ?", accountID, clientID).
		First(&model).Error; err != nil {
		return domain.ConsentGrant{}, err
	}
	return mapConsentGrantModel(model), nil
}

func (r ConsentGrantRepository) Upsert(ctx context.Context, grant domain.ConsentGrant) (domain.ConsentGrant, error) {
	now := r.clock.Now().UTC()

	var model ConsentGrantModel
	err := r.db.WithContext(ctx).
		Where("account_id = ? AND client_id = ?", grant.AccountID, grant.ClientID).
		First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if grant.ID == "" {
			id, idErr := r.idGenerator.NewID()
			if idErr != nil {
				return domain.ConsentGrant{}, idErr
			}
			grant.ID = id
		}
		if grant.GrantedAt.IsZero() {
			grant.GrantedAt = now
		}
		if grant.LastUsedAt.IsZero() {
			grant.LastUsedAt = now
		}

		model = ConsentGrantModel{
			ID:            grant.ID,
			AccountID:     grant.AccountID,
			ClientID:      grant.ClientID,
			GrantedScopes: grant.GrantedScopes,
			GrantedAt:     grant.GrantedAt,
			LastUsedAt:    grant.LastUsedAt,
			RevokedAt:     grant.RevokedAt,
		}
		if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
			return domain.ConsentGrant{}, err
		}
		return mapConsentGrantModel(model), nil
	}
	if err != nil {
		return domain.ConsentGrant{}, err
	}

	model.GrantedScopes = grant.GrantedScopes
	model.LastUsedAt = now
	model.RevokedAt = grant.RevokedAt
	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.ConsentGrant{}, err
	}
	return mapConsentGrantModel(model), nil
}

func mapConsentGrantModel(model ConsentGrantModel) domain.ConsentGrant {
	return domain.ConsentGrant{
		ID:            model.ID,
		AccountID:     model.AccountID,
		ClientID:      model.ClientID,
		GrantedScopes: model.GrantedScopes,
		GrantedAt:     model.GrantedAt,
		LastUsedAt:    model.LastUsedAt,
		RevokedAt:     model.RevokedAt,
	}
}
