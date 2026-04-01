package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type AccountProviderRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewAccountProviderRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) AccountProviderRepository {
	return AccountProviderRepository{
		db:          db,
		idGenerator: idGenerator,
		clock:       clock,
	}
}

func (r AccountProviderRepository) Create(ctx context.Context, provider domain.AccountProvider) (domain.AccountProvider, error) {
	now := r.clock.Now().UTC()

	if provider.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.AccountProvider{}, err
		}
		provider.ID = id
	}

	model := AccountProviderModel{
		ID:                    provider.ID,
		AccountID:             provider.AccountID,
		Provider:              provider.Provider,
		ProviderAccountID:     provider.ProviderAccountID,
		ProviderEmail:         provider.ProviderEmail,
		ProviderEmailVerified: provider.ProviderEmailVerified,
		ProfileName:           provider.ProfileName,
		ProfileAvatarURL:      provider.ProfileAvatarURL,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.AccountProvider{}, err
	}

	return mapAccountProviderModel(model), nil
}

func (r AccountProviderRepository) FindByProviderAccountID(ctx context.Context, provider string, providerAccountID string) (domain.AccountProvider, error) {
	var model AccountProviderModel
	if err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_account_id = ?", provider, providerAccountID).
		First(&model).Error; err != nil {
		return domain.AccountProvider{}, err
	}

	return mapAccountProviderModel(model), nil
}

func mapAccountProviderModel(model AccountProviderModel) domain.AccountProvider {
	return domain.AccountProvider{
		ID:                    model.ID,
		AccountID:             model.AccountID,
		Provider:              model.Provider,
		ProviderAccountID:     model.ProviderAccountID,
		ProviderEmail:         model.ProviderEmail,
		ProviderEmailVerified: model.ProviderEmailVerified,
		ProfileName:           model.ProfileName,
		ProfileAvatarURL:      model.ProfileAvatarURL,
		CreatedAt:             model.CreatedAt,
		UpdatedAt:             model.UpdatedAt,
	}
}
