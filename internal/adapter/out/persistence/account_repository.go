package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type AccountRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewAccountRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) AccountRepository {
	return AccountRepository{
		db:          db,
		idGenerator: idGenerator,
		clock:       clock,
	}
}

func (r AccountRepository) Create(ctx context.Context, account domain.Account) (domain.Account, error) {
	now := r.clock.Now().UTC()

	if account.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.Account{}, err
		}
		account.ID = id
	}

	if account.Status == "" {
		account.Status = domain.AccountStatusActive
	}

	model := AccountModel{
		ID:                   account.ID,
		PrimaryVerifiedEmail: account.PrimaryVerifiedEmail,
		DisplayName:          account.DisplayName,
		AvatarURL:            account.AvatarURL,
		Status:               account.Status,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.Account{}, err
	}

	return mapAccountModel(model), nil
}

func (r AccountRepository) FindByPrimaryVerifiedEmail(ctx context.Context, email string) (domain.Account, error) {
	var model AccountModel
	if err := r.db.WithContext(ctx).
		Where("primary_verified_email = ?", email).
		First(&model).Error; err != nil {
		return domain.Account{}, err
	}

	return mapAccountModel(model), nil
}

func (r AccountRepository) FindByID(ctx context.Context, id string) (domain.Account, error) {
	var model AccountModel
	if err := r.db.WithContext(ctx).
		Where("id = ?", id).
		First(&model).Error; err != nil {
		return domain.Account{}, err
	}

	return mapAccountModel(model), nil
}

func (r AccountRepository) Update(ctx context.Context, account domain.Account) (domain.Account, error) {
	now := r.clock.Now().UTC()
	model := AccountModel{
		ID:                   account.ID,
		PrimaryVerifiedEmail: account.PrimaryVerifiedEmail,
		DisplayName:          account.DisplayName,
		AvatarURL:            account.AvatarURL,
		Status:               account.Status,
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            now,
	}

	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.Account{}, err
	}

	return mapAccountModel(model), nil
}

func mapAccountModel(model AccountModel) domain.Account {
	return domain.Account{
		ID:                   model.ID,
		PrimaryVerifiedEmail: model.PrimaryVerifiedEmail,
		DisplayName:          model.DisplayName,
		AvatarURL:            model.AvatarURL,
		Status:               model.Status,
		CreatedAt:            model.CreatedAt,
		UpdatedAt:            model.UpdatedAt,
	}
}
