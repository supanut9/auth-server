package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type AuthorizationCodeRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewAuthorizationCodeRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) AuthorizationCodeRepository {
	return AuthorizationCodeRepository{db: db, idGenerator: idGenerator, clock: clock}
}

func (r AuthorizationCodeRepository) Create(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	now := r.clock.Now().UTC()
	if code.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.AuthorizationCode{}, err
		}
		code.ID = id
	}
	if code.CreatedAt.IsZero() {
		code.CreatedAt = now
	}

	model := AuthorizationCodeModel{
		ID:                      code.ID,
		CodeHash:                code.CodeHash,
		AuthorizationRequestID:  code.AuthorizationRequestID,
		AccountID:               code.AccountID,
		ClientID:                code.ClientID,
		SSOSessionID:            code.SSOSessionID,
		RedirectURI:             code.RedirectURI,
		GrantedScopes:           code.GrantedScopes,
		PKCECodeChallenge:       code.PKCECodeChallenge,
		PKCECodeChallengeMethod: code.PKCECodeChallengeMethod,
		AuthTime:                code.AuthTime,
		ExpiresAt:               code.ExpiresAt,
		ConsumedAt:              code.ConsumedAt,
		CreatedAt:               code.CreatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.AuthorizationCode{}, err
	}
	return mapAuthorizationCodeModel(model), nil
}

func (r AuthorizationCodeRepository) FindByCodeHash(ctx context.Context, codeHash string) (domain.AuthorizationCode, error) {
	var model AuthorizationCodeModel
	if err := r.db.WithContext(ctx).Where("code_hash = ?", codeHash).First(&model).Error; err != nil {
		return domain.AuthorizationCode{}, err
	}
	return mapAuthorizationCodeModel(model), nil
}

func (r AuthorizationCodeRepository) Update(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	model := AuthorizationCodeModel{
		ID:                      code.ID,
		CodeHash:                code.CodeHash,
		AuthorizationRequestID:  code.AuthorizationRequestID,
		AccountID:               code.AccountID,
		ClientID:                code.ClientID,
		SSOSessionID:            code.SSOSessionID,
		RedirectURI:             code.RedirectURI,
		GrantedScopes:           code.GrantedScopes,
		PKCECodeChallenge:       code.PKCECodeChallenge,
		PKCECodeChallengeMethod: code.PKCECodeChallengeMethod,
		AuthTime:                code.AuthTime,
		ExpiresAt:               code.ExpiresAt,
		ConsumedAt:              code.ConsumedAt,
		CreatedAt:               code.CreatedAt,
	}
	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.AuthorizationCode{}, err
	}
	return mapAuthorizationCodeModel(model), nil
}

func mapAuthorizationCodeModel(model AuthorizationCodeModel) domain.AuthorizationCode {
	return domain.AuthorizationCode{
		ID:                      model.ID,
		CodeHash:                model.CodeHash,
		AuthorizationRequestID:  model.AuthorizationRequestID,
		AccountID:               model.AccountID,
		ClientID:                model.ClientID,
		SSOSessionID:            model.SSOSessionID,
		RedirectURI:             model.RedirectURI,
		GrantedScopes:           model.GrantedScopes,
		PKCECodeChallenge:       model.PKCECodeChallenge,
		PKCECodeChallengeMethod: model.PKCECodeChallengeMethod,
		AuthTime:                model.AuthTime,
		ExpiresAt:               model.ExpiresAt,
		ConsumedAt:              model.ConsumedAt,
		CreatedAt:               model.CreatedAt,
	}
}
