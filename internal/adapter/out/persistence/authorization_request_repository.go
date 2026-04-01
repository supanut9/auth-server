package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type AuthorizationRequestRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewAuthorizationRequestRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) AuthorizationRequestRepository {
	return AuthorizationRequestRepository{db: db, idGenerator: idGenerator, clock: clock}
}

func (r AuthorizationRequestRepository) Create(ctx context.Context, request domain.AuthorizationRequest) (domain.AuthorizationRequest, error) {
	now := r.clock.Now().UTC()
	if request.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.AuthorizationRequest{}, err
		}
		request.ID = id
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = now
	}
	if request.UpdatedAt.IsZero() {
		request.UpdatedAt = now
	}

	model := AuthorizationRequestModel{
		ID:                           request.ID,
		ClientID:                     request.ClientID,
		AccountID:                    request.AccountID,
		SSOSessionID:                 request.SSOSessionID,
		RedirectURI:                  request.RedirectURI,
		RequestedScopes:              request.RequestedScopes,
		State:                        request.State,
		Nonce:                        request.Nonce,
		PKCECodeChallenge:            request.PKCECodeChallenge,
		PKCECodeChallengeMethod:      request.PKCECodeChallengeMethod,
		PendingProviderName:          request.PendingProviderName,
		PendingProviderAccountID:     request.PendingProviderAccountID,
		PendingProviderEmail:         request.PendingProviderEmail,
		PendingProviderEmailVerified: request.PendingProviderEmailVerified,
		PendingProviderDisplayName:   request.PendingProviderDisplayName,
		PendingProviderAvatarURL:     request.PendingProviderAvatarURL,
		Stage:                        request.Stage,
		ExpiresAt:                    request.ExpiresAt,
		CreatedAt:                    request.CreatedAt,
		UpdatedAt:                    request.UpdatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.AuthorizationRequest{}, err
	}
	return mapAuthorizationRequestModel(model), nil
}

func (r AuthorizationRequestRepository) FindByID(ctx context.Context, id string) (domain.AuthorizationRequest, error) {
	var model AuthorizationRequestModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&model).Error; err != nil {
		return domain.AuthorizationRequest{}, err
	}
	return mapAuthorizationRequestModel(model), nil
}

func (r AuthorizationRequestRepository) Update(ctx context.Context, request domain.AuthorizationRequest) (domain.AuthorizationRequest, error) {
	request.UpdatedAt = r.clock.Now().UTC()
	model := AuthorizationRequestModel{
		ID:                           request.ID,
		ClientID:                     request.ClientID,
		AccountID:                    request.AccountID,
		SSOSessionID:                 request.SSOSessionID,
		RedirectURI:                  request.RedirectURI,
		RequestedScopes:              request.RequestedScopes,
		State:                        request.State,
		Nonce:                        request.Nonce,
		PKCECodeChallenge:            request.PKCECodeChallenge,
		PKCECodeChallengeMethod:      request.PKCECodeChallengeMethod,
		PendingProviderName:          request.PendingProviderName,
		PendingProviderAccountID:     request.PendingProviderAccountID,
		PendingProviderEmail:         request.PendingProviderEmail,
		PendingProviderEmailVerified: request.PendingProviderEmailVerified,
		PendingProviderDisplayName:   request.PendingProviderDisplayName,
		PendingProviderAvatarURL:     request.PendingProviderAvatarURL,
		Stage:                        request.Stage,
		ExpiresAt:                    request.ExpiresAt,
		CreatedAt:                    request.CreatedAt,
		UpdatedAt:                    request.UpdatedAt,
	}
	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.AuthorizationRequest{}, err
	}
	return mapAuthorizationRequestModel(model), nil
}

func mapAuthorizationRequestModel(model AuthorizationRequestModel) domain.AuthorizationRequest {
	return domain.AuthorizationRequest{
		ID:                           model.ID,
		ClientID:                     model.ClientID,
		AccountID:                    model.AccountID,
		SSOSessionID:                 model.SSOSessionID,
		RedirectURI:                  model.RedirectURI,
		RequestedScopes:              model.RequestedScopes,
		State:                        model.State,
		Nonce:                        model.Nonce,
		PKCECodeChallenge:            model.PKCECodeChallenge,
		PKCECodeChallengeMethod:      model.PKCECodeChallengeMethod,
		PendingProviderName:          model.PendingProviderName,
		PendingProviderAccountID:     model.PendingProviderAccountID,
		PendingProviderEmail:         model.PendingProviderEmail,
		PendingProviderEmailVerified: model.PendingProviderEmailVerified,
		PendingProviderDisplayName:   model.PendingProviderDisplayName,
		PendingProviderAvatarURL:     model.PendingProviderAvatarURL,
		Stage:                        model.Stage,
		ExpiresAt:                    model.ExpiresAt,
		CreatedAt:                    model.CreatedAt,
		UpdatedAt:                    model.UpdatedAt,
	}
}
