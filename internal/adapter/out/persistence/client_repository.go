package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type OAuthClientRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewOAuthClientRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) OAuthClientRepository {
	return OAuthClientRepository{
		db:          db,
		idGenerator: idGenerator,
		clock:       clock,
	}
}

func (r OAuthClientRepository) Create(ctx context.Context, client domain.OAuthClient) (domain.OAuthClient, error) {
	now := r.clock.Now().UTC()

	if client.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.OAuthClient{}, err
		}
		client.ID = id
	}

	model := OAuthClientModel{
		ID:               client.ID,
		PublicClientID:   client.ClientID,
		ClientType:       client.ClientType,
		ClientSecretHash: client.ClientSecretHash,
		DisplayName:      client.DisplayName,
		RedirectURIs:     client.RedirectURIs,
		AllowedScopes:    client.AllowedScopes,
		Status:           client.Status,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.OAuthClient{}, err
	}

	return mapOAuthClientModel(model), nil
}

func (r OAuthClientRepository) FindByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error) {
	var model OAuthClientModel
	if err := r.db.WithContext(ctx).
		Where("client_id = ?", clientID).
		First(&model).Error; err != nil {
		return domain.OAuthClient{}, err
	}

	return mapOAuthClientModel(model), nil
}

func mapOAuthClientModel(model OAuthClientModel) domain.OAuthClient {
	return domain.OAuthClient{
		ID:               model.ID,
		ClientID:         model.PublicClientID,
		ClientType:       model.ClientType,
		ClientSecretHash: model.ClientSecretHash,
		DisplayName:      model.DisplayName,
		RedirectURIs:     model.RedirectURIs,
		AllowedScopes:    model.AllowedScopes,
		Status:           model.Status,
		CreatedAt:        model.CreatedAt,
		UpdatedAt:        model.UpdatedAt,
	}
}
