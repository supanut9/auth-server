package persistence

import (
	"context"
	"slices"
	"time"

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

	redirectURIs, err := r.buildRedirectURIModels(client, now)
	if err != nil {
		return domain.OAuthClient{}, err
	}

	model := OAuthClientModel{
		ID:               client.ID,
		PublicClientID:   client.ClientID,
		ClientType:       client.ClientType,
		ClientSecretHash: client.ClientSecretHash,
		DisplayName:      client.DisplayName,
		LogoURI:          client.LogoURI,
		RedirectURIs:     redirectURIs,
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
		Preload("RedirectURIs").
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
		LogoURI:          model.LogoURI,
		RedirectURIs:     mapRedirectURIs(model.RedirectURIs),
		AllowedScopes:    model.AllowedScopes,
		Status:           model.Status,
		CreatedAt:        model.CreatedAt,
		UpdatedAt:        model.UpdatedAt,
	}
}

func (r OAuthClientRepository) buildRedirectURIModels(client domain.OAuthClient, now time.Time) ([]OAuthClientRedirectURIModel, error) {
	redirectURIs := make([]string, 0, len(client.RedirectURIs))
	for _, redirectURI := range client.RedirectURIs {
		if redirectURI == "" || slices.Contains(redirectURIs, redirectURI) {
			continue
		}
		redirectURIs = append(redirectURIs, redirectURI)
	}

	models := make([]OAuthClientRedirectURIModel, 0, len(redirectURIs))
	for _, redirectURI := range redirectURIs {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return nil, err
		}
		models = append(models, OAuthClientRedirectURIModel{
			ID:          id,
			ClientID:    client.ClientID,
			RedirectURI: redirectURI,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}

	return models, nil
}

func mapRedirectURIs(models []OAuthClientRedirectURIModel) []string {
	redirectURIs := make([]string, 0, len(models))
	for _, model := range models {
		redirectURIs = append(redirectURIs, model.RedirectURI)
	}
	return redirectURIs
}
