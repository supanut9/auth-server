package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type SSOSessionRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewSSOSessionRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) SSOSessionRepository {
	return SSOSessionRepository{db: db, idGenerator: idGenerator, clock: clock}
}

func (r SSOSessionRepository) Create(ctx context.Context, session domain.SSOSession) (domain.SSOSession, error) {
	now := r.clock.Now().UTC()
	if session.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.SSOSession{}, err
		}
		session.ID = id
	}
	if session.Status == "" {
		session.Status = domain.SSOSessionStatusActive
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = now
	}

	model := SSOSessionModel{
		ID:              session.ID,
		AccountID:       session.AccountID,
		Status:          session.Status,
		LoginMethod:     session.LoginMethod,
		AuthenticatedAt: session.AuthenticatedAt,
		LastSeenAt:      session.LastSeenAt,
		ExpiresAt:       session.ExpiresAt,
		RevokedAt:       session.RevokedAt,
		CreatedAt:       session.CreatedAt,
		UpdatedAt:       session.UpdatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.SSOSession{}, err
	}
	return mapSSOSessionModel(model), nil
}

func (r SSOSessionRepository) FindByID(ctx context.Context, id string) (domain.SSOSession, error) {
	var model SSOSessionModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&model).Error; err != nil {
		return domain.SSOSession{}, err
	}
	return mapSSOSessionModel(model), nil
}

func (r SSOSessionRepository) Update(ctx context.Context, session domain.SSOSession) (domain.SSOSession, error) {
	session.UpdatedAt = r.clock.Now().UTC()
	model := SSOSessionModel{
		ID:              session.ID,
		AccountID:       session.AccountID,
		Status:          session.Status,
		LoginMethod:     session.LoginMethod,
		AuthenticatedAt: session.AuthenticatedAt,
		LastSeenAt:      session.LastSeenAt,
		ExpiresAt:       session.ExpiresAt,
		RevokedAt:       session.RevokedAt,
		CreatedAt:       session.CreatedAt,
		UpdatedAt:       session.UpdatedAt,
	}
	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.SSOSession{}, err
	}
	return mapSSOSessionModel(model), nil
}

func (r SSOSessionRepository) RevokeByID(ctx context.Context, id string) error {
	now := r.clock.Now().UTC()
	return r.db.WithContext(ctx).
		Model(&SSOSessionModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":     domain.SSOSessionStatusRevoked,
			"revoked_at": now,
			"updated_at": now,
		}).Error
}

func mapSSOSessionModel(model SSOSessionModel) domain.SSOSession {
	return domain.SSOSession{
		ID:              model.ID,
		AccountID:       model.AccountID,
		Status:          model.Status,
		LoginMethod:     model.LoginMethod,
		AuthenticatedAt: model.AuthenticatedAt,
		LastSeenAt:      model.LastSeenAt,
		ExpiresAt:       model.ExpiresAt,
		RevokedAt:       model.RevokedAt,
		CreatedAt:       model.CreatedAt,
		UpdatedAt:       model.UpdatedAt,
	}
}
