package persistence

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

type OTPChallengeRepository struct {
	db          *gorm.DB
	idGenerator port.IDGenerator
	clock       port.Clock
}

func NewOTPChallengeRepository(db *gorm.DB, idGenerator port.IDGenerator, clock port.Clock) OTPChallengeRepository {
	return OTPChallengeRepository{db: db, idGenerator: idGenerator, clock: clock}
}

func (r OTPChallengeRepository) Create(ctx context.Context, challenge domain.OTPChallenge) (domain.OTPChallenge, error) {
	now := r.clock.Now().UTC()
	if challenge.ID == "" {
		id, err := r.idGenerator.NewID()
		if err != nil {
			return domain.OTPChallenge{}, err
		}
		challenge.ID = id
	}
	if challenge.CreatedAt.IsZero() {
		challenge.CreatedAt = now
	}
	if challenge.LastSentAt.IsZero() {
		challenge.LastSentAt = now
	}

	model := OTPChallengeModel{
		ID:                     challenge.ID,
		AuthorizationRequestID: challenge.AuthorizationRequestID,
		Email:                  challenge.Email,
		Purpose:                challenge.Purpose,
		CodeHash:               challenge.CodeHash,
		AttemptCount:           challenge.AttemptCount,
		ResendCount:            challenge.ResendCount,
		ExpiresAt:              challenge.ExpiresAt,
		VerifiedAt:             challenge.VerifiedAt,
		LastSentAt:             challenge.LastSentAt,
		CreatedAt:              challenge.CreatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return domain.OTPChallenge{}, err
	}
	return mapOTPChallengeModel(model), nil
}

func (r OTPChallengeRepository) FindActiveByRequestAndEmail(ctx context.Context, requestID string, email string) (domain.OTPChallenge, error) {
	var model OTPChallengeModel
	err := r.db.WithContext(ctx).
		Where("authorization_request_id = ? AND email = ? AND verified_at IS NULL", requestID, email).
		Order("created_at DESC").
		First(&model).Error
	if err != nil {
		return domain.OTPChallenge{}, err
	}
	return mapOTPChallengeModel(model), nil
}

func (r OTPChallengeRepository) Update(ctx context.Context, challenge domain.OTPChallenge) (domain.OTPChallenge, error) {
	model := OTPChallengeModel{
		ID:                     challenge.ID,
		AuthorizationRequestID: challenge.AuthorizationRequestID,
		Email:                  challenge.Email,
		Purpose:                challenge.Purpose,
		CodeHash:               challenge.CodeHash,
		AttemptCount:           challenge.AttemptCount,
		ResendCount:            challenge.ResendCount,
		ExpiresAt:              challenge.ExpiresAt,
		VerifiedAt:             challenge.VerifiedAt,
		LastSentAt:             challenge.LastSentAt,
		CreatedAt:              challenge.CreatedAt,
	}
	if err := r.db.WithContext(ctx).Save(&model).Error; err != nil {
		return domain.OTPChallenge{}, err
	}
	return mapOTPChallengeModel(model), nil
}

func (r OTPChallengeRepository) FindLatestByRequestAndEmail(ctx context.Context, requestID string, email string) (domain.OTPChallenge, error) {
	return r.FindActiveByRequestAndEmail(ctx, requestID, email)
}

func (r OTPChallengeRepository) FindByID(ctx context.Context, id string) (domain.OTPChallenge, error) {
	var model OTPChallengeModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&model).Error; err != nil {
		return domain.OTPChallenge{}, err
	}
	return mapOTPChallengeModel(model), nil
}

// FindLatestActiveByEmail returns the most recent unverified, unexpired challenge
// for the given email address. Used only by the non-production test-hint endpoint.
func (r OTPChallengeRepository) FindLatestActiveByEmail(ctx context.Context, email string) (domain.OTPChallenge, error) {
	var model OTPChallengeModel
	now := r.clock.Now().UTC()
	err := r.db.WithContext(ctx).
		Where("email = ? AND verified_at IS NULL AND expires_at > ?", email, now).
		Order("created_at DESC").
		First(&model).Error
	if err != nil {
		return domain.OTPChallenge{}, err
	}
	return mapOTPChallengeModel(model), nil
}

func (r OTPChallengeRepository) RevokeByRequestID(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).
		Model(&OTPChallengeModel{}).
		Where("authorization_request_id = ?", requestID).
		Updates(map[string]any{
			"verified_at": r.clock.Now().UTC(),
		}).Error
}

func mapOTPChallengeModel(model OTPChallengeModel) domain.OTPChallenge {
	return domain.OTPChallenge{
		ID:                     model.ID,
		AuthorizationRequestID: model.AuthorizationRequestID,
		Email:                  model.Email,
		Purpose:                model.Purpose,
		CodeHash:               model.CodeHash,
		AttemptCount:           model.AttemptCount,
		ResendCount:            model.ResendCount,
		ExpiresAt:              model.ExpiresAt,
		VerifiedAt:             model.VerifiedAt,
		LastSentAt:             model.LastSentAt,
		CreatedAt:              model.CreatedAt,
	}
}
