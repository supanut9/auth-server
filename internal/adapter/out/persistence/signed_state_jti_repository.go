package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/supanut9/auth-server/internal/application/oauth"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SignedStateJTIRepository persists consumed envelope JTIs (one row per signed
// state we've ever verified). The primary key is the JTI itself, so Insert
// naturally surfaces replays as a unique-constraint violation, which we translate
// to oauth.ErrJTIExists for the application layer.
type SignedStateJTIRepository struct {
	db    *gorm.DB
	clock interface{ Now() time.Time }
}

// NewSignedStateJTIRepository constructs the repo.
func NewSignedStateJTIRepository(db *gorm.DB, clock interface{ Now() time.Time }) SignedStateJTIRepository {
	return SignedStateJTIRepository{db: db, clock: clock}
}

// Insert records a JTI. Returns oauth.ErrJTIExists if the JTI is already known.
func (r SignedStateJTIRepository) Insert(ctx context.Context, jti string, expiresAt time.Time) error {
	if jti == "" {
		return errors.New("signed_state_jti: jti is required")
	}
	now := r.clock.Now().UTC()
	model := SignedStateJTIModel{
		JTI:       jti,
		ExpiresAt: expiresAt.UTC(),
		CreatedAt: now,
	}
	// ON CONFLICT DO NOTHING — RowsAffected==0 means the JTI already existed.
	tx := r.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&model)
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		return oauth.ErrJTIExists
	}
	return nil
}

// PruneExpired deletes rows whose expires_at is in the past. Safe to call
// idempotently; intended for a periodic background job.
func (r SignedStateJTIRepository) PruneExpired(ctx context.Context, now time.Time) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", now.UTC()).
		Delete(&SignedStateJTIModel{}).Error
}

// JTIStoreAdapter adapts the context-free oauth.JTIStore interface (used inside
// the EnvelopeSigner) to the persistence-layer SignedStateJTIRepository.
// EnvelopeSigner can't take a context because callbacks expose a verify
// boundary, not a request context — we use Background for now. If we need
// cancellation, swap to a ctx-aware Signer.Verify.
type JTIStoreAdapter struct {
	Repo SignedStateJTIRepository
}

// Insert satisfies oauth.JTIStore.
func (a JTIStoreAdapter) Insert(jti string, expiresAt time.Time) error {
	return a.Repo.Insert(context.Background(), jti, expiresAt)
}
