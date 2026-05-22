package flow

import (
	"context"
	"testing"
	"time"

	"github.com/supanut9/auth-server/internal/domain"
)

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type sequentialIDs struct {
	next int
}

func (g *sequentialIDs) NewID() (string, error) {
	g.next++
	return "id-" + time.Unix(int64(g.next), 0).UTC().Format("150405"), nil
}

type memoryAuthorizationCodeRepo struct {
	byID   map[string]domain.AuthorizationCode
	byHash map[string]string
}

func (r *memoryAuthorizationCodeRepo) Create(_ context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	if r.byID == nil {
		r.byID = map[string]domain.AuthorizationCode{}
		r.byHash = map[string]string{}
	}
	r.byID[code.ID] = code
	r.byHash[code.CodeHash] = code.ID
	return code, nil
}

func (r *memoryAuthorizationCodeRepo) FindByCodeHash(_ context.Context, codeHash string) (domain.AuthorizationCode, error) {
	return r.byID[r.byHash[codeHash]], nil
}

func (r *memoryAuthorizationCodeRepo) Update(_ context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	r.byID[code.ID] = code
	r.byHash[code.CodeHash] = code.ID
	return code, nil
}

type memoryConsentGrantRepo struct {
	items map[string]domain.ConsentGrant
}

func (r *memoryConsentGrantRepo) FindByAccountAndClient(_ context.Context, accountID string, clientID string) (domain.ConsentGrant, error) {
	return r.items[accountID+"|"+clientID], nil
}

func (r *memoryConsentGrantRepo) Upsert(_ context.Context, grant domain.ConsentGrant) (domain.ConsentGrant, error) {
	if r.items == nil {
		r.items = map[string]domain.ConsentGrant{}
	}
	r.items[grant.AccountID+"|"+grant.ClientID] = grant
	return grant, nil
}

type memorySSOSessionRepo struct {
	items map[string]domain.SSOSession
}

func (r *memorySSOSessionRepo) Create(_ context.Context, session domain.SSOSession) (domain.SSOSession, error) {
	if r.items == nil {
		r.items = map[string]domain.SSOSession{}
	}
	r.items[session.ID] = session
	return session, nil
}

func (r *memorySSOSessionRepo) FindByID(_ context.Context, id string) (domain.SSOSession, error) {
	return r.items[id], nil
}

func (r *memorySSOSessionRepo) Update(_ context.Context, session domain.SSOSession) (domain.SSOSession, error) {
	r.items[session.ID] = session
	return session, nil
}

func (r *memorySSOSessionRepo) RevokeByID(_ context.Context, id string) error {
	session := r.items[id]
	now := time.Now().UTC()
	session.Status = domain.SSOSessionStatusRevoked
	session.RevokedAt = &now
	r.items[id] = session
	return nil
}

type memoryRefreshChainRepo struct {
	items map[string]domain.RefreshTokenChain
}

func (r *memoryRefreshChainRepo) Create(_ context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	if r.items == nil {
		r.items = map[string]domain.RefreshTokenChain{}
	}
	r.items[chain.ID] = chain
	return chain, nil
}

func (r *memoryRefreshChainRepo) FindByID(_ context.Context, id string) (domain.RefreshTokenChain, error) {
	return r.items[id], nil
}

func (r *memoryRefreshChainRepo) Update(_ context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	r.items[chain.ID] = chain
	return chain, nil
}

func (r *memoryRefreshChainRepo) RevokeByID(_ context.Context, id string) error {
	chain := r.items[id]
	now := time.Now().UTC()
	chain.Status = domain.RefreshTokenChainStatusRevoked
	chain.RevokedAt = &now
	r.items[id] = chain
	return nil
}

type memoryRefreshTokenRepo struct {
	revokedChains []string
}

func (r *memoryRefreshTokenRepo) Create(_ context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	return token, nil
}

func (r *memoryRefreshTokenRepo) FindByTokenHash(_ context.Context, tokenHash string) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, nil
}

func (r *memoryRefreshTokenRepo) Update(_ context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	return token, nil
}

func (r *memoryRefreshTokenRepo) RevokeByChainID(_ context.Context, chainID string) error {
	r.revokedChains = append(r.revokedChains, chainID)
	return nil
}

func TestLogoutGlobalRevokesSessionAndChains(t *testing.T) {
	t.Parallel()

	ssoSessions := &memorySSOSessionRepo{
		items: map[string]domain.SSOSession{
			"sso-1": {ID: "sso-1", Status: domain.SSOSessionStatusActive},
		},
	}
	refreshChains := &memoryRefreshChainRepo{
		items: map[string]domain.RefreshTokenChain{
			"chain-1": {ID: "chain-1", Status: domain.RefreshTokenChainStatusActive},
			"chain-2": {ID: "chain-2", Status: domain.RefreshTokenChainStatusActive},
		},
	}
	refreshTokens := &memoryRefreshTokenRepo{}

	svc := NewService(
		Config{
			AuthorizationCodeTTL: 5 * time.Minute,
			SSOSessionTTL:        24 * time.Hour,
		},
		fixedClock{now: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)},
		&sequentialIDs{},
		&memoryAuthorizationCodeRepo{},
		&memoryConsentGrantRepo{},
		ssoSessions,
		refreshChains,
		refreshTokens,
	)

	if err := svc.LogoutGlobal(context.Background(), "sso-1", []string{"chain-1", "chain-2"}); err != nil {
		t.Fatalf("logout global: %v", err)
	}

	if ssoSessions.items["sso-1"].Status != domain.SSOSessionStatusRevoked {
		t.Fatal("expected sso session revoked")
	}
	if refreshChains.items["chain-1"].Status != domain.RefreshTokenChainStatusRevoked {
		t.Fatal("expected refresh chain 1 revoked")
	}
	if len(refreshTokens.revokedChains) != 2 {
		t.Fatalf("expected refresh token revocations, got %d", len(refreshTokens.revokedChains))
	}
}

func ptr[T any](v T) *T {
	return &v
}
