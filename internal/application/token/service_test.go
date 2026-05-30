package token

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/supanut9/auth-server/internal/adapter/out/jwks"
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

type memoryAccessTokenRepo struct {
	records []domain.AccessTokenRecord
}

func (r *memoryAccessTokenRepo) Create(_ context.Context, record domain.AccessTokenRecord) (domain.AccessTokenRecord, error) {
	r.records = append(r.records, record)
	return record, nil
}

type memoryRefreshTokenChainRepo struct {
	chains map[string]domain.RefreshTokenChain
}

func (r *memoryRefreshTokenChainRepo) Create(_ context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	if r.chains == nil {
		r.chains = map[string]domain.RefreshTokenChain{}
	}
	r.chains[chain.ID] = chain
	return chain, nil
}

func (r *memoryRefreshTokenChainRepo) FindByID(_ context.Context, id string) (domain.RefreshTokenChain, error) {
	return r.chains[id], nil
}

func (r *memoryRefreshTokenChainRepo) Update(_ context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	r.chains[chain.ID] = chain
	return chain, nil
}

func (r *memoryRefreshTokenChainRepo) RevokeByID(_ context.Context, id string) error {
	chain := r.chains[id]
	now := time.Now().UTC()
	chain.Status = domain.RefreshTokenChainStatusRevoked
	chain.RevokedAt = &now
	r.chains[id] = chain
	return nil
}

type memoryRefreshTokenRepo struct {
	byID   map[string]domain.RefreshToken
	byHash map[string]string
}

func (r *memoryRefreshTokenRepo) Create(_ context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	if r.byID == nil {
		r.byID = map[string]domain.RefreshToken{}
		r.byHash = map[string]string{}
	}
	r.byID[token.ID] = token
	r.byHash[token.TokenHash] = token.ID
	return token, nil
}

func (r *memoryRefreshTokenRepo) FindByTokenHash(_ context.Context, tokenHash string) (domain.RefreshToken, error) {
	return r.byID[r.byHash[tokenHash]], nil
}

func (r *memoryRefreshTokenRepo) Update(_ context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	r.byID[token.ID] = token
	r.byHash[token.TokenHash] = token.ID
	return token, nil
}

func (r *memoryRefreshTokenRepo) RevokeByChainID(_ context.Context, chainID string) error {
	now := time.Now().UTC()
	for id, token := range r.byID {
		if token.RefreshTokenChainID == chainID {
			token.RevokedAt = &now
			r.byID[id] = token
		}
	}
	return nil
}

func TestIssueUserTokensAndRotateRefresh(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	idGenerator := &sequentialIDs{}
	accessRepo := &memoryAccessTokenRepo{}
	chainRepo := &memoryRefreshTokenChainRepo{}
	refreshRepo := &memoryRefreshTokenRepo{}

	svc := NewService(
		Config{
			Issuer:                  "http://localhost:8050",
			Audience:                "platform-api",
			AccessTokenTTL:          10 * time.Minute,
			IDTokenTTL:              10 * time.Minute,
			RefreshTokenAbsoluteTTL: 30 * 24 * time.Hour,
			RefreshTokenInactiveTTL: 7 * 24 * time.Hour,
		},
		fixedClock{now: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)},
		idGenerator,
		signer,
		accessRepo,
		chainRepo,
		refreshRepo,
	)

	issued, err := svc.IssueUserTokens(context.Background(), UserTokenRequest{
		AccountID:       "account-123",
		ClientID:        "trading-web",
		Scope:           []string{"openid", "profile", "trading.read"},
		SSOSessionID:    "sso-123",
		DeviceSessionID: "device-123",
		AuthTime:        time.Date(2026, 4, 1, 11, 55, 0, 0, time.UTC),
		Email:           "user@example.com",
		EmailVerified:   true,
		Name:            "Trader",
		Picture:         "https://example.com/avatar.png",
	})
	if err != nil {
		t.Fatalf("issue user tokens: %v", err)
	}

	if issued.AccessToken == "" || issued.IDToken == "" || issued.RefreshToken == "" {
		t.Fatal("expected full token set for user flow")
	}
	if len(accessRepo.records) != 1 {
		t.Fatalf("expected one access token audit record, got %d", len(accessRepo.records))
	}

	refreshed, err := svc.RefreshUserTokens(context.Background(), RefreshTokenRequest{
		ClientID:     "trading-web",
		RefreshToken: issued.RefreshToken,
	})
	if err != nil {
		t.Fatalf("refresh user tokens: %v", err)
	}

	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("expected refreshed token pair")
	}

	_, err = svc.RefreshUserTokens(context.Background(), RefreshTokenRequest{
		ClientID:     "trading-web",
		RefreshToken: issued.RefreshToken,
	})
	if err != ErrRefreshTokenReuseDetected {
		t.Fatalf("expected reuse detection error, got %v", err)
	}
}

func TestRefreshReuseWithinGraceSucceeds(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	idGenerator := &sequentialIDs{}
	accessRepo := &memoryAccessTokenRepo{}
	chainRepo := &memoryRefreshTokenChainRepo{}
	refreshRepo := &memoryRefreshTokenRepo{}

	svc := NewService(
		Config{
			Issuer:                  "http://localhost:8050",
			Audience:                "platform-api",
			AccessTokenTTL:          10 * time.Minute,
			IDTokenTTL:              10 * time.Minute,
			RefreshTokenAbsoluteTTL: 30 * 24 * time.Hour,
			RefreshTokenInactiveTTL: 7 * 24 * time.Hour,
			RefreshReuseGrace:       60 * time.Second,
		},
		fixedClock{now: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)},
		idGenerator,
		signer,
		accessRepo,
		chainRepo,
		refreshRepo,
	)

	issued, err := svc.IssueUserTokens(context.Background(), UserTokenRequest{
		AccountID:    "account-123",
		ClientID:     "trading-web",
		Scope:        []string{"openid", "profile"},
		SSOSessionID: "sso-123",
		AuthTime:     time.Date(2026, 4, 1, 11, 55, 0, 0, time.UTC),
		Email:        "user@example.com",
	})
	if err != nil {
		t.Fatalf("issue user tokens: %v", err)
	}

	// First refresh rotates the token.
	first, err := svc.RefreshUserTokens(context.Background(), RefreshTokenRequest{
		ClientID:     "trading-web",
		RefreshToken: issued.RefreshToken,
	})
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// A concurrent retry re-presents the same (just-rotated) token within the
	// grace window: it must succeed with a fresh token pair, not revoke.
	second, err := svc.RefreshUserTokens(context.Background(), RefreshTokenRequest{
		ClientID:     "trading-web",
		RefreshToken: issued.RefreshToken,
	})
	if err != nil {
		t.Fatalf("expected grace-window refresh to succeed, got %v", err)
	}
	if second.AccessToken == "" || second.RefreshToken == "" {
		t.Fatal("expected fresh token pair from grace-window refresh")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("expected a distinct refresh token from the grace-window refresh")
	}

	// The chain must still be usable afterwards (not revoked): the latest
	// rotated token refreshes cleanly.
	if _, err := svc.RefreshUserTokens(context.Background(), RefreshTokenRequest{
		ClientID:     "trading-web",
		RefreshToken: second.RefreshToken,
	}); err != nil {
		t.Fatalf("expected chain to remain active after grace refresh, got %v", err)
	}
}

func TestIssueClientCredentialsToken(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	idGenerator := &sequentialIDs{}
	accessRepo := &memoryAccessTokenRepo{}

	svc := NewService(
		Config{
			Issuer:                  "http://localhost:8050",
			Audience:                "platform-api",
			AccessTokenTTL:          10 * time.Minute,
			IDTokenTTL:              10 * time.Minute,
			RefreshTokenAbsoluteTTL: 30 * 24 * time.Hour,
			RefreshTokenInactiveTTL: 7 * 24 * time.Hour,
		},
		fixedClock{now: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)},
		idGenerator,
		signer,
		accessRepo,
		&memoryRefreshTokenChainRepo{},
		&memoryRefreshTokenRepo{},
	)

	issued, err := svc.IssueClientCredentialsToken(context.Background(), ClientCredentialsTokenRequest{
		ClientID: "market-data-worker",
		Scope:    []string{"trading.read"},
	})
	if err != nil {
		t.Fatalf("issue client credentials token: %v", err)
	}

	if issued.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if issued.IDToken != "" || issued.RefreshToken != "" {
		t.Fatal("did not expect id token or refresh token")
	}
}

func newTestSigner(t *testing.T) jwks.Manager {
	t.Helper()

	privateKey, publicKey, err := jwks.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	dir := t.TempDir()
	privatePath := filepath.Join(dir, "jwt-private.pem")
	publicPath := filepath.Join(dir, "jwt-public.pem")

	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	}), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	manager, err := jwks.NewManager("RS256", privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	return manager
}
