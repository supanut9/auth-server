package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

type Service struct {
	clock                   port.Clock
	idGenerator             port.IDGenerator
	signer                  port.JWTSigner
	accessTokenRepository   port.AccessTokenRepository
	refreshTokenChains      port.RefreshTokenChainRepository
	refreshTokens           port.RefreshTokenRepository
	issuer                  string
	audience                string
	accessTokenTTL          time.Duration
	idTokenTTL              time.Duration
	refreshTokenAbsoluteTTL time.Duration
	refreshTokenInactiveTTL time.Duration
	refreshReuseGrace       time.Duration
}

type Config struct {
	Issuer                  string
	Audience                string
	AccessTokenTTL          time.Duration
	IDTokenTTL              time.Duration
	RefreshTokenAbsoluteTTL time.Duration
	RefreshTokenInactiveTTL time.Duration
	RefreshReuseGrace       time.Duration
}

type UserTokenRequest struct {
	AccountID       string
	ClientID        string
	Scope           []string
	SSOSessionID    string
	DeviceSessionID string
	AuthTime        time.Time
	Email           string
	EmailVerified   bool
	Name            string
	Picture         string
}

type ClientCredentialsTokenRequest struct {
	ClientID string
	Scope    []string
}

type RefreshTokenRequest struct {
	ClientID     string
	RefreshToken string
}

type IssuedTokens struct {
	AccessToken           string
	IDToken               string
	RefreshToken          string
	TokenType             string
	ExpiresIn             int64
	Scope                 string
	AccessTokenExpiresAt  time.Time
	IDTokenExpiresAt      time.Time
	RefreshTokenExpiresAt time.Time
}

func NewService(
	cfg Config,
	clock port.Clock,
	idGenerator port.IDGenerator,
	signer port.JWTSigner,
	accessTokenRepository port.AccessTokenRepository,
	refreshTokenChains port.RefreshTokenChainRepository,
	refreshTokens port.RefreshTokenRepository,
) Service {
	return Service{
		clock:                   clock,
		idGenerator:             idGenerator,
		signer:                  signer,
		accessTokenRepository:   accessTokenRepository,
		refreshTokenChains:      refreshTokenChains,
		refreshTokens:           refreshTokens,
		issuer:                  cfg.Issuer,
		audience:                cfg.Audience,
		accessTokenTTL:          cfg.AccessTokenTTL,
		idTokenTTL:              cfg.IDTokenTTL,
		refreshTokenAbsoluteTTL: cfg.RefreshTokenAbsoluteTTL,
		refreshTokenInactiveTTL: cfg.RefreshTokenInactiveTTL,
		refreshReuseGrace:       cfg.RefreshReuseGrace,
	}
}

func (s Service) IssueUserTokens(ctx context.Context, req UserTokenRequest) (IssuedTokens, error) {
	now := s.clock.Now().UTC()
	scope := normalizeScopes(req.Scope)
	accessJTI, err := s.idGenerator.NewID()
	if err != nil {
		return IssuedTokens{}, err
	}

	accessExp := now.Add(s.accessTokenTTL)
	accessClaims := map[string]any{
		"iss":       s.issuer,
		"sub":       req.AccountID,
		"aud":       s.audience,
		"exp":       accessExp.Unix(),
		"iat":       now.Unix(),
		"scope":     strings.Join(scope, " "),
		"client_id": req.ClientID,
		"jti":       accessJTI,
		"sid":       req.SSOSessionID,
	}

	accessToken, err := s.signer.Sign(accessClaims)
	if err != nil {
		return IssuedTokens{}, err
	}

	idExp := now.Add(s.idTokenTTL)
	idClaims := map[string]any{
		"iss":            s.issuer,
		"sub":            req.AccountID,
		"aud":            req.ClientID,
		"exp":            idExp.Unix(),
		"iat":            now.Unix(),
		"auth_time":      req.AuthTime.UTC().Unix(),
		"email":          req.Email,
		"email_verified": req.EmailVerified,
		"name":           req.Name,
		"picture":        req.Picture,
	}

	idToken, err := s.signer.Sign(idClaims)
	if err != nil {
		return IssuedTokens{}, err
	}

	chainID, err := s.idGenerator.NewID()
	if err != nil {
		return IssuedTokens{}, err
	}

	refreshValue, refreshHash, err := newOpaqueToken()
	if err != nil {
		return IssuedTokens{}, err
	}

	refreshExp := now.Add(s.refreshTokenAbsoluteTTL)
	chain := domain.RefreshTokenChain{
		ID:                chainID,
		AccountID:         req.AccountID,
		ClientID:          req.ClientID,
		SSOSessionID:      req.SSOSessionID,
		Scope:             strings.Join(scope, " "),
		DeviceSessionID:   req.DeviceSessionID,
		Status:            domain.RefreshTokenChainStatusActive,
		AbsoluteExpiresAt: refreshExp,
		InactiveExpiresAt: now.Add(s.refreshTokenInactiveTTL),
		LastUsedAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if _, err := s.refreshTokenChains.Create(ctx, chain); err != nil {
		return IssuedTokens{}, err
	}

	refreshToken := domain.RefreshToken{
		RefreshTokenChainID: chainID,
		TokenHash:           refreshHash,
		IssuedAt:            now,
		ExpiresAt:           refreshExp,
	}
	if _, err := s.refreshTokens.Create(ctx, refreshToken); err != nil {
		return IssuedTokens{}, err
	}

	accountID := req.AccountID
	ssoSessionID := req.SSOSessionID
	if _, err := s.accessTokenRepository.Create(ctx, domain.AccessTokenRecord{
		JTI:          accessJTI,
		SID:          req.SSOSessionID,
		AccountID:    &accountID,
		ClientID:     req.ClientID,
		SSOSessionID: &ssoSessionID,
		Audience:     s.audience,
		Scope:        strings.Join(scope, " "),
		IssuedAt:     now,
		ExpiresAt:    accessExp,
		Status:       domain.AccessTokenStatusActive,
		CreatedAt:    now,
	}); err != nil {
		return IssuedTokens{}, err
	}

	return IssuedTokens{
		AccessToken:           accessToken.Token,
		IDToken:               idToken.Token,
		RefreshToken:          refreshValue,
		TokenType:             "Bearer",
		ExpiresIn:             int64(s.accessTokenTTL.Seconds()),
		Scope:                 strings.Join(scope, " "),
		AccessTokenExpiresAt:  accessExp,
		IDTokenExpiresAt:      idExp,
		RefreshTokenExpiresAt: refreshExp,
	}, nil
}

func (s Service) IssueClientCredentialsToken(ctx context.Context, req ClientCredentialsTokenRequest) (IssuedTokens, error) {
	now := s.clock.Now().UTC()
	scope := normalizeScopes(req.Scope)
	accessJTI, err := s.idGenerator.NewID()
	if err != nil {
		return IssuedTokens{}, err
	}

	accessExp := now.Add(s.accessTokenTTL)
	claims := map[string]any{
		"iss":       s.issuer,
		"sub":       req.ClientID,
		"aud":       s.audience,
		"exp":       accessExp.Unix(),
		"iat":       now.Unix(),
		"scope":     strings.Join(scope, " "),
		"client_id": req.ClientID,
		"jti":       accessJTI,
	}

	accessToken, err := s.signer.Sign(claims)
	if err != nil {
		return IssuedTokens{}, err
	}

	if _, err := s.accessTokenRepository.Create(ctx, domain.AccessTokenRecord{
		JTI:       accessJTI,
		SID:       "",
		ClientID:  req.ClientID,
		Audience:  s.audience,
		Scope:     strings.Join(scope, " "),
		IssuedAt:  now,
		ExpiresAt: accessExp,
		Status:    domain.AccessTokenStatusActive,
		CreatedAt: now,
	}); err != nil {
		return IssuedTokens{}, err
	}

	return IssuedTokens{
		AccessToken:          accessToken.Token,
		TokenType:            "Bearer",
		ExpiresIn:            int64(s.accessTokenTTL.Seconds()),
		Scope:                strings.Join(scope, " "),
		AccessTokenExpiresAt: accessExp,
	}, nil
}

func (s Service) RefreshUserTokens(ctx context.Context, req RefreshTokenRequest) (IssuedTokens, error) {
	now := s.clock.Now().UTC()
	_, refreshHash, err := hashOpaqueToken(req.RefreshToken)
	if err != nil {
		return IssuedTokens{}, err
	}

	current, err := s.refreshTokens.FindByTokenHash(ctx, refreshHash)
	if err != nil {
		return IssuedTokens{}, err
	}

	if current.RevokedAt != nil {
		return IssuedTokens{}, ErrRefreshTokenRevoked
	}
	alreadyUsed := current.UsedAt != nil
	if alreadyUsed {
		// A just-rotated token presented again within the grace window is a
		// benign concurrent refresh (common from serverless clients firing
		// parallel requests), not theft: mint a fresh set of tokens without
		// revoking the chain. Reuse outside the grace window is still treated
		// as theft and revokes the whole chain.
		if s.refreshReuseGrace <= 0 || now.Sub(*current.UsedAt) > s.refreshReuseGrace {
			_ = s.refreshTokens.RevokeByChainID(ctx, current.RefreshTokenChainID)
			_ = s.refreshTokenChains.RevokeByID(ctx, current.RefreshTokenChainID)
			return IssuedTokens{}, ErrRefreshTokenReuseDetected
		}
	}
	if now.After(current.ExpiresAt) {
		return IssuedTokens{}, ErrRefreshTokenExpired
	}

	chain, err := s.refreshTokenChains.FindByID(ctx, current.RefreshTokenChainID)
	if err != nil {
		return IssuedTokens{}, err
	}
	if chain.ClientID != req.ClientID {
		return IssuedTokens{}, ErrRefreshTokenClientMismatch
	}
	if chain.Status != domain.RefreshTokenChainStatusActive || chain.RevokedAt != nil {
		return IssuedTokens{}, ErrRefreshTokenChainInactive
	}
	if now.After(chain.AbsoluteExpiresAt) || now.After(chain.InactiveExpiresAt) {
		return IssuedTokens{}, ErrRefreshTokenExpired
	}

	scope := splitScopes(chain.Scope)
	accessJTI, err := s.idGenerator.NewID()
	if err != nil {
		return IssuedTokens{}, err
	}
	accessExp := now.Add(s.accessTokenTTL)
	claims := map[string]any{
		"iss":       s.issuer,
		"sub":       chain.AccountID,
		"aud":       s.audience,
		"exp":       accessExp.Unix(),
		"iat":       now.Unix(),
		"scope":     strings.Join(scope, " "),
		"client_id": chain.ClientID,
		"jti":       accessJTI,
		"sid":       chain.SSOSessionID,
	}
	accessToken, err := s.signer.Sign(claims)
	if err != nil {
		return IssuedTokens{}, err
	}

	nextRefreshValue, nextRefreshHash, err := newOpaqueToken()
	if err != nil {
		return IssuedTokens{}, err
	}

	replacement, err := s.refreshTokens.Create(ctx, domain.RefreshToken{
		RefreshTokenChainID: chain.ID,
		TokenHash:           nextRefreshHash,
		IssuedAt:            now,
		ExpiresAt:           chain.AbsoluteExpiresAt,
	})
	if err != nil {
		return IssuedTokens{}, err
	}

	// Only mark the presented token as used on its first rotation. Within the
	// grace window it is already used (pointing at the first replacement); leave
	// that record intact so reuse-detection outside the window still works.
	if !alreadyUsed {
		current.UsedAt = &now
		current.ReplacedByTokenID = &replacement.ID
		if _, err := s.refreshTokens.Update(ctx, current); err != nil {
			return IssuedTokens{}, err
		}
	}

	chain.LastUsedAt = now
	chain.InactiveExpiresAt = now.Add(s.refreshTokenInactiveTTL)
	if _, err := s.refreshTokenChains.Update(ctx, chain); err != nil {
		return IssuedTokens{}, err
	}

	accountID := chain.AccountID
	ssoSessionID := chain.SSOSessionID
	if _, err := s.accessTokenRepository.Create(ctx, domain.AccessTokenRecord{
		JTI:          accessJTI,
		SID:          chain.SSOSessionID,
		AccountID:    &accountID,
		ClientID:     chain.ClientID,
		SSOSessionID: &ssoSessionID,
		Audience:     s.audience,
		Scope:        "",
		IssuedAt:     now,
		ExpiresAt:    accessExp,
		Status:       domain.AccessTokenStatusActive,
		CreatedAt:    now,
	}); err != nil {
		return IssuedTokens{}, err
	}

	return IssuedTokens{
		AccessToken:           accessToken.Token,
		RefreshToken:          nextRefreshValue,
		TokenType:             "Bearer",
		ExpiresIn:             int64(s.accessTokenTTL.Seconds()),
		Scope:                 strings.Join(scope, " "),
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: chain.AbsoluteExpiresAt,
	}, nil
}

func normalizeScopes(scopes []string) []string {
	set := map[string]struct{}{}
	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}

	normalized := make([]string, 0, len(set))
	for scope := range set {
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return normalized
}

func splitScopes(raw string) []string {
	if raw == "" {
		return nil
	}

	return normalizeScopes(strings.Fields(raw))
}

func newOpaqueToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate opaque token: %w", err)
	}

	value := base64.RawURLEncoding.EncodeToString(raw)
	_, hash, err := hashOpaqueToken(value)
	if err != nil {
		return "", "", err
	}

	return value, hash, nil
}

func hashOpaqueToken(value string) (string, string, error) {
	if value == "" {
		return "", "", fmt.Errorf("hash opaque token: empty token")
	}

	sum := sha256.Sum256([]byte(value))
	return value, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
