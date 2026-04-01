package flow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

type Config struct {
	AuthorizationRequestTTL time.Duration
	AuthorizationCodeTTL    time.Duration
	SSOSessionTTL           time.Duration
}

type Service struct {
	clock                   port.Clock
	idGenerator             port.IDGenerator
	authorizationRequests   port.AuthorizationRequestRepository
	authorizationCodes      port.AuthorizationCodeRepository
	consentGrants           port.ConsentGrantRepository
	ssoSessions             port.SSOSessionRepository
	refreshTokenChains      port.RefreshTokenChainRepository
	refreshTokens           port.RefreshTokenRepository
	authorizationRequestTTL time.Duration
	authorizationCodeTTL    time.Duration
	ssoSessionTTL           time.Duration
}

type StartAuthorizationRequest struct {
	ClientID                string
	RedirectURI             string
	RequestedScopes         []string
	State                   string
	Nonce                   *string
	PKCECodeChallenge       string
	PKCECodeChallengeMethod string
	AccountID               *string
	SSOSessionID            *string
}

type AttachSessionRequest struct {
	RequestID    string
	AccountID    string
	SSOSessionID string
}

type IssueAuthorizationCodeRequest struct {
	RequestID string
	AuthTime  time.Time
}

type ConsumeAuthorizationCodeRequest struct {
	Code        string
	ClientID    string
	RedirectURI string
}

func NewService(
	cfg Config,
	clock port.Clock,
	idGenerator port.IDGenerator,
	authorizationRequests port.AuthorizationRequestRepository,
	authorizationCodes port.AuthorizationCodeRepository,
	consentGrants port.ConsentGrantRepository,
	ssoSessions port.SSOSessionRepository,
	refreshTokenChains port.RefreshTokenChainRepository,
	refreshTokens port.RefreshTokenRepository,
) Service {
	return Service{
		clock:                   clock,
		idGenerator:             idGenerator,
		authorizationRequests:   authorizationRequests,
		authorizationCodes:      authorizationCodes,
		consentGrants:           consentGrants,
		ssoSessions:             ssoSessions,
		refreshTokenChains:      refreshTokenChains,
		refreshTokens:           refreshTokens,
		authorizationRequestTTL: cfg.AuthorizationRequestTTL,
		authorizationCodeTTL:    cfg.AuthorizationCodeTTL,
		ssoSessionTTL:           cfg.SSOSessionTTL,
	}
}

func (s Service) StartAuthorization(ctx context.Context, req StartAuthorizationRequest) (domain.AuthorizationRequest, error) {
	now := s.clock.Now().UTC()
	scopes := normalizeScopes(req.RequestedScopes)

	request := domain.AuthorizationRequest{
		ClientID:                req.ClientID,
		AccountID:               req.AccountID,
		SSOSessionID:            req.SSOSessionID,
		RedirectURI:             req.RedirectURI,
		RequestedScopes:         strings.Join(scopes, " "),
		State:                   req.State,
		Nonce:                   req.Nonce,
		PKCECodeChallenge:       req.PKCECodeChallenge,
		PKCECodeChallengeMethod: req.PKCECodeChallengeMethod,
		Stage:                   domain.AuthorizationStageLoginRequired,
		ExpiresAt:               now.Add(s.authorizationRequestTTL),
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	if req.AccountID != nil && req.SSOSessionID != nil {
		grant, err := s.consentGrants.FindByAccountAndClient(ctx, *req.AccountID, req.ClientID)
		if err == nil && scopeSubset(scopes, splitScopes(grant.GrantedScopes)) {
			request.Stage = domain.AuthorizationStageAuthorizationReady
		} else {
			request.Stage = domain.AuthorizationStageConsentRequired
		}
	}

	return s.authorizationRequests.Create(ctx, request)
}

func (s Service) MarkProviderRedirect(ctx context.Context, requestID string) (domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, requestID)
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}
	request.Stage = domain.AuthorizationStageProviderRedirect
	return s.authorizationRequests.Update(ctx, request)
}

func (s Service) RequireOTP(ctx context.Context, requestID string) (domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, requestID)
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}
	request.Stage = domain.AuthorizationStageOTPRequired
	return s.authorizationRequests.Update(ctx, request)
}

func (s Service) AttachAuthenticatedSession(ctx context.Context, req AttachSessionRequest) (domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, req.RequestID)
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}
	if s.clock.Now().UTC().After(request.ExpiresAt) {
		request.Stage = domain.AuthorizationStageExpired
		_, _ = s.authorizationRequests.Update(ctx, request)
		return domain.AuthorizationRequest{}, ErrAuthorizationRequestExpired
	}

	request.AccountID = &req.AccountID
	request.SSOSessionID = &req.SSOSessionID

	grant, err := s.consentGrants.FindByAccountAndClient(ctx, req.AccountID, request.ClientID)
	if err == nil && scopeSubset(splitScopes(request.RequestedScopes), splitScopes(grant.GrantedScopes)) {
		request.Stage = domain.AuthorizationStageAuthorizationReady
	} else {
		request.Stage = domain.AuthorizationStageConsentRequired
	}

	return s.authorizationRequests.Update(ctx, request)
}

func (s Service) AcceptConsent(ctx context.Context, requestID string) (domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, requestID)
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}
	if request.AccountID == nil {
		return domain.AuthorizationRequest{}, ErrAuthorizationRequestInvalidStage
	}
	if request.Stage != domain.AuthorizationStageConsentRequired {
		return domain.AuthorizationRequest{}, ErrAuthorizationRequestInvalidStage
	}

	now := s.clock.Now().UTC()
	existing, err := s.consentGrants.FindByAccountAndClient(ctx, *request.AccountID, request.ClientID)
	grantScopes := splitScopes(request.RequestedScopes)
	if err == nil {
		grantScopes = unionScopes(grantScopes, splitScopes(existing.GrantedScopes))
	}

	_, err = s.consentGrants.Upsert(ctx, domain.ConsentGrant{
		ID:            existing.ID,
		AccountID:     *request.AccountID,
		ClientID:      request.ClientID,
		GrantedScopes: strings.Join(grantScopes, " "),
		GrantedAt:     existing.GrantedAt,
		LastUsedAt:    now,
	})
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}

	request.Stage = domain.AuthorizationStageAuthorizationReady
	return s.authorizationRequests.Update(ctx, request)
}

func (s Service) RejectConsent(ctx context.Context, requestID string) (domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, requestID)
	if err != nil {
		return domain.AuthorizationRequest{}, err
	}
	request.Stage = domain.AuthorizationStageFailed
	return s.authorizationRequests.Update(ctx, request)
}

func (s Service) IssueAuthorizationCode(ctx context.Context, req IssueAuthorizationCodeRequest) (string, domain.AuthorizationCode, error) {
	request, err := s.authorizationRequests.FindByID(ctx, req.RequestID)
	if err != nil {
		return "", domain.AuthorizationCode{}, err
	}
	if request.Stage != domain.AuthorizationStageAuthorizationReady || request.AccountID == nil {
		return "", domain.AuthorizationCode{}, ErrAuthorizationRequestInvalidStage
	}
	if s.clock.Now().UTC().After(request.ExpiresAt) {
		request.Stage = domain.AuthorizationStageExpired
		_, _ = s.authorizationRequests.Update(ctx, request)
		return "", domain.AuthorizationCode{}, ErrAuthorizationRequestExpired
	}

	value, hash, err := newOpaqueSecret()
	if err != nil {
		return "", domain.AuthorizationCode{}, err
	}
	now := s.clock.Now().UTC()
	code := domain.AuthorizationCode{
		CodeHash:                hash,
		AuthorizationRequestID:  request.ID,
		AccountID:               *request.AccountID,
		ClientID:                request.ClientID,
		SSOSessionID:            request.SSOSessionID,
		RedirectURI:             request.RedirectURI,
		GrantedScopes:           request.RequestedScopes,
		PKCECodeChallenge:       request.PKCECodeChallenge,
		PKCECodeChallengeMethod: request.PKCECodeChallengeMethod,
		AuthTime:                req.AuthTime.UTC(),
		ExpiresAt:               now.Add(s.authorizationCodeTTL),
		CreatedAt:               now,
	}
	code, err = s.authorizationCodes.Create(ctx, code)
	if err != nil {
		return "", domain.AuthorizationCode{}, err
	}

	request.Stage = domain.AuthorizationStageCompleted
	if _, err := s.authorizationRequests.Update(ctx, request); err != nil {
		return "", domain.AuthorizationCode{}, err
	}

	return value, code, nil
}

func (s Service) ConsumeAuthorizationCode(ctx context.Context, req ConsumeAuthorizationCodeRequest) (domain.AuthorizationCode, error) {
	_, hash, err := hashSecret(req.Code)
	if err != nil {
		return domain.AuthorizationCode{}, err
	}
	code, err := s.authorizationCodes.FindByCodeHash(ctx, hash)
	if err != nil {
		return domain.AuthorizationCode{}, err
	}

	now := s.clock.Now().UTC()
	if code.ClientID != req.ClientID {
		return domain.AuthorizationCode{}, ErrAuthorizationCodeClientMismatch
	}
	if code.RedirectURI != req.RedirectURI {
		return domain.AuthorizationCode{}, ErrAuthorizationCodeRedirectMismatch
	}
	if code.ConsumedAt != nil {
		return domain.AuthorizationCode{}, ErrAuthorizationCodeAlreadyConsumed
	}
	if now.After(code.ExpiresAt) {
		return domain.AuthorizationCode{}, ErrAuthorizationCodeExpired
	}

	code.ConsumedAt = &now
	return s.authorizationCodes.Update(ctx, code)
}

func (s Service) StartSSOSession(ctx context.Context, accountID string, loginMethod string) (domain.SSOSession, error) {
	now := s.clock.Now().UTC()
	return s.ssoSessions.Create(ctx, domain.SSOSession{
		AccountID:       accountID,
		Status:          domain.SSOSessionStatusActive,
		LoginMethod:     loginMethod,
		AuthenticatedAt: now,
		LastSeenAt:      now,
		ExpiresAt:       now.Add(s.ssoSessionTTL),
		CreatedAt:       now,
		UpdatedAt:       now,
	})
}

func (s Service) LogoutLocal(ctx context.Context, refreshTokenChainID string) error {
	if refreshTokenChainID == "" {
		return nil
	}
	if err := s.refreshTokens.RevokeByChainID(ctx, refreshTokenChainID); err != nil {
		return err
	}
	return s.refreshTokenChains.RevokeByID(ctx, refreshTokenChainID)
}

func (s Service) LogoutGlobal(ctx context.Context, ssoSessionID string, refreshTokenChainIDs []string) error {
	if ssoSessionID != "" {
		if err := s.ssoSessions.RevokeByID(ctx, ssoSessionID); err != nil {
			return err
		}
	}
	for _, chainID := range refreshTokenChainIDs {
		if err := s.refreshTokens.RevokeByChainID(ctx, chainID); err != nil {
			return err
		}
		if err := s.refreshTokenChains.RevokeByID(ctx, chainID); err != nil {
			return err
		}
	}
	return nil
}

func splitScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	return normalizeScopes(strings.Fields(raw))
}

func unionScopes(base []string, extra []string) []string {
	return normalizeScopes(append(base, extra...))
}

func scopeSubset(requested []string, granted []string) bool {
	grantedSet := map[string]struct{}{}
	for _, scope := range granted {
		grantedSet[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := grantedSet[scope]; !ok {
			return false
		}
	}
	return true
}

func normalizeScopes(scopes []string) []string {
	set := map[string]struct{}{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for scope := range set {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func newOpaqueSecret() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	_, hash, err := hashSecret(value)
	return value, hash, err
}

func hashSecret(value string) (string, string, error) {
	if value == "" {
		return "", "", ErrAuthorizationCodeExpired
	}
	sum := sha256.Sum256([]byte(value))
	return value, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
