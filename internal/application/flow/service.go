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
	AuthorizationCodeTTL time.Duration
	SSOSessionTTL        time.Duration
}

type Service struct {
	clock                port.Clock
	idGenerator          port.IDGenerator
	authorizationCodes   port.AuthorizationCodeRepository
	consentGrants        port.ConsentGrantRepository
	ssoSessions          port.SSOSessionRepository
	refreshTokenChains   port.RefreshTokenChainRepository
	refreshTokens        port.RefreshTokenRepository
	authorizationCodeTTL time.Duration
	ssoSessionTTL        time.Duration
}

// IssueDirectCodeRequest is the stateless-flow input for issuing an
// authorization code without going through an AuthorizationRequest record.
// The caller (typically the new /authorize or /consent handlers in the
// stateless flow) has already validated the OAuth params via oauth.Validate
// and resolved the subject via the SSO session cookie.
type IssueDirectCodeRequest struct {
	AccountID               string
	ClientID                string
	SSOSessionID            *string
	RedirectURI             string
	Scopes                  []string
	PKCECodeChallenge       string
	PKCECodeChallengeMethod string
	AuthTime                time.Time
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
	authorizationCodes port.AuthorizationCodeRepository,
	consentGrants port.ConsentGrantRepository,
	ssoSessions port.SSOSessionRepository,
	refreshTokenChains port.RefreshTokenChainRepository,
	refreshTokens port.RefreshTokenRepository,
) Service {
	return Service{
		clock:                clock,
		idGenerator:          idGenerator,
		authorizationCodes:   authorizationCodes,
		consentGrants:        consentGrants,
		ssoSessions:          ssoSessions,
		refreshTokenChains:   refreshTokenChains,
		refreshTokens:        refreshTokens,
		authorizationCodeTTL: cfg.AuthorizationCodeTTL,
		ssoSessionTTL:        cfg.SSOSessionTTL,
	}
}

// IssueDirectCode issues an authorization code without referencing an
// AuthorizationRequest record. Used by stateless-flow handlers where the
// request lifecycle lives entirely in the URL (no server-side flow state to
// reference). All security gates (param validation, consent grant check) must
// be performed by the caller — this method only persists the code.
func (s Service) IssueDirectCode(ctx context.Context, req IssueDirectCodeRequest) (string, domain.AuthorizationCode, error) {
	if req.AccountID == "" || req.ClientID == "" || req.RedirectURI == "" {
		return "", domain.AuthorizationCode{}, ErrAuthorizationRequestInvalidStage
	}
	value, hash, err := newOpaqueSecret()
	if err != nil {
		return "", domain.AuthorizationCode{}, err
	}
	now := s.clock.Now().UTC()
	scopes := normalizeScopes(req.Scopes)
	code := domain.AuthorizationCode{
		CodeHash:                hash,
		AuthorizationRequestID:  nil,
		AccountID:               req.AccountID,
		ClientID:                req.ClientID,
		SSOSessionID:            req.SSOSessionID,
		RedirectURI:             req.RedirectURI,
		GrantedScopes:           strings.Join(scopes, " "),
		PKCECodeChallenge:       req.PKCECodeChallenge,
		PKCECodeChallengeMethod: req.PKCECodeChallengeMethod,
		AuthTime:                req.AuthTime.UTC(),
		ExpiresAt:               now.Add(s.authorizationCodeTTL),
		CreatedAt:               now,
	}
	code, err = s.authorizationCodes.Create(ctx, code)
	if err != nil {
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

// UpsertConsentRequest is the stateless input to UpsertConsent. The caller is
// expected to have already validated scopes against the client registration.
type UpsertConsentRequest struct {
	AccountID string
	ClientID  string
	Scopes    []string
}

// UpsertConsent records (or refreshes) a consent grant for the given account +
// client + scope set. Used by the stateless /v1/auth/consent/accept handler.
// Existing scopes are unioned with the new ones so revoking is an explicit
// separate operation.
func (s Service) UpsertConsent(ctx context.Context, req UpsertConsentRequest) (domain.ConsentGrant, error) {
	now := s.clock.Now().UTC()
	existing, err := s.consentGrants.FindByAccountAndClient(ctx, req.AccountID, req.ClientID)
	grantScopes := normalizeScopes(req.Scopes)
	if err == nil {
		grantScopes = unionScopes(grantScopes, splitScopes(existing.GrantedScopes))
	}
	return s.consentGrants.Upsert(ctx, domain.ConsentGrant{
		ID:            existing.ID,
		AccountID:     req.AccountID,
		ClientID:      req.ClientID,
		GrantedScopes: strings.Join(grantScopes, " "),
		GrantedAt:     existing.GrantedAt,
		LastUsedAt:    now,
	})
}

// HasConsentForScopes reports whether the given account has already granted
// the given scopes (a superset is sufficient) for the given client. Used by
// the stateless /authorize handler to skip the consent UI for returning users.
func (s Service) HasConsentForScopes(ctx context.Context, accountID, clientID string, scopes []string) bool {
	grant, err := s.consentGrants.FindByAccountAndClient(ctx, accountID, clientID)
	if err != nil {
		return false
	}
	if grant.RevokedAt != nil {
		return false
	}
	return scopeSubset(normalizeScopes(scopes), splitScopes(grant.GrantedScopes))
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
