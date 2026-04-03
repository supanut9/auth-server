package http

import (
	"context"
	"crypto/subtle"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/adapter/out/persistence/schema"
	"github.com/supanut9/auth-server/internal/config"
	"gorm.io/gorm"
)

type supportAccountResponse struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	AvatarURL   string    `json:"avatar_url"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type supportClientRef struct {
	ClientID    string `json:"client_id"`
	DisplayName string `json:"display_name"`
}

type supportSessionResponse struct {
	ID              string     `json:"id"`
	Status          string     `json:"status"`
	LoginMethod     string     `json:"login_method"`
	AuthenticatedAt time.Time  `json:"authenticated_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
}

type supportConsentResponse struct {
	ID            string           `json:"id"`
	Client        supportClientRef `json:"client"`
	GrantedScopes string           `json:"granted_scopes"`
	GrantedAt     time.Time        `json:"granted_at"`
	LastUsedAt    time.Time        `json:"last_used_at"`
	RevokedAt     *time.Time       `json:"revoked_at"`
}

type supportRefreshChainResponse struct {
	ID                string           `json:"id"`
	Client            supportClientRef `json:"client"`
	SSOSessionID      string           `json:"sso_session_id"`
	Scope             string           `json:"scope"`
	Status            string           `json:"status"`
	AbsoluteExpiresAt time.Time        `json:"absolute_expires_at"`
	InactiveExpiresAt time.Time        `json:"inactive_expires_at"`
	LastUsedAt        time.Time        `json:"last_used_at"`
	RevokedAt         *time.Time       `json:"revoked_at"`
}

type supportAccountSummaryResponse struct {
	Account            supportAccountResponse        `json:"account"`
	Sessions           []supportSessionResponse      `json:"sessions"`
	Consents           []supportConsentResponse      `json:"consents"`
	RefreshTokenChains []supportRefreshChainResponse `json:"refresh_token_chains"`
}

type supportSignOutResponse struct {
	AccountID                string   `json:"account_id"`
	RevokedSessionIDs        []string `json:"revoked_session_ids"`
	RevokedChainIDs          []string `json:"revoked_chain_ids"`
	RevokedRefreshChainCount int      `json:"revoked_refresh_chain_count"`
}

func SupportAuthMiddleware(cfg config.Config) gin.HandlerFunc {
	expected := strings.TrimSpace(cfg.SupportAPIToken)
	return func(c *gin.Context) {
		if expected == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "support_unavailable"})
			c.Abort()
			return
		}

		provided := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer"))
		if provided == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (h Handler) getSupportAccount(c *gin.Context) {
	accountID := strings.TrimSpace(c.Param("accountID"))
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	summary, err := h.loadSupportAccountSummary(c.Request.Context(), accountID)
	if err != nil {
		h.renderLookupError(c, err)
		return
	}

	c.JSON(http.StatusOK, summary)
}

func (h Handler) signOutSupportAccount(c *gin.Context) {
	accountID := strings.TrimSpace(c.Param("accountID"))
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	summary, err := h.loadSupportAccountSummary(c.Request.Context(), accountID)
	if err != nil {
		h.renderLookupError(c, err)
		return
	}

	sessionIDs := make([]string, 0, len(summary.Sessions))
	for _, session := range summary.Sessions {
		sessionIDs = append(sessionIDs, session.ID)
	}
	chainIDs := make([]string, 0, len(summary.RefreshTokenChains))
	for _, chain := range summary.RefreshTokenChains {
		chainIDs = append(chainIDs, chain.ID)
	}

	now := time.Now().UTC()
	if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if len(sessionIDs) > 0 {
			if err := tx.Model(&schema.SSOSessionModel{}).
				Where("id IN ?", sessionIDs).
				Updates(map[string]any{
					"status":     "revoked",
					"revoked_at": now,
					"updated_at": now,
				}).Error; err != nil {
				return err
			}
		}
		if len(chainIDs) > 0 {
			if err := tx.Model(&schema.RefreshTokenChainModel{}).
				Where("id IN ?", chainIDs).
				Updates(map[string]any{
					"status":     "revoked",
					"revoked_at": now,
					"updated_at": now,
				}).Error; err != nil {
				return err
			}
			if err := tx.Model(&schema.RefreshTokenModel{}).
				Where("refresh_token_chain_id IN ?", chainIDs).
				Updates(map[string]any{
					"revoked_at": now,
				}).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, supportSignOutResponse{
		AccountID:                accountID,
		RevokedSessionIDs:        sessionIDs,
		RevokedChainIDs:          chainIDs,
		RevokedRefreshChainCount: len(chainIDs),
	})
}

func (h Handler) loadSupportAccountSummary(ctx context.Context, accountID string) (supportAccountSummaryResponse, error) {
	var account schema.AccountModel
	if err := h.db.WithContext(ctx).Where("id = ?", accountID).First(&account).Error; err != nil {
		return supportAccountSummaryResponse{}, err
	}

	var sessions []schema.SSOSessionModel
	if err := h.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Order("last_seen_at desc").
		Find(&sessions).Error; err != nil {
		return supportAccountSummaryResponse{}, err
	}

	var consents []schema.ConsentGrantModel
	if err := h.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Order("last_used_at desc").
		Find(&consents).Error; err != nil {
		return supportAccountSummaryResponse{}, err
	}

	var chains []schema.RefreshTokenChainModel
	if err := h.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Order("last_used_at desc").
		Find(&chains).Error; err != nil {
		return supportAccountSummaryResponse{}, err
	}

	clientIDs := uniqueClientIDs(consents, chains)
	clientsByID := map[string]schema.OAuthClientModel{}
	if len(clientIDs) > 0 {
		var clients []schema.OAuthClientModel
		if err := h.db.WithContext(ctx).
			Where("client_id IN ?", clientIDs).
			Find(&clients).Error; err != nil {
			return supportAccountSummaryResponse{}, err
		}
		for _, client := range clients {
			clientsByID[client.PublicClientID] = client
		}
	}

	response := supportAccountSummaryResponse{
		Account: supportAccountResponse{
			ID:          account.ID,
			Email:       account.PrimaryVerifiedEmail,
			DisplayName: account.DisplayName,
			AvatarURL:   account.AvatarURL,
			Status:      account.Status,
			CreatedAt:   account.CreatedAt,
			UpdatedAt:   account.UpdatedAt,
		},
		Sessions:           make([]supportSessionResponse, 0, len(sessions)),
		Consents:           make([]supportConsentResponse, 0, len(consents)),
		RefreshTokenChains: make([]supportRefreshChainResponse, 0, len(chains)),
	}

	for _, session := range sessions {
		response.Sessions = append(response.Sessions, supportSessionResponse{
			ID:              session.ID,
			Status:          session.Status,
			LoginMethod:     session.LoginMethod,
			AuthenticatedAt: session.AuthenticatedAt,
			LastSeenAt:      session.LastSeenAt,
			ExpiresAt:       session.ExpiresAt,
			RevokedAt:       session.RevokedAt,
		})
	}

	for _, consent := range consents {
		client := clientsByID[consent.ClientID]
		response.Consents = append(response.Consents, supportConsentResponse{
			ID:            consent.ID,
			Client:        supportClientRef{ClientID: consent.ClientID, DisplayName: client.DisplayName},
			GrantedScopes: consent.GrantedScopes,
			GrantedAt:     consent.GrantedAt,
			LastUsedAt:    consent.LastUsedAt,
			RevokedAt:     consent.RevokedAt,
		})
	}

	for _, chain := range chains {
		client := clientsByID[chain.ClientID]
		response.RefreshTokenChains = append(response.RefreshTokenChains, supportRefreshChainResponse{
			ID:                chain.ID,
			Client:            supportClientRef{ClientID: chain.ClientID, DisplayName: client.DisplayName},
			SSOSessionID:      chain.SSOSessionID,
			Scope:             chain.Scope,
			Status:            chain.Status,
			AbsoluteExpiresAt: chain.AbsoluteExpiresAt,
			InactiveExpiresAt: chain.InactiveExpiresAt,
			LastUsedAt:        chain.LastUsedAt,
			RevokedAt:         chain.RevokedAt,
		})
	}

	return response, nil
}

func uniqueClientIDs(consents []schema.ConsentGrantModel, chains []schema.RefreshTokenChainModel) []string {
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(consents)+len(chains))
	for _, consent := range consents {
		if consent.ClientID == "" {
			continue
		}
		if _, ok := seen[consent.ClientID]; ok {
			continue
		}
		seen[consent.ClientID] = struct{}{}
		ids = append(ids, consent.ClientID)
	}
	for _, chain := range chains {
		if chain.ClientID == "" {
			continue
		}
		if _, ok := seen[chain.ClientID]; ok {
			continue
		}
		seen[chain.ClientID] = struct{}{}
		ids = append(ids, chain.ClientID)
	}
	slices.Sort(ids)
	return ids
}
