package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/supanut9/auth-server/internal/adapter/out/persistence/schema"
	"github.com/supanut9/auth-server/internal/application"
	"github.com/supanut9/auth-server/internal/config"
)

func TestSupportAccountSummaryRequiresToken(t *testing.T) {
	t.Parallel()

	router, _ := newSupportTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/support/accounts/account-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rec.Code)
	}
}

func TestSupportAccountSummaryReturnsSessionsAndConsents(t *testing.T) {
	t.Parallel()

	db := newSupportTestDB(t)
	seedSupportFixture(t, db)
	router, token := newSupportTestRouterWithDB(t, db)

	req := httptest.NewRequest(http.MethodGet, "/v1/support/accounts/account-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Account struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"account"`
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
		Consents []struct {
			Client struct {
				ClientID    string `json:"client_id"`
				DisplayName string `json:"display_name"`
			} `json:"client"`
		} `json:"consents"`
		RefreshTokenChains []struct {
			ID string `json:"id"`
		} `json:"refresh_token_chains"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Account.ID != "account-1" || payload.Account.Email != "alice@example.com" {
		t.Fatalf("unexpected account payload: %+v", payload.Account)
	}
	if len(payload.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(payload.Sessions))
	}
	if len(payload.Consents) != 2 {
		t.Fatalf("expected 2 consents, got %d", len(payload.Consents))
	}
	if payload.Consents[0].Client.DisplayName == "" {
		t.Fatal("expected client display names in consent payload")
	}
	if len(payload.RefreshTokenChains) != 2 {
		t.Fatalf("expected 2 refresh token chains, got %d", len(payload.RefreshTokenChains))
	}
}

func TestSupportSignOutRevokesSessionsAndChains(t *testing.T) {
	t.Parallel()

	db := newSupportTestDB(t)
	seedSupportFixture(t, db)
	router, token := newSupportTestRouterWithDB(t, db)

	req := httptest.NewRequest(http.MethodPost, "/v1/support/accounts/account-1/sign-out", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		RevokedSessionIDs []string `json:"revoked_session_ids"`
		RevokedChainIDs   []string `json:"revoked_chain_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.RevokedSessionIDs) != 2 {
		t.Fatalf("expected 2 revoked sessions, got %d", len(payload.RevokedSessionIDs))
	}
	if len(payload.RevokedChainIDs) != 2 {
		t.Fatalf("expected 2 revoked chains, got %d", len(payload.RevokedChainIDs))
	}

	var sessions []schema.SSOSessionModel
	if err := db.Find(&sessions).Error; err != nil {
		t.Fatalf("load sessions: %v", err)
	}
	for _, session := range sessions {
		if session.Status != "revoked" || session.RevokedAt == nil {
			t.Fatalf("expected session revoked, got %+v", session)
		}
	}

	var chains []schema.RefreshTokenChainModel
	if err := db.Find(&chains).Error; err != nil {
		t.Fatalf("load chains: %v", err)
	}
	for _, chain := range chains {
		if chain.Status != "revoked" || chain.RevokedAt == nil {
			t.Fatalf("expected chain revoked, got %+v", chain)
		}
	}

	var tokens []schema.RefreshTokenModel
	if err := db.Find(&tokens).Error; err != nil {
		t.Fatalf("load tokens: %v", err)
	}
	for _, token := range tokens {
		if token.RevokedAt == nil {
			t.Fatalf("expected token revoked, got %+v", token)
		}
	}
}

func newSupportTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	db := newSupportTestDB(t)
	seedSupportFixture(t, db)
	return newSupportTestRouterWithDB(t, db)
}

func newSupportTestRouterWithDB(t *testing.T, db *gorm.DB) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.Config{
		AuthUIBaseURL:   "https://auth-ui.example",
		SupportAPIToken: "dev-support-token",
	}
	router := gin.New()
	router.Use(CORSMiddleware(cfg))
	RegisterRoutes(router, cfg, db, application.App{})
	return router, cfg.SupportAPIToken
}

func newSupportTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&schema.AccountModel{},
		&schema.OAuthClientModel{},
		&schema.OAuthClientRedirectURIModel{},
		&schema.SSOSessionModel{},
		&schema.RefreshTokenChainModel{},
		&schema.RefreshTokenModel{},
		&schema.ConsentGrantModel{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedSupportFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	now := time.Date(2026, 4, 3, 12, 0, 0, 0, time.UTC)

	account := schema.AccountModel{
		ID:                   "account-1",
		PrimaryVerifiedEmail: "alice@example.com",
		DisplayName:          "Alice Example",
		AvatarURL:            "https://cdn.example/alice.png",
		Status:               "active",
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	clientA := schema.OAuthClientModel{
		ID:             "client-db-1",
		PublicClientID: "client-a",
		ClientType:     "confidential",
		DisplayName:    "Client A",
		AllowedScopes:  "openid email profile",
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	clientB := schema.OAuthClientModel{
		ID:             "client-db-2",
		PublicClientID: "client-b",
		ClientType:     "confidential",
		DisplayName:    "Client B",
		AllowedScopes:  "openid email profile",
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	sessionA := schema.SSOSessionModel{
		ID:              "session-1",
		AccountID:       account.ID,
		Status:          "active",
		LoginMethod:     "google",
		AuthenticatedAt: now,
		LastSeenAt:      now,
		ExpiresAt:       now.Add(24 * time.Hour),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	sessionB := schema.SSOSessionModel{
		ID:              "session-2",
		AccountID:       account.ID,
		Status:          "active",
		LoginMethod:     "email_otp",
		AuthenticatedAt: now.Add(-1 * time.Hour),
		LastSeenAt:      now.Add(-1 * time.Hour),
		ExpiresAt:       now.Add(48 * time.Hour),
		CreatedAt:       now.Add(-1 * time.Hour),
		UpdatedAt:       now.Add(-1 * time.Hour),
	}
	chainA := schema.RefreshTokenChainModel{
		ID:                "chain-1",
		AccountID:         account.ID,
		ClientID:          clientA.PublicClientID,
		SSOSessionID:      sessionA.ID,
		Scope:             "openid email profile",
		DeviceSessionID:   "device-1",
		Status:            "active",
		AbsoluteExpiresAt: now.Add(30 * 24 * time.Hour),
		InactiveExpiresAt: now.Add(7 * 24 * time.Hour),
		LastUsedAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	chainB := schema.RefreshTokenChainModel{
		ID:                "chain-2",
		AccountID:         account.ID,
		ClientID:          clientB.PublicClientID,
		SSOSessionID:      sessionB.ID,
		Scope:             "openid email",
		DeviceSessionID:   "device-2",
		Status:            "active",
		AbsoluteExpiresAt: now.Add(30 * 24 * time.Hour),
		InactiveExpiresAt: now.Add(7 * 24 * time.Hour),
		LastUsedAt:        now.Add(-1 * time.Hour),
		CreatedAt:         now.Add(-1 * time.Hour),
		UpdatedAt:         now.Add(-1 * time.Hour),
	}
	tokenA := schema.RefreshTokenModel{
		ID:                  "token-1",
		RefreshTokenChainID: chainA.ID,
		TokenHash:           "token-hash-1",
		IssuedAt:            now,
		ExpiresAt:           now.Add(30 * 24 * time.Hour),
	}
	tokenB := schema.RefreshTokenModel{
		ID:                  "token-2",
		RefreshTokenChainID: chainB.ID,
		TokenHash:           "token-hash-2",
		IssuedAt:            now.Add(-1 * time.Hour),
		ExpiresAt:           now.Add(30 * 24 * time.Hour),
	}
	consentA := schema.ConsentGrantModel{
		ID:            "consent-1",
		AccountID:     account.ID,
		ClientID:      clientA.PublicClientID,
		GrantedScopes: "openid email profile",
		GrantedAt:     now.Add(-2 * time.Hour),
		LastUsedAt:    now.Add(-1 * time.Hour),
	}
	consentB := schema.ConsentGrantModel{
		ID:            "consent-2",
		AccountID:     account.ID,
		ClientID:      clientB.PublicClientID,
		GrantedScopes: "openid email",
		GrantedAt:     now.Add(-3 * time.Hour),
		LastUsedAt:    now.Add(-30 * time.Minute),
	}

	for _, value := range []any{&account, &clientA, &clientB, &sessionA, &sessionB, &chainA, &chainB, &tokenA, &tokenB, &consentA, &consentB} {
		if err := db.Create(value).Error; err != nil {
			t.Fatalf("seed fixture: %v", err)
		}
	}
}
