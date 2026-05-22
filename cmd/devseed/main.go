package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"github.com/supanut9/auth-server/internal/adapter/out/persistence"
	"github.com/supanut9/auth-server/internal/adapter/out/system"
	uuidadapter "github.com/supanut9/auth-server/internal/adapter/out/uuid"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
	"gorm.io/gorm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := persistence.Open(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	clock := system.NewClock()
	idGenerator := uuidadapter.NewGenerator()
	repo := persistence.NewOAuthClientRepository(db, idGenerator, clock)

	ctx := context.Background()
	settings := loadSeedSettings()

	publicClient := domain.OAuthClient{
		ClientID:      "dev-browser",
		ClientType:    "public",
		DisplayName:   "Development Browser Client",
		RedirectURIs:  settings.devBrowserRedirectURIs,
		AllowedScopes: "openid email profile trading.read trading.write",
		Status:        "active",
	}

	communityWebClient := domain.OAuthClient{
		ClientID:         "community-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.communityWebClientSecret),
		DisplayName:      "Community Web",
		RedirectURIs:     settings.communityWebRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	knowledgeWebClient := domain.OAuthClient{
		ClientID:         "knowledge-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.knowledgeWebClientSecret),
		DisplayName:      "Knowledge",
		RedirectURIs:     settings.knowledgeWebRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	languageWebClient := domain.OAuthClient{
		ClientID:         "language-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.languageWebClientSecret),
		DisplayName:      "Language Coach",
		RedirectURIs:     settings.languageWebRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	interviewWebClient := domain.OAuthClient{
		ClientID:         "interview-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.interviewWebClientSecret),
		DisplayName:      "Interview Prep",
		RedirectURIs:     settings.interviewWebRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	portalWebClient := domain.OAuthClient{
		ClientID:         "portal-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.portalWebClientSecret),
		DisplayName:      "Portal",
		RedirectURIs:     settings.portalWebRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	tradingWebClient := domain.OAuthClient{
		ClientID:         "trading-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.tradingWebClientSecret),
		DisplayName:      "Trading",
		RedirectURIs:     settings.tradingWebRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	confidentialClient := domain.OAuthClient{
		ClientID:         "dev-worker",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.devWorkerClientSecret),
		DisplayName:      "Development Worker Client",
		RedirectURIs:     settings.devWorkerRedirectURIs,
		AllowedScopes:    "trading.read trading.write",
		Status:           "active",
	}

	cmsAdminClient := domain.OAuthClient{
		ClientID:         "cms-admin",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.cmsAdminClientSecret),
		DisplayName:      "CMS Admin",
		RedirectURIs:     settings.cmsAdminRedirectURIs,
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	realtimeServiceClient := domain.OAuthClient{
		ClientID:         "realtime-service",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.realtimeServiceClientSecret),
		DisplayName:      "Realtime Service",
		RedirectURIs:     nil,
		AllowedScopes:    "trading.read trading.write",
		Status:           "active",
	}

	upsertClient(ctx, db, repo, idGenerator, publicClient)
	upsertClient(ctx, db, repo, idGenerator, communityWebClient)
	upsertClient(ctx, db, repo, idGenerator, knowledgeWebClient)
	upsertClient(ctx, db, repo, idGenerator, languageWebClient)
	upsertClient(ctx, db, repo, idGenerator, interviewWebClient)
	upsertClient(ctx, db, repo, idGenerator, portalWebClient)
	upsertClient(ctx, db, repo, idGenerator, tradingWebClient)
	upsertClient(ctx, db, repo, idGenerator, confidentialClient)
	upsertClient(ctx, db, repo, idGenerator, cmsAdminClient)
	upsertClient(ctx, db, repo, idGenerator, realtimeServiceClient)

	fmt.Println("seeded oauth clients:")
	fmt.Println("- public client_id: dev-browser")
	fmt.Println("- confidential client_id: community-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.communityWebClientSecret)
	fmt.Println("- confidential client_id: knowledge-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.knowledgeWebClientSecret)
	fmt.Println("- confidential client_id: language-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.languageWebClientSecret)
	fmt.Println("- confidential client_id: interview-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.interviewWebClientSecret)
	fmt.Println("- confidential client_id: portal-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.portalWebClientSecret)
	fmt.Println("- confidential client_id: trading-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.tradingWebClientSecret)
	fmt.Println("- confidential client_id: dev-worker")
	fmt.Printf("- confidential client_secret: %s\n", settings.devWorkerClientSecret)
	fmt.Println("- confidential client_id: realtime-service")
	fmt.Printf("- confidential client_secret: %s\n", settings.realtimeServiceClientSecret)
	fmt.Printf("- demo redirect_uris: %s\n", strings.Join(settings.devBrowserRedirectURIs, ", "))
	fmt.Printf("- community web redirect_uris: %s\n", strings.Join(settings.communityWebRedirectURIs, ", "))
	fmt.Printf("- knowledge web redirect_uris: %s\n", strings.Join(settings.knowledgeWebRedirectURIs, ", "))
	fmt.Printf("- language web redirect_uris: %s\n", strings.Join(settings.languageWebRedirectURIs, ", "))
	fmt.Printf("- interview web redirect_uris: %s\n", strings.Join(settings.interviewWebRedirectURIs, ", "))
	fmt.Printf("- portal web redirect_uris: %s\n", strings.Join(settings.portalWebRedirectURIs, ", "))
	fmt.Printf("- trading web redirect_uris: %s\n", strings.Join(settings.tradingWebRedirectURIs, ", "))
}

type seedSettings struct {
	devBrowserRedirectURIs      []string
	communityWebRedirectURIs    []string
	knowledgeWebRedirectURIs    []string
	languageWebRedirectURIs     []string
	interviewWebRedirectURIs    []string
	portalWebRedirectURIs       []string
	tradingWebRedirectURIs      []string
	cmsAdminRedirectURIs        []string
	devWorkerRedirectURIs       []string
	communityWebClientSecret    string
	knowledgeWebClientSecret    string
	languageWebClientSecret     string
	interviewWebClientSecret    string
	portalWebClientSecret       string
	tradingWebClientSecret      string
	cmsAdminClientSecret        string
	devWorkerClientSecret       string
	realtimeServiceClientSecret string
}

func loadSeedSettings() seedSettings {
	return seedSettings{
		devBrowserRedirectURIs:      redirectURIsFromEnv("DEV_BROWSER_REDIRECT_URIS", "DEV_BROWSER_REDIRECT_URI", "http://localhost:8050/dev/callback"),
		communityWebRedirectURIs:    redirectURIsFromEnv("COMMUNITY_WEB_REDIRECT_URIS", "COMMUNITY_WEB_REDIRECT_URI", "http://localhost:3006/api/auth/oauth2/callback/auth-server"),
		knowledgeWebRedirectURIs:    redirectURIsFromEnv("KNOWLEDGE_WEB_REDIRECT_URIS", "KNOWLEDGE_WEB_REDIRECT_URI", "http://localhost:3007/api/auth/oauth2/callback/auth-server"),
		languageWebRedirectURIs:     redirectURIsFromEnv("LANGUAGE_WEB_REDIRECT_URIS", "LANGUAGE_WEB_REDIRECT_URI", "http://localhost:3008/api/auth/oauth2/callback/auth-server"),
		interviewWebRedirectURIs:    redirectURIsFromEnv("INTERVIEW_WEB_REDIRECT_URIS", "INTERVIEW_WEB_REDIRECT_URI", "http://localhost:4301/api/auth/oauth2/callback/auth-server"),
		portalWebRedirectURIs:       redirectURIsFromEnv("PORTAL_WEB_REDIRECT_URIS", "PORTAL_WEB_REDIRECT_URI", "http://localhost:3009/api/auth/oauth2/callback/auth-server"),
		tradingWebRedirectURIs:      redirectURIsFromEnv("TRADING_WEB_REDIRECT_URIS", "TRADING_WEB_REDIRECT_URI", "http://localhost:3011/api/auth/oauth2/callback/auth-server"),
		cmsAdminRedirectURIs:        redirectURIsFromEnv("CMS_ADMIN_REDIRECT_URIS", "CMS_ADMIN_REDIRECT_URI", "http://localhost:4101/auth/callback"),
		devWorkerRedirectURIs:       redirectURIsFromEnv("DEV_WORKER_REDIRECT_URIS", "DEV_WORKER_REDIRECT_URI", "http://localhost:8050/dev/callback"),
		communityWebClientSecret:    envOrDefault("COMMUNITY_WEB_CLIENT_SECRET", "community-web-secret"),
		knowledgeWebClientSecret:    envOrDefault("KNOWLEDGE_WEB_CLIENT_SECRET", "knowledge-web-secret"),
		languageWebClientSecret:     envOrDefault("LANGUAGE_WEB_CLIENT_SECRET", "language-web-secret"),
		interviewWebClientSecret:    envOrDefault("INTERVIEW_WEB_CLIENT_SECRET", "interview-web-secret"),
		portalWebClientSecret:       envOrDefault("PORTAL_WEB_CLIENT_SECRET", "portal-web-secret"),
		tradingWebClientSecret:      envOrDefault("TRADING_WEB_CLIENT_SECRET", "trading-web-secret"),
		cmsAdminClientSecret:        envOrDefault("CMS_ADMIN_CLIENT_SECRET", "cms-admin-secret"),
		devWorkerClientSecret:       envOrDefault("DEV_WORKER_CLIENT_SECRET", "dev-worker-secret"),
		realtimeServiceClientSecret: envOrDefault("REALTIME_SERVICE_CLIENT_SECRET", "dev-realtime-secret"),
	}
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func redirectURIsFromEnv(listKey string, singleKey string, fallbacks ...string) []string {
	if values := splitRedirectURIs(os.Getenv(listKey)); len(values) > 0 {
		return values
	}
	if value := strings.TrimSpace(os.Getenv(singleKey)); value != "" {
		return []string{value}
	}
	return append([]string(nil), fallbacks...)
}

func splitRedirectURIs(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	redirectURIs := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		redirectURI := strings.TrimSpace(part)
		if redirectURI == "" {
			continue
		}
		if _, ok := seen[redirectURI]; ok {
			continue
		}
		seen[redirectURI] = struct{}{}
		redirectURIs = append(redirectURIs, redirectURI)
	}
	return redirectURIs
}

func upsertClient(ctx context.Context, db *gorm.DB, repo persistence.OAuthClientRepository, idGenerator port.IDGenerator, client domain.OAuthClient) {
	if existing, err := repo.FindByClientID(ctx, client.ClientID); err == nil {
		client.ID = existing.ID
		client.CreatedAt = existing.CreatedAt
		client.UpdatedAt = time.Now().UTC()
		if err := db.WithContext(ctx).Model(&persistence.OAuthClientModel{}).
			Where("client_id = ?", client.ClientID).
			Updates(map[string]any{
				"client_type":        client.ClientType,
				"client_secret_hash": client.ClientSecretHash,
				"display_name":       client.DisplayName,
				"allowed_scopes":     client.AllowedScopes,
				"status":             client.Status,
				"updated_at":         client.UpdatedAt,
			}).Error; err != nil {
			log.Fatalf("update client %s: %v", client.ClientID, err)
		}
		if err := db.WithContext(ctx).Where("client_id = ?", client.ClientID).Delete(&persistence.OAuthClientRedirectURIModel{}).Error; err != nil {
			log.Fatalf("clear redirect uris for client %s: %v", client.ClientID, err)
		}
		if len(client.RedirectURIs) > 0 {
			now := client.UpdatedAt
			redirectURIs := make([]persistence.OAuthClientRedirectURIModel, 0, len(client.RedirectURIs))
			for _, redirectURI := range client.RedirectURIs {
				redirectURIs = append(redirectURIs, persistence.OAuthClientRedirectURIModel{
					ID:          mustNewID(idGenerator),
					ClientID:    client.ClientID,
					RedirectURI: redirectURI,
					CreatedAt:   now,
					UpdatedAt:   now,
				})
			}
			if err := db.WithContext(ctx).Create(&redirectURIs).Error; err != nil {
				log.Fatalf("create redirect uris for client %s: %v", client.ClientID, err)
			}
		}
		return
	}

	if _, err := repo.Create(ctx, client); err != nil {
		log.Fatalf("create client %s: %v", client.ClientID, err)
	}
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func mustNewID(idGenerator port.IDGenerator) string {
	id, err := idGenerator.NewID()
	if err != nil {
		log.Fatalf("generate id: %v", err)
	}
	return id
}
