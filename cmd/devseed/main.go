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
		RedirectURIs:  []string{settings.devBrowserRedirectURI},
		AllowedScopes: "openid email profile trading.read trading.write",
		Status:        "active",
	}

	communityWebClient := domain.OAuthClient{
		ClientID:         "community-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.communityWebClientSecret),
		DisplayName:      "Community Web",
		RedirectURIs:     []string{settings.communityWebRedirectURI},
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	knowledgeWebClient := domain.OAuthClient{
		ClientID:         "knowledge-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.knowledgeWebClientSecret),
		DisplayName:      "Knowledge",
		RedirectURIs:     []string{settings.knowledgeWebRedirectURI},
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	languageWebClient := domain.OAuthClient{
		ClientID:         "language-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.languageWebClientSecret),
		DisplayName:      "Language Coach",
		RedirectURIs:     []string{settings.languageWebRedirectURI},
		AllowedScopes:    "openid email profile offline_access",
		Status:           "active",
	}

	confidentialClient := domain.OAuthClient{
		ClientID:         "dev-worker",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(settings.devWorkerClientSecret),
		DisplayName:      "Development Worker Client",
		RedirectURIs:     []string{settings.devWorkerRedirectURI},
		AllowedScopes:    "trading.read trading.write",
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
	upsertClient(ctx, db, repo, idGenerator, confidentialClient)
	upsertClient(ctx, db, repo, idGenerator, realtimeServiceClient)

	fmt.Println("seeded oauth clients:")
	fmt.Println("- public client_id: dev-browser")
	fmt.Println("- confidential client_id: community-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.communityWebClientSecret)
	fmt.Println("- confidential client_id: knowledge-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.knowledgeWebClientSecret)
	fmt.Println("- confidential client_id: language-web")
	fmt.Printf("- confidential client_secret: %s\n", settings.languageWebClientSecret)
	fmt.Println("- confidential client_id: dev-worker")
	fmt.Printf("- confidential client_secret: %s\n", settings.devWorkerClientSecret)
	fmt.Println("- confidential client_id: realtime-service")
	fmt.Printf("- confidential client_secret: %s\n", settings.realtimeServiceClientSecret)
	fmt.Printf("- demo redirect_uri: %s\n", settings.devBrowserRedirectURI)
	fmt.Printf("- community web redirect_uri: %s\n", settings.communityWebRedirectURI)
	fmt.Printf("- knowledge web redirect_uri: %s\n", settings.knowledgeWebRedirectURI)
	fmt.Printf("- language web redirect_uri: %s\n", settings.languageWebRedirectURI)
}

type seedSettings struct {
	devBrowserRedirectURI       string
	communityWebRedirectURI     string
	knowledgeWebRedirectURI     string
	languageWebRedirectURI      string
	devWorkerRedirectURI        string
	communityWebClientSecret    string
	knowledgeWebClientSecret    string
	languageWebClientSecret     string
	devWorkerClientSecret       string
	realtimeServiceClientSecret string
}

func loadSeedSettings() seedSettings {
	return seedSettings{
		devBrowserRedirectURI:       envOrDefault("DEV_BROWSER_REDIRECT_URI", "http://localhost:8050/dev/callback"),
		communityWebRedirectURI:     envOrDefault("COMMUNITY_WEB_REDIRECT_URI", "http://localhost:3006/api/auth/oauth2/callback/auth-server"),
		knowledgeWebRedirectURI:     envOrDefault("KNOWLEDGE_WEB_REDIRECT_URI", "http://localhost:3007/api/auth/oauth2/callback/auth-server"),
		languageWebRedirectURI:      envOrDefault("LANGUAGE_WEB_REDIRECT_URI", "http://localhost:3008/api/auth/oauth2/callback/auth-server"),
		devWorkerRedirectURI:        envOrDefault("DEV_WORKER_REDIRECT_URI", "http://localhost:8050/dev/callback"),
		communityWebClientSecret:    envOrDefault("COMMUNITY_WEB_CLIENT_SECRET", "community-web-secret"),
		knowledgeWebClientSecret:    envOrDefault("KNOWLEDGE_WEB_CLIENT_SECRET", "knowledge-web-secret"),
		languageWebClientSecret:     envOrDefault("LANGUAGE_WEB_CLIENT_SECRET", "language-web-secret"),
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
