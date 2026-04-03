package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
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

	publicClient := domain.OAuthClient{
		ClientID:      "dev-browser",
		ClientType:    "public",
		DisplayName:   "Development Browser Client",
		RedirectURIs:  []string{"http://localhost:8050/dev/callback"},
		AllowedScopes: "openid email profile trading.read trading.write",
		Status:        "active",
	}

	communityWebClient := domain.OAuthClient{
		ClientID:         "community-web",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret("community-web-secret"),
		DisplayName:      "Community Web",
		RedirectURIs: []string{
			"http://localhost:3006/api/auth/oauth2/callback/auth-server",
		},
		AllowedScopes: "openid email profile",
		Status:        "active",
	}

	confidentialSecret := "dev-worker-secret"
	confidentialClient := domain.OAuthClient{
		ClientID:         "dev-worker",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(confidentialSecret),
		DisplayName:      "Development Worker Client",
		RedirectURIs:     []string{"http://localhost:8050/dev/callback"},
		AllowedScopes:    "trading.read trading.write",
		Status:           "active",
	}

	realtimeServiceSecret := "dev-realtime-secret"
	realtimeServiceClient := domain.OAuthClient{
		ClientID:         "realtime-service",
		ClientType:       "confidential",
		ClientSecretHash: hashSecret(realtimeServiceSecret),
		DisplayName:      "Realtime Service",
		RedirectURIs:     nil,
		AllowedScopes:    "trading.read trading.write",
		Status:           "active",
	}

	upsertClient(ctx, db, repo, idGenerator, publicClient)
	upsertClient(ctx, db, repo, idGenerator, communityWebClient)
	upsertClient(ctx, db, repo, idGenerator, confidentialClient)
	upsertClient(ctx, db, repo, idGenerator, realtimeServiceClient)

	fmt.Println("seeded oauth clients:")
	fmt.Println("- public client_id: dev-browser")
	fmt.Println("- confidential client_id: community-web")
	fmt.Println("- confidential client_secret: community-web-secret")
	fmt.Println("- confidential client_id: dev-worker")
	fmt.Println("- confidential client_secret: dev-worker-secret")
	fmt.Println("- confidential client_id: realtime-service")
	fmt.Println("- confidential client_secret: dev-realtime-secret")
	fmt.Println("- demo redirect_uri: http://localhost:8050/dev/callback")
	fmt.Println("- community web redirect_uri: http://localhost:3006/api/auth/oauth2/callback/auth-server")
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
