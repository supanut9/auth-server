package main

import (
	"log"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"

	"github.com/supanut9/auth-server/internal/adapter/in/http"
	"github.com/supanut9/auth-server/internal/adapter/out/jwks"
	"github.com/supanut9/auth-server/internal/adapter/out/persistence"
	provideradapter "github.com/supanut9/auth-server/internal/adapter/out/provider"
	"github.com/supanut9/auth-server/internal/adapter/out/system"
	uuidadapter "github.com/supanut9/auth-server/internal/adapter/out/uuid"
	"github.com/supanut9/auth-server/internal/application"
	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	identityapp "github.com/supanut9/auth-server/internal/application/identity"
	tokenapp "github.com/supanut9/auth-server/internal/application/token"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/port"
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

	jwksManager, err := jwks.NewManager(cfg.JWTSigningAlg, cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath)
	if err != nil {
		log.Fatalf("load signing keys: %v", err)
	}

	accountRepository := persistence.NewAccountRepository(db, idGenerator, clock)
	clientRepository := persistence.NewOAuthClientRepository(db, idGenerator, clock)
	accountProviderRepository := persistence.NewAccountProviderRepository(db, idGenerator, clock)
	authorizationRequestRepository := persistence.NewAuthorizationRequestRepository(db, idGenerator, clock)
	authorizationCodeRepository := persistence.NewAuthorizationCodeRepository(db, idGenerator, clock)
	consentGrantRepository := persistence.NewConsentGrantRepository(db, idGenerator, clock)
	ssoSessionRepository := persistence.NewSSOSessionRepository(db, idGenerator, clock)
	refreshTokenChainRepository := persistence.NewRefreshTokenChainRepository(db, idGenerator, clock)
	refreshTokenRepository := persistence.NewRefreshTokenRepository(db, idGenerator)
	accessTokenRepository := persistence.NewAccessTokenRepository(db, idGenerator, clock)
	otpChallengeRepository := persistence.NewOTPChallengeRepository(db, idGenerator, clock)

	flowService := flowapp.NewService(
		flowapp.Config{
			AuthorizationRequestTTL: cfg.AuthorizationRequestTTL,
			AuthorizationCodeTTL:    cfg.AuthorizationCodeTTL,
			SSOSessionTTL:           cfg.SSOSessionTTL,
		},
		clock,
		idGenerator,
		authorizationRequestRepository,
		authorizationCodeRepository,
		consentGrantRepository,
		ssoSessionRepository,
		refreshTokenChainRepository,
		refreshTokenRepository,
	)

	identityService := identityapp.NewService(
		identityapp.Config{
			OTPChallengeTTL: cfg.OTPChallengeTTL,
		},
		clock,
		idGenerator,
		nil,
		accountRepository,
		accountProviderRepository,
		authorizationRequestRepository,
		otpChallengeRepository,
		nil,
		flowService,
	)

	tokenService := tokenapp.NewService(
		tokenapp.Config{
			Issuer:                  cfg.JWTIssuer,
			Audience:                cfg.PlatformAudience,
			AccessTokenTTL:          cfg.AccessTokenTTL,
			IDTokenTTL:              cfg.IDTokenTTL,
			RefreshTokenAbsoluteTTL: cfg.RefreshAbsoluteTTL,
			RefreshTokenInactiveTTL: cfg.RefreshInactiveTTL,
		},
		clock,
		idGenerator,
		jwksManager,
		accessTokenRepository,
		refreshTokenChainRepository,
		refreshTokenRepository,
	)

	providers := map[string]port.IdentityProvider{}
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" && cfg.GoogleRedirectURL != "" {
		googleProvider := provideradapter.NewGoogleProvider(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL)
		providers[googleProvider.Name()] = googleProvider
	}
	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" && cfg.GitHubRedirectURL != "" {
		githubProvider := provideradapter.NewGitHubProvider(cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubRedirectURL)
		providers[githubProvider.Name()] = githubProvider
	}

	app := application.App{
		Flow:          flowService,
		Identity:      identityService,
		Token:         tokenService,
		Accounts:      accountRepository,
		Clients:       clientRepository,
		SSOSessions:   ssoSessionRepository,
		Requests:      authorizationRequestRepository,
		JWKS:          jwksManager,
		Verifier:      jwksManager,
		Providers:     providers,
		RefreshChains: refreshTokenChainRepository,
		RefreshTokens: refreshTokenRepository,
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(http.CORSMiddleware(cfg))

	http.RegisterRoutes(router, cfg, app)

	if err := router.Run(cfg.HTTPAddr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
