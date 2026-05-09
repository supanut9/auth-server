package httpserver

import (
	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/adapter/in/http"
	"github.com/supanut9/auth-server/internal/adapter/out/jwks"
	mailadapter "github.com/supanut9/auth-server/internal/adapter/out/mail"
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

type fixedOTPCodeGenerator struct {
	code string
}

func (g fixedOTPCodeGenerator) NewCode() (string, error) {
	return g.code, nil
}

func NewRouterFromEnv() (*gin.Engine, config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, config.Config{}, err
	}

	db, err := persistence.Open(cfg.DatabaseURL)
	if err != nil {
		return nil, config.Config{}, err
	}

	clock := system.NewClock()
	idGenerator := uuidadapter.NewGenerator()

	var mailSender port.MailSender
	if cfg.SMTPHost != "" && cfg.SMTPFrom != "" {
		sender, err := mailadapter.NewSMTPSender(mailadapter.SMTPSenderConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		})
		if err != nil {
			return nil, config.Config{}, err
		}
		mailSender = sender
	}

	jwksManager, err := jwks.NewManagerWithSources(
		cfg.JWTSigningAlg,
		cfg.JWTPrivateKeyPath,
		cfg.JWTPublicKeyPath,
		cfg.JWTPrivateKeyPEM,
		cfg.JWTPublicKeyPEM,
	)
	if err != nil {
		return nil, config.Config{}, err
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

	var otpCodeGenerator port.OTPCodeGenerator
	if cfg.FixedOTPCode != "" {
		otpCodeGenerator = fixedOTPCodeGenerator{code: cfg.FixedOTPCode}
	}

	identityService := identityapp.NewService(
		identityapp.Config{
			OTPChallengeTTL:   cfg.OTPChallengeTTL,
			OTPMaxAttempts:    cfg.OTPMaxAttempts,
			OTPMaxResends:     cfg.OTPMaxResends,
			OTPResendCooldown: cfg.OTPResendCooldown,
		},
		clock,
		idGenerator,
		otpCodeGenerator,
		accountRepository,
		accountProviderRepository,
		authorizationRequestRepository,
		otpChallengeRepository,
		mailSender,
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
	router.Use(http.RequestIDMiddleware())
	router.Use(http.StructuredLogger())
	router.Use(gin.Recovery())
	router.Use(http.CORSMiddleware(cfg))

	http.RegisterRoutes(router, cfg, db, app)
	return router, cfg, nil
}
