package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	AppName            string
	AppEnv             string
	HTTPAddr           string
	PublicBaseURL      string
	AuthUIBaseURL      string
	DatabaseURL        string
	RedisURL           string
	JWTIssuer          string
	JWTSigningAlg      string
	JWTPrivateKeyPath  string
	JWTPublicKeyPath   string
	PlatformAudience   string
	AccessTokenTTL     time.Duration
	IDTokenTTL         time.Duration
	RefreshAbsoluteTTL time.Duration
	RefreshInactiveTTL time.Duration
}

func Load() (Config, error) {
	publicBaseURL, err := mustEnv("PUBLIC_BASE_URL")
	if err != nil {
		return Config{}, err
	}
	authUIBaseURL, err := mustEnv("AUTH_UI_BASE_URL")
	if err != nil {
		return Config{}, err
	}
	databaseURL, err := mustEnv("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	redisURL, err := mustEnv("REDIS_URL")
	if err != nil {
		return Config{}, err
	}
	jwtIssuer, err := mustEnv("JWT_ISSUER")
	if err != nil {
		return Config{}, err
	}
	jwtPrivateKeyPath, err := mustEnv("JWT_PRIVATE_KEY_PATH")
	if err != nil {
		return Config{}, err
	}
	jwtPublicKeyPath, err := mustEnv("JWT_PUBLIC_KEY_PATH")
	if err != nil {
		return Config{}, err
	}
	accessTokenTTL, err := durationEnv("ACCESS_TOKEN_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	idTokenTTL, err := durationEnv("ID_TOKEN_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	refreshAbsoluteTTL, err := durationEnv("REFRESH_TOKEN_ABSOLUTE_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	refreshInactiveTTL, err := durationEnv("REFRESH_TOKEN_INACTIVE_TTL", 7*24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		AppName:            getEnv("APP_NAME", "auth-server"),
		AppEnv:             getEnv("APP_ENV", "development"),
		HTTPAddr:           getEnv("HTTP_ADDR", ":8050"),
		PublicBaseURL:      publicBaseURL,
		AuthUIBaseURL:      authUIBaseURL,
		DatabaseURL:        databaseURL,
		RedisURL:           redisURL,
		JWTIssuer:          jwtIssuer,
		JWTSigningAlg:      getEnv("JWT_SIGNING_ALG", "RS256"),
		JWTPrivateKeyPath:  jwtPrivateKeyPath,
		JWTPublicKeyPath:   jwtPublicKeyPath,
		PlatformAudience:   getEnv("PLATFORM_AUDIENCE", "platform-api"),
		AccessTokenTTL:     accessTokenTTL,
		IDTokenTTL:         idTokenTTL,
		RefreshAbsoluteTTL: refreshAbsoluteTTL,
		RefreshInactiveTTL: refreshInactiveTTL,
	}

	return cfg, nil
}

func mustEnv(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("missing required env: %s", key)
	}
	return value, nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse duration env %s: %w", key, err)
	}

	return parsed, nil
}
