package config

import (
	"fmt"
	"os"
)

type Config struct {
	AppName           string
	AppEnv            string
	HTTPAddr          string
	PublicBaseURL     string
	AuthUIBaseURL     string
	DatabaseURL       string
	RedisURL          string
	JWTIssuer         string
	JWTSigningAlg     string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
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

	cfg := Config{
		AppName:           getEnv("APP_NAME", "auth-server"),
		AppEnv:            getEnv("APP_ENV", "development"),
		HTTPAddr:          getEnv("HTTP_ADDR", ":8050"),
		PublicBaseURL:     publicBaseURL,
		AuthUIBaseURL:     authUIBaseURL,
		DatabaseURL:       databaseURL,
		RedisURL:          redisURL,
		JWTIssuer:         jwtIssuer,
		JWTSigningAlg:     getEnv("JWT_SIGNING_ALG", "RS256"),
		JWTPrivateKeyPath: jwtPrivateKeyPath,
		JWTPublicKeyPath:  jwtPublicKeyPath,
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
