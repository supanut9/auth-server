package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppName                 string
	AppEnv                  string
	HTTPAddr                string
	PublicBaseURL           string
	AuthUIBaseURL           string
	DatabaseURL             string
	RedisURL                string
	JWTIssuer               string
	JWTSigningAlg           string
	JWTPrivateKeyPath       string
	JWTPublicKeyPath        string
	GoogleClientID          string
	GoogleClientSecret      string
	GoogleRedirectURL       string
	GitHubClientID          string
	GitHubClientSecret      string
	GitHubRedirectURL       string
	SMTPHost                string
	SMTPPort                string
	SMTPUsername            string
	SMTPPassword            string
	SMTPFrom                string
	PlatformAudience        string
	AccessTokenTTL          time.Duration
	IDTokenTTL              time.Duration
	RefreshAbsoluteTTL      time.Duration
	RefreshInactiveTTL      time.Duration
	OTPChallengeTTL         time.Duration
	AuthorizationRequestTTL time.Duration
	AuthorizationCodeTTL    time.Duration
	SSOSessionTTL           time.Duration
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
	otpChallengeTTL, err := durationEnv("OTP_CHALLENGE_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	authorizationRequestTTL, err := durationEnv("AUTHORIZATION_REQUEST_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	authorizationCodeTTL, err := durationEnv("AUTHORIZATION_CODE_TTL", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	ssoSessionTTL, err := durationEnv("SSO_SESSION_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		AppName:                 getEnv("APP_NAME", "auth-server"),
		AppEnv:                  getEnv("APP_ENV", "development"),
		HTTPAddr:                getEnv("HTTP_ADDR", ":8050"),
		PublicBaseURL:           publicBaseURL,
		AuthUIBaseURL:           authUIBaseURL,
		DatabaseURL:             databaseURL,
		RedisURL:                redisURL,
		JWTIssuer:               jwtIssuer,
		JWTSigningAlg:           getEnv("JWT_SIGNING_ALG", "RS256"),
		JWTPrivateKeyPath:       jwtPrivateKeyPath,
		JWTPublicKeyPath:        jwtPublicKeyPath,
		GoogleClientID:          getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:      getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:       getEnv("GOOGLE_REDIRECT_URL", ""),
		GitHubClientID:          getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:      getEnv("GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURL:       getEnv("GITHUB_REDIRECT_URL", ""),
		SMTPHost:                getEnv("SMTP_HOST", ""),
		SMTPPort:                getEnv("SMTP_PORT", "587"),
		SMTPUsername:            getEnv("SMTP_USERNAME", ""),
		SMTPPassword:            getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:                getEnv("SMTP_FROM", ""),
		PlatformAudience:        getEnv("PLATFORM_AUDIENCE", "platform-api"),
		AccessTokenTTL:          accessTokenTTL,
		IDTokenTTL:              idTokenTTL,
		RefreshAbsoluteTTL:      refreshAbsoluteTTL,
		RefreshInactiveTTL:      refreshInactiveTTL,
		OTPChallengeTTL:         otpChallengeTTL,
		AuthorizationRequestTTL: authorizationRequestTTL,
		AuthorizationCodeTTL:    authorizationCodeTTL,
		SSOSessionTTL:           ssoSessionTTL,
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if err := validateAbsoluteURL("PUBLIC_BASE_URL", c.PublicBaseURL); err != nil {
		return err
	}
	if err := validateAbsoluteURL("AUTH_UI_BASE_URL", c.AuthUIBaseURL); err != nil {
		return err
	}
	if err := validateAbsoluteURL("JWT_ISSUER", c.JWTIssuer); err != nil {
		return err
	}

	if err := validateProviderGroup(
		"GOOGLE",
		c.GoogleClientID,
		c.GoogleClientSecret,
		c.GoogleRedirectURL,
	); err != nil {
		return err
	}
	if err := validateProviderGroup(
		"GITHUB",
		c.GitHubClientID,
		c.GitHubClientSecret,
		c.GitHubRedirectURL,
	); err != nil {
		return err
	}

	if strings.TrimSpace(c.SMTPHost) != "" {
		if strings.TrimSpace(c.SMTPFrom) == "" {
			return fmt.Errorf("missing required env: SMTP_FROM when SMTP_HOST is set")
		}
		if _, err := strconv.Atoi(strings.TrimSpace(c.SMTPPort)); err != nil {
			return fmt.Errorf("invalid SMTP_PORT: %w", err)
		}
	}

	return nil
}

func validateAbsoluteURL(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid %s: must be an absolute URL", name)
	}
	return nil
}

func validateProviderGroup(prefix, clientID, clientSecret, redirectURL string) error {
	values := []string{clientID, clientSecret, redirectURL}
	filled := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			filled++
		}
	}
	if filled == 0 || filled == len(values) {
		return nil
	}

	return fmt.Errorf("incomplete %s provider config: set client id, secret, and redirect url together", prefix)
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
