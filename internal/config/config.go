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
	AppName                     string
	AppEnv                      string
	HTTPAddr                    string
	PublicBaseURL               string
	AuthUIBaseURL               string
	PostLogoutRedirectAllowlist []string
	DatabaseURL                 string
	RedisURL                    string
	JWTIssuer                   string
	JWTSigningAlg               string
	JWTPrivateKeyPath           string
	JWTPrivateKeyPEM            string
	JWTPublicKeyPath            string
	JWTPublicKeyPEM             string
	SSOCookieSecure             bool
	SSOCookieSameSite           string
	SSOCookieDomain             string
	GoogleClientID              string
	GoogleClientSecret          string
	GoogleRedirectURL           string
	GitHubClientID              string
	GitHubClientSecret          string
	GitHubRedirectURL           string
	SMTPHost                    string
	SMTPPort                    string
	SMTPUsername                string
	SMTPPassword                string
	SMTPFrom                    string
	FixedOTPCode                string
	SupportAPIToken             string
	PlatformAudience            string
	AccessTokenTTL              time.Duration
	IDTokenTTL                  time.Duration
	RefreshAbsoluteTTL          time.Duration
	RefreshInactiveTTL          time.Duration
	OTPChallengeTTL             time.Duration
	OTPMaxAttempts              int
	OTPMaxResends               int
	OTPResendCooldown           time.Duration
	AuthorizationRequestTTL     time.Duration
	AuthorizationCodeTTL        time.Duration
	SSOSessionTTL               time.Duration
}

func Load() (Config, error) {
	appEnv := getEnv("APP_ENV", "development")
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
	jwtIssuer, err := mustEnv("JWT_ISSUER")
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
	otpMaxAttempts, err := intEnv("OTP_MAX_ATTEMPTS", 6)
	if err != nil {
		return Config{}, err
	}
	otpMaxResends, err := intEnv("OTP_MAX_RESENDS", 3)
	if err != nil {
		return Config{}, err
	}
	otpResendCooldown, err := durationEnv("OTP_RESEND_COOLDOWN", time.Minute)
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
	ssocookieSecure, err := boolEnv("SSO_COOKIE_SECURE", defaultSSOCookieSecure(appEnv, publicBaseURL))
	if err != nil {
		return Config{}, err
	}
	ssocookieSameSite := strings.ToLower(strings.TrimSpace(getEnv("SSO_COOKIE_SAME_SITE", "lax")))
	ssocookieDomain := strings.TrimSpace(getEnv("SSO_COOKIE_DOMAIN", ""))

	cfg := Config{
		AppName:                     getEnv("APP_NAME", "auth-server"),
		AppEnv:                      appEnv,
		HTTPAddr:                    getEnv("HTTP_ADDR", ":8050"),
		PublicBaseURL:               publicBaseURL,
		AuthUIBaseURL:               authUIBaseURL,
		PostLogoutRedirectAllowlist: splitEnvList("POST_LOGOUT_REDIRECT_ALLOWLIST"),
		DatabaseURL:                 databaseURL,
		RedisURL:                    strings.TrimSpace(getEnv("REDIS_URL", "")),
		JWTIssuer:                   jwtIssuer,
		JWTSigningAlg:               getEnv("JWT_SIGNING_ALG", "RS256"),
		JWTPrivateKeyPath:           strings.TrimSpace(getEnv("JWT_PRIVATE_KEY_PATH", "")),
		JWTPrivateKeyPEM:            strings.TrimSpace(getEnv("JWT_PRIVATE_KEY_PEM", "")),
		JWTPublicKeyPath:            strings.TrimSpace(getEnv("JWT_PUBLIC_KEY_PATH", "")),
		JWTPublicKeyPEM:             strings.TrimSpace(getEnv("JWT_PUBLIC_KEY_PEM", "")),
		SSOCookieSecure:             ssocookieSecure,
		SSOCookieSameSite:           ssocookieSameSite,
		SSOCookieDomain:             ssocookieDomain,
		GoogleClientID:              getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:          getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:           getEnv("GOOGLE_REDIRECT_URL", ""),
		GitHubClientID:              getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:          getEnv("GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURL:           getEnv("GITHUB_REDIRECT_URL", ""),
		SMTPHost:                    getEnv("SMTP_HOST", ""),
		SMTPPort:                    getEnv("SMTP_PORT", "587"),
		SMTPUsername:                getEnv("SMTP_USERNAME", ""),
		SMTPPassword:                getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:                    getEnv("SMTP_FROM", ""),
		FixedOTPCode:                strings.TrimSpace(getEnv("FIXED_OTP_CODE", "")),
		SupportAPIToken:             getEnv("SUPPORT_API_TOKEN", defaultSupportAPIToken(appEnv)),
		PlatformAudience:            getEnv("PLATFORM_AUDIENCE", "platform-api"),
		AccessTokenTTL:              accessTokenTTL,
		IDTokenTTL:                  idTokenTTL,
		RefreshAbsoluteTTL:          refreshAbsoluteTTL,
		RefreshInactiveTTL:          refreshInactiveTTL,
		OTPChallengeTTL:             otpChallengeTTL,
		OTPMaxAttempts:              otpMaxAttempts,
		OTPMaxResends:               otpMaxResends,
		OTPResendCooldown:           otpResendCooldown,
		AuthorizationRequestTTL:     authorizationRequestTTL,
		AuthorizationCodeTTL:        authorizationCodeTTL,
		SSOSessionTTL:               ssoSessionTTL,
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
	for _, candidate := range c.PostLogoutRedirectAllowlist {
		if err := validateAbsoluteURL("POST_LOGOUT_REDIRECT_ALLOWLIST", candidate); err != nil {
			return err
		}
	}
	if err := validateAbsoluteURL("JWT_ISSUER", c.JWTIssuer); err != nil {
		return err
	}
	if err := validateCookiePolicy(c); err != nil {
		return err
	}
	if err := validateJWTKeySources(c); err != nil {
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
	if c.FixedOTPCode != "" && strings.EqualFold(c.AppEnv, "production") {
		return fmt.Errorf("FIXED_OTP_CODE must not be set in production")
	}
	if strings.TrimSpace(c.SupportAPIToken) == "" {
		return fmt.Errorf("missing required env: SUPPORT_API_TOKEN")
	}

	if c.OTPMaxAttempts <= 0 {
		return fmt.Errorf("invalid OTP_MAX_ATTEMPTS: must be greater than zero")
	}
	if c.OTPMaxResends < 0 {
		return fmt.Errorf("invalid OTP_MAX_RESENDS: must be zero or greater")
	}
	if c.OTPResendCooldown <= 0 {
		return fmt.Errorf("invalid OTP_RESEND_COOLDOWN: must be greater than zero")
	}

	return nil
}

func validateJWTKeySources(c Config) error {
	if strings.TrimSpace(c.JWTPrivateKeyPath) == "" && strings.TrimSpace(c.JWTPrivateKeyPEM) == "" {
		return fmt.Errorf("missing required env: JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM")
	}
	if strings.TrimSpace(c.JWTPublicKeyPath) == "" && strings.TrimSpace(c.JWTPublicKeyPEM) == "" {
		return fmt.Errorf("missing required env: JWT_PUBLIC_KEY_PATH or JWT_PUBLIC_KEY_PEM")
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

func validateCookiePolicy(c Config) error {
	switch c.SSOCookieSameSite {
	case "", "lax", "strict", "none":
	default:
		return fmt.Errorf("invalid SSO_COOKIE_SAME_SITE: must be lax, strict, or none")
	}
	if c.SSOCookieSameSite == "none" && !c.SSOCookieSecure {
		return fmt.Errorf("invalid cookie policy: SSO_COOKIE_SAME_SITE=none requires SSO_COOKIE_SECURE=true")
	}
	return nil
}

func defaultSSOCookieSecure(appEnv string, publicBaseURL string) bool {
	parsed, err := url.Parse(publicBaseURL)
	if err != nil {
		return false
	}
	if strings.EqualFold(appEnv, "development") {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}

func defaultSupportAPIToken(appEnv string) string {
	if strings.EqualFold(appEnv, "development") {
		return "dev-support-token"
	}
	return ""
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

func splitEnvList(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}

	rawParts := strings.Split(value, ",")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}

	return parts
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

func boolEnv(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse bool env %s: %w", key, err)
	}

	return parsed, nil
}

func intEnv(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse int env %s: %w", key, err)
	}

	return parsed, nil
}
