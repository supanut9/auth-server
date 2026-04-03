package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsInvalidSSOCookieSameSite(t *testing.T) {
	t.Parallel()

	cfg := baseTestConfig()
	cfg.SSOCookieSameSite = "unsupported"

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SSO_COOKIE_SAME_SITE") {
		t.Fatalf("expected SameSite validation error, got %v", err)
	}
}

func TestValidateRejectsSameSiteNoneWithoutSecure(t *testing.T) {
	t.Parallel()

	cfg := baseTestConfig()
	cfg.SSOCookieSameSite = "none"
	cfg.SSOCookieSecure = false

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires SSO_COOKIE_SECURE=true") {
		t.Fatalf("expected secure cookie validation error, got %v", err)
	}
}

func TestValidateRejectsInvalidOTPLimits(t *testing.T) {
	t.Parallel()

	cfg := baseTestConfig()
	cfg.OTPMaxAttempts = 0

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "OTP_MAX_ATTEMPTS") {
		t.Fatalf("expected otp attempts validation error, got %v", err)
	}
}

func baseTestConfig() Config {
	return Config{
		PublicBaseURL:           "https://auth.example",
		AuthUIBaseURL:           "https://ui.example",
		JWTIssuer:               "https://auth.example",
		SSOCookieSecure:         true,
		SSOCookieSameSite:       "lax",
		OTPMaxAttempts:          6,
		OTPMaxResends:           3,
		OTPResendCooldown:       time.Minute,
		OTPChallengeTTL:         10 * time.Minute,
		AuthorizationRequestTTL: 10 * time.Minute,
		AuthorizationCodeTTL:    5 * time.Minute,
		SSOSessionTTL:           24 * time.Hour,
		AccessTokenTTL:          10 * time.Minute,
		IDTokenTTL:              10 * time.Minute,
		RefreshAbsoluteTTL:      24 * time.Hour,
		RefreshInactiveTTL:      24 * time.Hour,
	}
}
