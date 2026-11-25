package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadFlowEnvelopeSecret(t *testing.T) {
	const publicBaseURL = "https://auth.example"
	for key, value := range map[string]string{
		"PUBLIC_BASE_URL":         publicBaseURL,
		"AUTH_UI_BASE_URL":        "https://ui.example",
		"DATABASE_URL":            "postgres://localhost/auth_test",
		"JWT_ISSUER":              publicBaseURL,
		"JWT_PRIVATE_KEY_PEM":     "test-private-key",
		"JWT_PUBLIC_KEY_PEM":      "test-public-key",
		"SUPPORT_API_TOKEN":       "test-support-token",
		"FIXED_OTP_CODE":          "",
		"OTP_TEST_HINT_ALLOWLIST": "",
	} {
		t.Setenv(key, value)
	}

	validSecret := strings.Repeat("é", 16)
	tests := []struct {
		name       string
		appEnv     string
		secret     string
		wantSecret string
		wantErr    bool
	}{
		{name: "production missing", appEnv: "production", wantErr: true},
		{name: "production blank", appEnv: "production", secret: " \t", wantErr: true},
		{name: "production short", appEnv: "Production", secret: " " + strings.Repeat("x", 31) + " ", wantErr: true},
		{name: "production valid", appEnv: "production", secret: " " + validSecret + " ", wantSecret: validSecret},
		{name: "development missing", appEnv: "development", wantSecret: "dev-flow-envelope-secret-" + publicBaseURL + "-min-32-bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_ENV", tt.appEnv)
			t.Setenv("FLOW_ENVELOPE_SECRET", tt.secret)

			cfg, err := Load()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "FLOW_ENVELOPE_SECRET") {
					t.Fatalf("expected FLOW_ENVELOPE_SECRET validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.FlowEnvelopeSecret != tt.wantSecret {
				t.Fatal("unexpected flow envelope secret")
			}
		})
	}
}

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

func TestValidateRejectsMissingSupportToken(t *testing.T) {
	t.Parallel()

	cfg := baseTestConfig()
	cfg.SupportAPIToken = ""

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SUPPORT_API_TOKEN") {
		t.Fatalf("expected support token validation error, got %v", err)
	}
}

func baseTestConfig() Config {
	return Config{
		PublicBaseURL:           "https://auth.example",
		AuthUIBaseURL:           "https://ui.example",
		JWTIssuer:               "https://auth.example",
		JWTPrivateKeyPEM:        "test-private-key",
		JWTPublicKeyPEM:         "test-public-key",
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
		SupportAPIToken:         "dev-support-token",
	}
}
