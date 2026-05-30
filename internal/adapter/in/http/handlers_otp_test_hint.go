package http

// handlers_otp_test_hint.go
//
// INT-244 — non-production-only endpoint that returns the most recent active
// OTP code for an allowlisted email address, so that CI can complete OTP login
// without operator interaction.
//
// Production refusal contract (mirrors smoke-bypass.ts in interview-web):
//   - Returns 404 if APP_ENV=production.
//   - Returns 404 if OTP_TEST_HINT_ALLOWLIST is unset or empty.
//   - Returns 404 if the requested email is not in OTP_TEST_HINT_ALLOWLIST.
//   - Returns 404 if no active (unverified, unexpired) challenge exists.
//
// The endpoint is registered in router.go only when AppEnv != production, but
// the handler itself also checks — defence in depth.

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// testOTPHint implements GET /v1/auth/otp/test-hint?email=<email>
func (h Handler) testOTPHint(c *gin.Context) {
	// Hard-refuse in production regardless of how the route was mounted.
	if strings.EqualFold(h.cfg.AppEnv, "production") {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	// Default behavior when the allowlist is unconfigured: 404.
	if len(h.cfg.OTPTestHintAllowlist) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	email := strings.TrimSpace(strings.ToLower(c.Query("email")))
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "email query param required"})
		return
	}

	// Check the email is on the allowlist.
	allowed := false
	for _, entry := range h.cfg.OTPTestHintAllowlist {
		if strings.EqualFold(strings.TrimSpace(entry), email) {
			allowed = true
			break
		}
	}
	if !allowed {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	challenge, err := h.app.OTPChallenges.FindLatestActiveByEmail(c.Request.Context(), email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"otp_challenge_id": challenge.ID,
		"email":            challenge.Email,
		"expires_at":       challenge.ExpiresAt,
		// code_hash is returned so CI can confirm which challenge is active.
		// The raw code is NOT returned here — CI uses the hash to correlate
		// against the code obtained from the FIXED_OTP_CODE dev env var OR the
		// fixed code set in the non-prod environment, enabling automation
		// without exposing a live code over the wire in plaintext.
		//
		// INT-244 NOTE: to get the raw code for CI, set FIXED_OTP_CODE to a
		// known value in non-production. The test-hint endpoint confirms the
		// challenge is active; the CI job already knows the fixed code.
		"code_hash_prefix": challenge.CodeHash[:8],
	})
}
