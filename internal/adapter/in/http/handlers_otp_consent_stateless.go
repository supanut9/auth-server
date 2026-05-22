package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	identityapp "github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/application/oauth"
)

// otpStartStatelessBody piggy-backs on the canonical OAuth-param shape and
// adds an `email` field.
type otpStartStatelessBody struct {
	authorizeRequestBody
	Email string `json:"email" binding:"required"`
}

// startOTPStateless validates the OAuth params, creates a fresh OTP challenge
// (not tied to any AuthorizationRequest), emails the code, and returns a
// redirect URL to auth-ui /otp with the OAuth params + otp_challenge_id + email.
func (h Handler) startOTPStateless(c *gin.Context) {
	var body otpStartStatelessBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if _, oauthErr := oauth.Validate(c.Request.Context(), h.app.Clients, body.toOAuthRequest()); oauthErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
		return
	}

	challenge, err := h.app.Identity.StartOTPChallengeStateless(c.Request.Context(), identityapp.OTPStartStatelessRequest{
		Email: body.Email,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	q := body.toQuery()
	q.Set("otp_challenge_id", challenge.ID)
	q.Set("email", strings.TrimSpace(body.Email))

	c.JSON(http.StatusOK, gin.H{
		"otp_challenge_id": challenge.ID,
		"email":            maskEmail(challenge.Email),
		"expires_at":       challenge.ExpiresAt,
		"redirect_to":      h.authUIRoute("/otp", q),
	})
}

// otpVerifyStatelessBody includes the OAuth params plus the OTP challenge ID,
// email and code.
type otpVerifyStatelessBody struct {
	authorizeRequestBody
	OTPChallengeID string `json:"otp_challenge_id" binding:"required"`
	Email          string `json:"email" binding:"required"`
	Code           string `json:"code" binding:"required"`
}

// verifyOTPStateless verifies the OTP, signs the user in, and decides the next
// hop (client redirect if consent already granted, otherwise auth-ui /consent).
func (h Handler) verifyOTPStateless(c *gin.Context) {
	var body otpVerifyStatelessBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	validated, oauthErr := oauth.Validate(c.Request.Context(), h.app.Clients, body.toOAuthRequest())
	if oauthErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
		return
	}

	account, session, err := h.app.Identity.VerifyOTPChallengeStateless(c.Request.Context(), identityapp.OTPVerifyStatelessRequest{
		OTPChallengeID: body.OTPChallengeID,
		Email:          body.Email,
		Code:           body.Code,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	h.setSSOCookie(c, session.ID, session.ExpiresAt)

	response := gin.H{
		"account": gin.H{
			"id":           account.ID,
			"display_name": account.DisplayName,
			"email":        account.PrimaryVerifiedEmail,
		},
	}

	if h.app.Flow.HasConsentForScopes(c.Request.Context(), account.ID, validated.Client.ClientID, validated.Scopes) {
		ssoSessionID := session.ID
		codeValue, _, issueErr := h.app.Flow.IssueDirectCode(c.Request.Context(), flowapp.IssueDirectCodeRequest{
			AccountID:               account.ID,
			ClientID:                validated.Client.ClientID,
			SSOSessionID:            &ssoSessionID,
			RedirectURI:             validated.Request.RedirectURI,
			Scopes:                  validated.Scopes,
			PKCECodeChallenge:       validated.Request.CodeChallenge,
			PKCECodeChallengeMethod: validated.Request.CodeChallengeMethod,
			AuthTime:                session.AuthenticatedAt,
		})
		if issueErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": issueErr.Error()})
			return
		}
		redirectTo, ok := h.authorizationSuccessURL(validated.Request.RedirectURI, codeValue, validated.Request.State)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		response["redirect_to"] = redirectTo
	} else {
		response["redirect_to"] = h.authUIRoute("/consent", oauthValuesFromValidated(validated))
	}

	c.JSON(http.StatusOK, response)
}

type otpResendStatelessBody struct {
	OTPChallengeID string `json:"otp_challenge_id" binding:"required"`
}

func (h Handler) resendOTPStateless(c *gin.Context) {
	var body otpResendStatelessBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	challenge, err := h.app.Identity.ResendOTPChallengeStateless(c.Request.Context(), identityapp.OTPResendStatelessRequest{
		OTPChallengeID: body.OTPChallengeID,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"otp_challenge_id": challenge.ID,
		"email":            maskEmail(challenge.Email),
		"expires_at":       challenge.ExpiresAt,
	})
}

// consentRequestStatelessBody carries the OAuth params (already on the auth-ui
// /consent URL) and a CSRF token. Server compares the token against the cookie.
type consentRequestStatelessBody struct {
	authorizeRequestBody
	CSRFToken string `json:"csrf_token" binding:"required"`
}

// acceptConsentStateless: verify CSRF + OAuth params, read SSO session for the
// account, upsert the consent grant, issue a code, return the redirect URL.
func (h Handler) acceptConsentStateless(c *gin.Context) {
	var body consentRequestStatelessBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if err := h.verifyCSRF(c, body.CSRFToken); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "csrf", "error_description": err.Error()})
		return
	}

	validated, oauthErr := oauth.Validate(c.Request.Context(), h.app.Clients, body.toOAuthRequest())
	if oauthErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
		return
	}

	session, err := h.currentSSOSession(c.Request.Context(), c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}

	if _, err := h.app.Flow.UpsertConsent(c.Request.Context(), flowapp.UpsertConsentRequest{
		AccountID: session.AccountID,
		ClientID:  validated.Client.ClientID,
		Scopes:    validated.Scopes,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	ssoSessionID := session.ID
	codeValue, _, err := h.app.Flow.IssueDirectCode(c.Request.Context(), flowapp.IssueDirectCodeRequest{
		AccountID:               session.AccountID,
		ClientID:                validated.Client.ClientID,
		SSOSessionID:            &ssoSessionID,
		RedirectURI:             validated.Request.RedirectURI,
		Scopes:                  validated.Scopes,
		PKCECodeChallenge:       validated.Request.CodeChallenge,
		PKCECodeChallengeMethod: validated.Request.CodeChallengeMethod,
		AuthTime:                session.AuthenticatedAt,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	redirectTo, ok := h.authorizationSuccessURL(validated.Request.RedirectURI, codeValue, validated.Request.State)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": redirectTo,
	})
}

type consentRejectStatelessBody struct {
	ClientID    string `json:"client_id" binding:"required"`
	RedirectURI string `json:"redirect_uri" binding:"required"`
	State       string `json:"state" binding:"required"`
	CSRFToken   string `json:"csrf_token" binding:"required"`
}

// rejectConsentStateless: redirect the user back to the client with an
// access_denied error per OAuth spec. CSRF check still applies so a forged
// reject can't cancel an in-flight legit consent attempt.
func (h Handler) rejectConsentStateless(c *gin.Context) {
	var body consentRejectStatelessBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if err := h.verifyCSRF(c, body.CSRFToken); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "csrf", "error_description": err.Error()})
		return
	}

	// Minimal validation — confirm the client + redirect_uri are real before we
	// echo them back. (We don't need full Validate here since we're declining;
	// scope/PKCE don't apply.)
	client, err := h.app.Clients.FindByClientID(c.Request.Context(), body.ClientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}
	if !containsValue(client.RedirectURIs, body.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	redirectTo, ok := h.oauthErrorURL(body.RedirectURI, body.State, "access_denied", "user denied consent")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": redirectTo,
	})
}

var _ = time.Now // keep import even if not used after edits
