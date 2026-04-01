package http

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/application"
	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	identityapp "github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
	"gorm.io/gorm"
)

const ssoCookieName = "auth_sso_session"

type Handler struct {
	cfg config.Config
	app application.App
}

func RegisterRoutes(router *gin.Engine, cfg config.Config, app application.App) {
	handler := Handler{cfg: cfg, app: app}

	router.GET("/healthz", handler.healthz)
	router.GET("/.well-known/openid-configuration", handler.openIDConfiguration)
	router.GET("/.well-known/jwks.json", handler.jwks)

	auth := router.Group("/v1/auth")
	auth.GET("/requests/:requestID", handler.getAuthorizationRequest)
	auth.POST("/consent/accept", handler.acceptConsent)
	auth.POST("/consent/reject", handler.rejectConsent)
	auth.POST("/otp/start", handler.startOTP)
	auth.POST("/otp/verify", handler.verifyOTP)
	auth.POST("/otp/resend", handler.resendOTP)
	auth.GET("/logout", handler.logoutLocal)
	auth.GET("/logout/global", handler.logoutGlobal)
}

func (h Handler) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"app_name": h.cfg.AppName,
	})
}

func (h Handler) openIDConfiguration(c *gin.Context) {
	issuer := strings.TrimRight(h.cfg.JWTIssuer, "/")
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/v1/oauth2/authorize",
		"token_endpoint":                        issuer + "/v1/oauth2/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":                     issuer + "/v1/oidc/userinfo",
		"revocation_endpoint":                   issuer + "/v1/oauth2/revoke",
		"introspection_endpoint":                issuer + "/v1/oauth2/introspect",
		"scopes_supported":                      []string{"openid", "email", "profile", "trading.read", "trading.write"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{h.cfg.JWTSigningAlg},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
	})
}

func (h Handler) jwks(c *gin.Context) {
	document, err := h.app.JWKS.PublicJWKS()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.Data(http.StatusOK, "application/json", document)
}

type authorizationRequestResponse struct {
	RequestID             string              `json:"request_id"`
	Stage                 string              `json:"stage"`
	ExpiresAt             time.Time           `json:"expires_at"`
	Client                requestClient       `json:"client"`
	RequestedScopes       []string            `json:"requested_scopes"`
	AvailableLoginMethods []string            `json:"available_login_methods"`
	Consent               requestConsent      `json:"consent"`
	OTP                   requestOTP          `json:"otp"`
	AccountHint           *requestAccountHint `json:"account_hint"`
}

type requestClient struct {
	ClientID    string `json:"client_id"`
	DisplayName string `json:"display_name"`
}

type requestConsent struct {
	Required bool `json:"required"`
}

type requestOTP struct {
	Required    bool    `json:"required"`
	MaskedEmail *string `json:"masked_email"`
}

type requestAccountHint struct {
	DisplayName *string `json:"display_name"`
	Email       *string `json:"email"`
}

func (h Handler) getAuthorizationRequest(c *gin.Context) {
	requestID := c.Param("requestID")
	request, err := h.app.Requests.FindByID(c.Request.Context(), requestID)
	if err != nil {
		h.renderLookupError(c, err)
		return
	}

	client, err := h.app.Clients.FindByClientID(c.Request.Context(), request.ClientID)
	if err != nil {
		h.renderLookupError(c, err)
		return
	}

	var accountHint *requestAccountHint
	if request.AccountID != nil {
		if account, err := h.app.Accounts.FindByID(c.Request.Context(), *request.AccountID); err == nil {
			accountHint = &requestAccountHint{
				DisplayName: stringPtr(account.DisplayName),
				Email:       stringPtr(account.PrimaryVerifiedEmail),
			}
		}
	} else if request.PendingProviderDisplayName != "" || request.PendingProviderEmail != "" {
		accountHint = &requestAccountHint{
			DisplayName: optionalStringPtr(request.PendingProviderDisplayName),
			Email:       optionalStringPtr(request.PendingProviderEmail),
		}
	}

	var maskedEmail *string
	if request.PendingProviderEmail != "" {
		value := maskEmail(request.PendingProviderEmail)
		maskedEmail = &value
	}

	c.JSON(http.StatusOK, authorizationRequestResponse{
		RequestID:             request.ID,
		Stage:                 request.Stage,
		ExpiresAt:             request.ExpiresAt,
		Client:                requestClient{ClientID: client.ClientID, DisplayName: client.DisplayName},
		RequestedScopes:       strings.Fields(request.RequestedScopes),
		AvailableLoginMethods: []string{"google", "github", "email_otp"},
		Consent:               requestConsent{Required: request.Stage == domain.AuthorizationStageConsentRequired},
		OTP:                   requestOTP{Required: request.Stage == domain.AuthorizationStageOTPRequired, MaskedEmail: maskedEmail},
		AccountHint:           accountHint,
	})
}

type consentRequest struct {
	RequestID string `json:"request_id" binding:"required"`
}

func (h Handler) acceptConsent(c *gin.Context) {
	var req consentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	request, err := h.app.Flow.AcceptConsent(c.Request.Context(), req.RequestID)
	if err != nil {
		h.renderFlowError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request_id": request.ID,
		"stage":      request.Stage,
	})
}

func (h Handler) rejectConsent(c *gin.Context) {
	var req consentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	request, err := h.app.Flow.RejectConsent(c.Request.Context(), req.RequestID)
	if err != nil {
		h.renderFlowError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request_id": request.ID,
		"stage":      request.Stage,
	})
}

type otpStartRequest struct {
	RequestID string `json:"request_id" binding:"required"`
	Email     string `json:"email"`
}

func (h Handler) startOTP(c *gin.Context) {
	var req otpStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	challenge, err := h.app.Identity.StartOTPChallenge(c.Request.Context(), identityapp.OTPStartRequest{
		RequestID: req.RequestID,
		Email:     req.Email,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request_id": challenge.AuthorizationRequestID,
		"email":      maskEmail(challenge.Email),
		"expires_at": challenge.ExpiresAt,
	})
}

type otpVerifyRequest struct {
	RequestID string `json:"request_id" binding:"required"`
	Email     string `json:"email" binding:"required"`
	Code      string `json:"code" binding:"required"`
}

func (h Handler) verifyOTP(c *gin.Context) {
	var req otpVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	account, _, session, request, err := h.app.Identity.VerifyOTPChallenge(c.Request.Context(), identityapp.OTPVerifyRequest{
		RequestID: req.RequestID,
		Email:     req.Email,
		Code:      req.Code,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	h.setSSOCookie(c, session.ID, session.ExpiresAt)
	c.JSON(http.StatusOK, gin.H{
		"request_id": request.ID,
		"stage":      request.Stage,
		"account": gin.H{
			"id":             account.ID,
			"display_name":   account.DisplayName,
			"email":          account.PrimaryVerifiedEmail,
			"email_verified": true,
		},
	})
}

func (h Handler) resendOTP(c *gin.Context) {
	var req otpStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	challenge, err := h.app.Identity.ResendOTPChallenge(c.Request.Context(), identityapp.OTPStartRequest{
		RequestID: req.RequestID,
		Email:     req.Email,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request_id": challenge.AuthorizationRequestID,
		"email":      maskEmail(challenge.Email),
		"expires_at": challenge.ExpiresAt,
	})
}

func (h Handler) logoutLocal(c *gin.Context) {
	chainID := c.Query("refresh_token_chain_id")
	if err := h.app.Flow.LogoutLocal(c.Request.Context(), chainID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	redirectTarget := h.postLogoutRedirect(c.Query("post_logout_redirect_uri"))
	c.Redirect(http.StatusFound, redirectTarget)
}

func (h Handler) logoutGlobal(c *gin.Context) {
	ssoSessionID, _ := c.Cookie(ssoCookieName)
	if ssoSessionID == "" {
		c.Redirect(http.StatusFound, h.postLogoutRedirect(c.Query("post_logout_redirect_uri")))
		return
	}

	if err := h.app.Flow.LogoutGlobal(c.Request.Context(), ssoSessionID, nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	h.clearSSOCookie(c)
	c.Redirect(http.StatusFound, h.postLogoutRedirect(c.Query("post_logout_redirect_uri")))
}

func (h Handler) setSSOCookie(c *gin.Context, value string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(ssoCookieName, value, maxAge, "/", "", false, true)
}

func (h Handler) clearSSOCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(ssoCookieName, "", -1, "/", "", false, true)
}

func (h Handler) postLogoutRedirect(candidate string) string {
	if candidate == "" {
		return strings.TrimRight(h.cfg.AuthUIBaseURL, "/") + "/logout"
	}
	if _, err := url.ParseRequestURI(candidate); err != nil {
		return strings.TrimRight(h.cfg.AuthUIBaseURL, "/") + "/logout"
	}
	return candidate
}

func (h Handler) renderLookupError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
}

func (h Handler) renderFlowError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, flowapp.ErrAuthorizationRequestExpired):
		c.JSON(http.StatusGone, gin.H{"error": "expired_request"})
	case errors.Is(err, flowapp.ErrAuthorizationRequestInvalidStage):
		c.JSON(http.StatusConflict, gin.H{"error": "invalid_stage"})
	default:
		h.renderLookupError(c, err)
	}
}

func stringPtr(value string) *string {
	return &value
}

func optionalStringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func maskEmail(value string) string {
	parts := strings.Split(value, "@")
	if len(parts) != 2 || parts[0] == "" {
		return value
	}

	local := parts[0]
	if len(local) <= 2 {
		return local[:1] + "*" + "@" + parts[1]
	}

	return local[:1] + strings.Repeat("*", len(local)-2) + local[len(local)-1:] + "@" + parts[1]
}
