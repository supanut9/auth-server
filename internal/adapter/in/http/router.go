package http

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/application"
	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	identityapp "github.com/supanut9/auth-server/internal/application/identity"
	tokenapp "github.com/supanut9/auth-server/internal/application/token"
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
	router.GET("/v1/oauth2/authorize", handler.authorize)
	router.POST("/v1/oauth2/token", handler.token)
	router.POST("/v1/oauth2/revoke", handler.revoke)
	router.POST("/v1/oauth2/introspect", handler.introspect)
	router.GET("/v1/oidc/userinfo", handler.userInfo)

	auth := router.Group("/v1/auth")
	auth.GET("/requests/:requestID", handler.getAuthorizationRequest)
	auth.POST("/login/google", handler.startGoogleLogin)
	auth.POST("/login/github", handler.startGitHubLogin)
	auth.GET("/login/callback/google", handler.handleGoogleCallback)
	auth.GET("/login/callback/github", handler.handleGitHubCallback)
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

func (h Handler) authorize(c *gin.Context) {
	responseType := c.Query("response_type")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := splitProtocolList(c.Query("scope"))
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.DefaultQuery("code_challenge_method", "plain")

	client, clientErr := h.app.Clients.FindByClientID(c.Request.Context(), clientID)
	if clientErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if responseType != "code" {
		h.redirectOAuthError(c, redirectURI, state, "unsupported_response_type", "response_type must be code")
		return
	}
	if redirectURI == "" || !containsValue(splitProtocolList(client.RedirectURIs), redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri is invalid"})
		return
	}
	if state == "" {
		h.redirectOAuthError(c, redirectURI, state, "invalid_request", "state is required")
		return
	}
	if !scopeSubset(scope, splitProtocolList(client.AllowedScopes)) {
		h.redirectOAuthError(c, redirectURI, state, "invalid_scope", "requested scopes are not allowed")
		return
	}
	if containsValue(scope, "openid") && nonce == "" {
		h.redirectOAuthError(c, redirectURI, state, "invalid_request", "nonce is required for openid")
		return
	}
	if client.ClientType == "public" && codeChallenge == "" {
		h.redirectOAuthError(c, redirectURI, state, "invalid_request", "code_challenge is required for public clients")
		return
	}

	var accountID *string
	var ssoSessionID *string
	authTime := time.Now().UTC()
	if session, err := h.currentSSOSession(c.Request.Context(), c); err == nil {
		accountID = stringPtr(session.AccountID)
		ssoSessionID = stringPtr(session.ID)
		authTime = session.AuthenticatedAt
	}

	request, err := h.app.Flow.StartAuthorization(c.Request.Context(), flowapp.StartAuthorizationRequest{
		ClientID:                client.ClientID,
		RedirectURI:             redirectURI,
		RequestedScopes:         scope,
		State:                   state,
		Nonce:                   optionalStringPtr(nonce),
		PKCECodeChallenge:       codeChallenge,
		PKCECodeChallengeMethod: codeChallengeMethod,
		AccountID:               accountID,
		SSOSessionID:            ssoSessionID,
	})
	if err != nil {
		h.redirectOAuthError(c, redirectURI, state, "server_error", err.Error())
		return
	}

	switch request.Stage {
	case domain.AuthorizationStageAuthorizationReady:
		codeValue, _, err := h.app.Flow.IssueAuthorizationCode(c.Request.Context(), flowapp.IssueAuthorizationCodeRequest{
			RequestID: request.ID,
			AuthTime:  authTime,
		})
		if err != nil {
			h.redirectOAuthError(c, redirectURI, state, "server_error", err.Error())
			return
		}
		h.redirectAuthorizationSuccess(c, redirectURI, codeValue, state)
	case domain.AuthorizationStageConsentRequired:
		c.Redirect(http.StatusFound, strings.TrimRight(h.cfg.AuthUIBaseURL, "/")+"/consent?request_id="+url.QueryEscape(request.ID))
	default:
		c.Redirect(http.StatusFound, strings.TrimRight(h.cfg.AuthUIBaseURL, "/")+"/login?request_id="+url.QueryEscape(request.ID))
	}
}

func (h Handler) token(c *gin.Context) {
	clientID, clientSecret := h.clientCredentials(c)
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}

	grantType := c.PostForm("grant_type")
	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeToken(c, clientID, clientSecret)
	case "refresh_token":
		h.handleRefreshToken(c, clientID, clientSecret)
	case "client_credentials":
		h.handleClientCredentials(c, clientID, clientSecret)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func (h Handler) revoke(c *gin.Context) {
	clientID, clientSecret := h.clientCredentials(c)
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}
	client, ok := h.authenticateClient(c, clientID, clientSecret, false)
	if !ok {
		return
	}

	tokenValue := c.PostForm("token")
	_, tokenHash, err := hashOpaqueToken(tokenValue)
	if err != nil {
		c.Status(http.StatusOK)
		return
	}
	refreshToken, err := h.app.RefreshTokens.FindByTokenHash(c.Request.Context(), tokenHash)
	if err == nil {
		chain, chainErr := h.app.RefreshChains.FindByID(c.Request.Context(), refreshToken.RefreshTokenChainID)
		if chainErr == nil && chain.ClientID == client.ClientID {
			_ = h.app.RefreshTokens.RevokeByChainID(c.Request.Context(), chain.ID)
			_ = h.app.RefreshChains.RevokeByID(c.Request.Context(), chain.ID)
		}
	}
	c.Status(http.StatusOK)
}

func (h Handler) introspect(c *gin.Context) {
	clientID, clientSecret := h.clientCredentials(c)
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}
	_, ok := h.authenticateClient(c, clientID, clientSecret, true)
	if !ok {
		return
	}

	tokenValue := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")
	if tokenTypeHint == "refresh_token" {
		h.introspectRefreshToken(c, tokenValue)
		return
	}
	h.introspectAccessToken(c, tokenValue)
}

func (h Handler) userInfo(c *gin.Context) {
	rawToken := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer"))
	if rawToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	claims, err := h.app.Verifier.Verify(rawToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	subject := stringClaim(claims, "sub")
	if subject == "" || subject == stringClaim(claims, "client_id") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	account, err := h.app.Accounts.FindByID(c.Request.Context(), subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	scopeSet := make(map[string]struct{})
	for _, scope := range splitProtocolList(stringClaim(claims, "scope")) {
		scopeSet[scope] = struct{}{}
	}

	response := gin.H{"sub": account.ID}
	if _, ok := scopeSet["email"]; ok {
		response["email"] = account.PrimaryVerifiedEmail
		response["email_verified"] = true
	}
	if _, ok := scopeSet["profile"]; ok {
		response["name"] = account.DisplayName
		response["picture"] = account.AvatarURL
	}

	c.JSON(http.StatusOK, response)
}

func (h Handler) handleAuthorizationCodeToken(c *gin.Context, clientID string, clientSecret string) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	client, ok := h.authenticateClient(c, clientID, clientSecret, false)
	if !ok {
		return
	}

	authorizationCode, err := h.app.Flow.ConsumeAuthorizationCode(c.Request.Context(), flowapp.ConsumeAuthorizationCodeRequest{
		Code:        code,
		ClientID:    client.ClientID,
		RedirectURI: redirectURI,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if !validatePKCE(authorizationCode.PKCECodeChallengeMethod, authorizationCode.PKCECodeChallenge, codeVerifier) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "pkce validation failed"})
		return
	}

	account, err := h.app.Accounts.FindByID(c.Request.Context(), authorizationCode.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	tokens, err := h.app.Token.IssueUserTokens(c.Request.Context(), tokenapp.UserTokenRequest{
		AccountID:       account.ID,
		ClientID:        client.ClientID,
		Scope:           splitProtocolList(authorizationCode.GrantedScopes),
		SSOSessionID:    derefString(authorizationCode.SSOSessionID),
		DeviceSessionID: authorizationCode.ID,
		AuthTime:        authorizationCode.AuthTime,
		Email:           account.PrimaryVerifiedEmail,
		EmailVerified:   true,
		Name:            account.DisplayName,
		Picture:         account.AvatarURL,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"id_token":      tokens.IDToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"expires_in":    tokens.ExpiresIn,
		"scope":         tokens.Scope,
	})
}

func (h Handler) handleRefreshToken(c *gin.Context, clientID string, clientSecret string) {
	client, ok := h.authenticateClient(c, clientID, clientSecret, false)
	if !ok {
		return
	}

	tokens, err := h.app.Token.RefreshUserTokens(c.Request.Context(), tokenapp.RefreshTokenRequest{
		ClientID:     client.ClientID,
		RefreshToken: c.PostForm("refresh_token"),
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"expires_in":    tokens.ExpiresIn,
		"scope":         tokens.Scope,
	})
}

func (h Handler) handleClientCredentials(c *gin.Context, clientID string, clientSecret string) {
	client, ok := h.authenticateClient(c, clientID, clientSecret, true)
	if !ok {
		return
	}

	scope := splitProtocolList(c.PostForm("scope"))
	if containsValue(scope, "openid") || containsValue(scope, "email") || containsValue(scope, "profile") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		return
	}
	if !scopeSubset(scope, splitProtocolList(client.AllowedScopes)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		return
	}

	tokens, err := h.app.Token.IssueClientCredentialsToken(c.Request.Context(), tokenapp.ClientCredentialsTokenRequest{
		ClientID: client.ClientID,
		Scope:    scope,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": tokens.AccessToken,
		"token_type":   tokens.TokenType,
		"expires_in":   tokens.ExpiresIn,
		"scope":        tokens.Scope,
	})
}

func (h Handler) introspectAccessToken(c *gin.Context, tokenValue string) {
	claims, err := h.app.Verifier.Verify(tokenValue)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	exp, _ := claims["exp"].(float64)
	if exp > 0 && time.Now().UTC().Unix() >= int64(exp) {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	response := gin.H{
		"active":     true,
		"scope":      stringClaim(claims, "scope"),
		"client_id":  stringClaim(claims, "client_id"),
		"sub":        stringClaim(claims, "sub"),
		"token_type": "Bearer",
	}
	if exp > 0 {
		response["exp"] = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		response["iat"] = int64(iat)
	}
	if aud, ok := claims["aud"]; ok {
		response["aud"] = aud
	}

	c.JSON(http.StatusOK, response)
}

func (h Handler) introspectRefreshToken(c *gin.Context, tokenValue string) {
	_, tokenHash, err := hashOpaqueToken(tokenValue)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	tokenRecord, err := h.app.RefreshTokens.FindByTokenHash(c.Request.Context(), tokenHash)
	if err != nil || tokenRecord.RevokedAt != nil || tokenRecord.UsedAt != nil || time.Now().UTC().After(tokenRecord.ExpiresAt) {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	chain, err := h.app.RefreshChains.FindByID(c.Request.Context(), tokenRecord.RefreshTokenChainID)
	if err != nil || chain.RevokedAt != nil || chain.Status != domain.RefreshTokenChainStatusActive {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active":     true,
		"scope":      chain.Scope,
		"client_id":  chain.ClientID,
		"sub":        chain.AccountID,
		"exp":        chain.AbsoluteExpiresAt.Unix(),
		"iat":        tokenRecord.IssuedAt.Unix(),
		"token_type": "refresh_token",
	})
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

type providerLoginStartRequest struct {
	RequestID string `json:"request_id" binding:"required"`
}

func (h Handler) startGoogleLogin(c *gin.Context) {
	h.startProviderLogin(c, "google")
}

func (h Handler) startGitHubLogin(c *gin.Context) {
	h.startProviderLogin(c, "github")
}

func (h Handler) startProviderLogin(c *gin.Context, providerName string) {
	var req providerLoginStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	request, err := h.app.Requests.FindByID(c.Request.Context(), req.RequestID)
	if err != nil {
		h.renderLookupError(c, err)
		return
	}
	if _, ok := h.app.Providers[providerName]; !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "provider_unavailable"})
		return
	}

	if _, err := h.app.Flow.MarkProviderRedirect(c.Request.Context(), request.ID); err != nil {
		h.renderFlowError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": h.providerAuthorizationURL(providerName, request.ID),
	})
}

func (h Handler) handleGoogleCallback(c *gin.Context) {
	h.handleProviderCallback(c, "google")
}

func (h Handler) handleGitHubCallback(c *gin.Context) {
	h.handleProviderCallback(c, "github")
}

func (h Handler) handleProviderCallback(c *gin.Context, providerName string) {
	requestID := c.Query("state")
	code := c.Query("code")
	if requestID == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	provider, ok := h.app.Providers[providerName]
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "provider_unavailable"})
		return
	}

	profile, err := provider.ExchangeAuthorizationCode(c.Request.Context(), code, h.providerRedirectURI(providerName))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "provider_error", "error_description": err.Error()})
		return
	}

	_, _, session, request, err := h.app.Identity.HandleProviderLogin(c.Request.Context(), identityapp.ProviderLoginRequest{
		RequestID:         requestID,
		ProviderName:      providerName,
		ProviderAccountID: profile.AccountID,
		Email:             profile.Email,
		EmailVerified:     profile.EmailVerified,
		DisplayName:       profile.DisplayName,
		AvatarURL:         profile.AvatarURL,
	})
	if err != nil {
		if errors.Is(err, identityapp.ErrProviderEmailVerificationRequired) {
			c.Redirect(http.StatusFound, strings.TrimRight(h.cfg.AuthUIBaseURL, "/")+"/otp?request_id="+url.QueryEscape(requestID))
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	h.setSSOCookie(c, session.ID, session.ExpiresAt)
	h.redirectPostAuthentication(c, request, session.AuthenticatedAt)
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

func (h Handler) redirectPostAuthentication(c *gin.Context, request domain.AuthorizationRequest, authTime time.Time) {
	switch request.Stage {
	case domain.AuthorizationStageAuthorizationReady:
		codeValue, _, err := h.app.Flow.IssueAuthorizationCode(c.Request.Context(), flowapp.IssueAuthorizationCodeRequest{
			RequestID: request.ID,
			AuthTime:  authTime,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		h.redirectAuthorizationSuccess(c, request.RedirectURI, codeValue, request.State)
	case domain.AuthorizationStageConsentRequired:
		c.Redirect(http.StatusFound, strings.TrimRight(h.cfg.AuthUIBaseURL, "/")+"/consent?request_id="+url.QueryEscape(request.ID))
	default:
		c.Redirect(http.StatusFound, strings.TrimRight(h.cfg.AuthUIBaseURL, "/")+"/login?request_id="+url.QueryEscape(request.ID))
	}
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

func (h Handler) authenticateClient(c *gin.Context, clientID string, clientSecret string, confidentialOnly bool) (domain.OAuthClient, bool) {
	client, err := h.app.Clients.FindByClientID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return domain.OAuthClient{}, false
	}

	if confidentialOnly && client.ClientType != "confidential" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized_client"})
		return domain.OAuthClient{}, false
	}

	if client.ClientType == "confidential" {
		if !matchSecret(client.ClientSecretHash, clientSecret) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return domain.OAuthClient{}, false
		}
	}

	return client, true
}

func (h Handler) currentSSOSession(ctx context.Context, c *gin.Context) (domain.SSOSession, error) {
	cookieValue, err := c.Cookie(ssoCookieName)
	if err != nil {
		return domain.SSOSession{}, err
	}

	session, err := h.app.SSOSessions.FindByID(ctx, cookieValue)
	if err != nil {
		return domain.SSOSession{}, err
	}
	if session.Status != domain.SSOSessionStatusActive || time.Now().UTC().After(session.ExpiresAt) || session.RevokedAt != nil {
		return domain.SSOSession{}, fmt.Errorf("inactive sso session")
	}
	return session, nil
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

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func containsValue(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func splitProtocolList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\t'
	})
	values := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		values = append(values, trimmed)
	}
	return values
}

func scopeSubset(requested []string, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowedSet[item] = struct{}{}
	}
	for _, item := range requested {
		if _, ok := allowedSet[item]; !ok {
			return false
		}
	}
	return true
}

func validatePKCE(method string, challenge string, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	if verifier == "" {
		return false
	}
	switch method {
	case "", "plain":
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(encoded)) == 1
	default:
		return false
	}
}

func matchSecret(stored string, provided string) bool {
	if stored == "" || provided == "" {
		return false
	}
	if strings.HasPrefix(stored, "sha256:") {
		sum := sha256.Sum256([]byte(provided))
		encoded := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(stored, "sha256:")), []byte(encoded)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}

func hashOpaqueToken(value string) (string, string, error) {
	if value == "" {
		return "", "", fmt.Errorf("empty token")
	}
	sum := sha256.Sum256([]byte(value))
	return value, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (h Handler) clientCredentials(c *gin.Context) (string, string) {
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		return "", ""
	}
	return username, password
}

func (h Handler) providerAuthorizationURL(providerName string, requestID string) string {
	callback := h.providerRedirectURI(providerName)
	values := url.Values{}
	values.Set("client_id", h.providerClientID(providerName))
	values.Set("redirect_uri", callback)
	values.Set("response_type", "code")
	values.Set("state", requestID)

	switch providerName {
	case "google":
		values.Set("scope", "openid email profile")
		values.Set("access_type", "offline")
		return "https://accounts.google.com/o/oauth2/v2/auth?" + values.Encode()
	case "github":
		values.Set("scope", "read:user user:email")
		return "https://github.com/login/oauth/authorize?" + values.Encode()
	default:
		return ""
	}
}

func (h Handler) providerClientID(providerName string) string {
	switch providerName {
	case "google":
		return h.cfg.GoogleClientID
	case "github":
		return h.cfg.GitHubClientID
	default:
		return ""
	}
}

func (h Handler) providerRedirectURI(providerName string) string {
	switch providerName {
	case "google":
		return h.cfg.GoogleRedirectURL
	case "github":
		return h.cfg.GitHubRedirectURL
	default:
		return ""
	}
}

func (h Handler) redirectOAuthError(c *gin.Context, redirectURI string, state string, errorCode string, description string) {
	target, err := url.Parse(redirectURI)
	if err != nil || redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": description,
		})
		return
	}
	query := target.Query()
	query.Set("error", errorCode)
	if description != "" {
		query.Set("error_description", description)
	}
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, target.String())
}

func (h Handler) redirectAuthorizationSuccess(c *gin.Context, redirectURI string, code string, state string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	query := target.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, target.String())
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

func stringClaim(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}
