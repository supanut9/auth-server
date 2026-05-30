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
	tokenapp "github.com/supanut9/auth-server/internal/application/token"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
	"gorm.io/gorm"
)

const ssoCookieName = "auth_sso_session"

type Handler struct {
	cfg config.Config
	db  *gorm.DB
	app application.App
}

func CORSMiddleware(cfg config.Config) gin.HandlerFunc {
	allowedOrigin := strings.TrimRight(cfg.AuthUIBaseURL, "/")

	return func(c *gin.Context) {
		c.Header("Vary", "Origin")
		origin := strings.TrimRight(c.GetHeader("Origin"), "/")
		if origin == allowedOrigin {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func RegisterRoutes(router *gin.Engine, cfg config.Config, db *gorm.DB, app application.App) {
	handler := Handler{cfg: cfg, db: db, app: app}

	// 20 OTP-endpoint hits per IP per minute — enough headroom for legit users
	// to start/verify/resend several times, tight enough to neutralise
	// brute-force or email-bomb attempts. Per-challenge attempt + resend caps
	// inside the identity service catch the remaining slow attacks.
	otpLimiter := NewRateLimiter(time.Minute, 20)

	router.GET("/healthz", handler.healthz)
	router.GET("/readyz", handler.readyz)
	// /dev/callback is a debug echo used by dev OAuth providers — info leak in
	// production, so only mount it when we're not in prod.
	if !strings.EqualFold(cfg.AppEnv, "production") {
		router.GET("/dev/callback", handler.devCallback)
	}
	router.GET("/.well-known/openid-configuration", handler.openIDConfiguration)
	router.GET("/.well-known/jwks.json", handler.jwks)
	router.GET("/v1/oauth2/authorize", handler.authorizeStateless)
	router.POST("/v1/oauth2/token", handler.token)
	router.POST("/v1/oauth2/revoke", handler.revoke)
	router.POST("/v1/oauth2/introspect", handler.introspect)
	router.GET("/v1/oidc/userinfo", handler.userInfo)
	router.GET("/v1/clients/:clientID/public-info", handler.clientPublicInfo)

	auth := router.Group("/v1/auth")
	auth.GET("/me", handler.currentUser)
	auth.GET("/csrf", handler.csrfToken)
	auth.POST("/login/google", handler.startGoogleLoginStateless)
	auth.POST("/login/github", handler.startGitHubLoginStateless)
	auth.GET("/login/callback/google", handler.handleGoogleCallbackStateless)
	auth.GET("/login/callback/github", handler.handleGitHubCallbackStateless)
	auth.POST("/consent/accept", handler.acceptConsentStateless)
	auth.POST("/consent/reject", handler.rejectConsentStateless)
	otpMiddleware := OTPRateLimitMiddleware(otpLimiter)
	auth.POST("/otp/start", otpMiddleware, handler.startOTPStateless)
	auth.POST("/otp/verify", otpMiddleware, handler.verifyOTPStateless)
	auth.POST("/otp/resend", otpMiddleware, handler.resendOTPStateless)
	// INT-244: test-hint endpoint. Only mounted when not in production; the
	// handler itself also hard-refuses in production (defence in depth).
	if !strings.EqualFold(cfg.AppEnv, "production") {
		auth.GET("/otp/test-hint", handler.testOTPHint)
	}
	auth.GET("/logout", handler.logoutLocal)
	auth.GET("/logout/global", handler.logoutGlobal)

	support := router.Group("/v1/support", SupportAuthMiddleware(cfg))
	support.GET("/accounts/:accountID", handler.getSupportAccount)
	support.POST("/accounts/:accountID/sign-out", handler.signOutSupportAccount)
}

func (h Handler) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"app_name":   h.cfg.AppName,
		"request_id": requestIDFromContext(c),
	})
}

func (h Handler) readyz(c *gin.Context) {
	sqlDB, err := h.db.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "degraded",
			"error":  "database_unavailable",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "degraded",
			"error":  "database_unavailable",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"app_name":   h.cfg.AppName,
		"database":   "ready",
		"request_id": requestIDFromContext(c),
	})
}

func (h Handler) devCallback(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code":  c.Query("code"),
		"state": c.Query("state"),
		"error": c.Query("error"),
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
		"scopes_supported":                      []string{"openid", "email", "profile", "offline_access", "trading.read", "trading.write"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"prompt_values_supported":               []string{"login", "none"},
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

func (h Handler) token(c *gin.Context) {
	clientID, clientSecret := h.clientCredentials(c)
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}
	if clientSecret == "" {
		clientSecret = c.PostForm("client_secret")
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
	if clientSecret == "" {
		clientSecret = c.PostForm("client_secret")
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
	if clientSecret == "" {
		clientSecret = c.PostForm("client_secret")
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
	c.SetSameSite(sameSiteMode(h.cfg.SSOCookieSameSite))
	c.SetCookie(ssoCookieName, value, maxAge, "/", h.cfg.SSOCookieDomain, h.cfg.SSOCookieSecure, true)
}

func (h Handler) clearSSOCookie(c *gin.Context) {
	c.SetSameSite(sameSiteMode(h.cfg.SSOCookieSameSite))
	c.SetCookie(ssoCookieName, "", -1, "/", h.cfg.SSOCookieDomain, h.cfg.SSOCookieSecure, true)
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
	defaultTarget := strings.TrimRight(h.cfg.AuthUIBaseURL, "/") + "/logout"
	if candidate == "" {
		return defaultTarget
	}

	if sameOriginURL(candidate, h.cfg.AuthUIBaseURL) {
		return candidate
	}

	for _, allowedBase := range h.cfg.PostLogoutRedirectAllowlist {
		if sameOriginURL(candidate, allowedBase) {
			return candidate
		}
	}

	return defaultTarget
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

func sameSiteMode(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func sameOriginURL(candidate string, base string) bool {
	candidateURL, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return false
	}
	if candidateURL.Scheme == "" || candidateURL.Host == "" || baseURL.Scheme == "" || baseURL.Host == "" {
		return false
	}
	return strings.EqualFold(candidateURL.Scheme, baseURL.Scheme) && strings.EqualFold(candidateURL.Host, baseURL.Host)
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
	target, ok := h.oauthErrorURL(redirectURI, state, errorCode, description)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": description,
		})
		return
	}
	c.Redirect(http.StatusFound, target)
}

func (h Handler) redirectAuthorizationSuccess(c *gin.Context, redirectURI string, code string, state string) {
	target, ok := h.authorizationSuccessURL(redirectURI, code, state)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	c.Redirect(http.StatusFound, target)
}

func (h Handler) authorizationSuccessURL(redirectURI string, code string, state string) (string, bool) {
	target, err := url.Parse(redirectURI)
	if err != nil || redirectURI == "" {
		return "", false
	}
	query := target.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	return target.String(), true
}

func (h Handler) oauthErrorURL(redirectURI string, state string, errorCode string, description string) (string, bool) {
	target, err := url.Parse(redirectURI)
	if err != nil || redirectURI == "" {
		return "", false
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
	return target.String(), true
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
