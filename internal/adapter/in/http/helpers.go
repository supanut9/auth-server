package http

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// csrfCookieName is the double-submit-cookie used by stateless flow endpoints
// (consent accept/reject). The cookie is readable from JS (no HttpOnly) so the
// UI can echo it in the request body; server compares cookie vs body.
const csrfCookieName = "auth_csrf"

// csrfTokenTTL bounds how long an issued CSRF token stays valid. The cookie's
// Max-Age tracks this; we also re-issue on every /v1/auth/csrf call so a single
// token lifetime is short.
const csrfTokenTTL = 30 * time.Minute

// clientPublicInfo returns the non-secret fields of an OAuth client. Used by the
// stateless auth-ui to render the consent / login screen header when only the
// client_id is known from the URL query.
func (h Handler) clientPublicInfo(c *gin.Context) {
	clientID := strings.TrimSpace(c.Param("clientID"))
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	client, err := h.app.Clients.FindByClientID(c.Request.Context(), clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"client_id":      client.ClientID,
		"display_name":   client.DisplayName,
		"logo_uri":       client.LogoURI,
		"allowed_scopes": splitProtocolList(client.AllowedScopes),
	})
}

// currentUser returns the signed-in subject from the SSO session cookie. Used
// by the stateless auth-ui to render account hints ("Continuing as Foo") on
// login / consent. Returns 401 when no active session is bound to this browser.
func (h Handler) currentUser(c *gin.Context) {
	session, err := h.currentSSOSession(c.Request.Context(), c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}
	account, err := h.app.Accounts.FindByID(c.Request.Context(), session.AccountID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"account_id":    account.ID,
		"display_name":  account.DisplayName,
		"email":         account.PrimaryVerifiedEmail,
		"login_method":  session.LoginMethod,
		"authenticated": true,
		"session": gin.H{
			"id":               session.ID,
			"expires_at":       session.ExpiresAt,
			"authenticated_at": session.AuthenticatedAt,
		},
	})
}

// csrfToken mints a fresh CSRF token using the double-submit-cookie pattern.
// Sets the token as a non-HttpOnly cookie so JS can read it back; the same
// token is returned in the response body. Action handlers compare cookie vs
// body before accepting state-changing requests.
//
// Note: the cookie is intentionally NOT HttpOnly — the UI needs to read it to
// echo it back. This is fine for CSRF because the secret is the *unforgeability*
// of the cookie domain pairing, not the cookie contents.
func (h Handler) csrfToken(c *gin.Context) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	maxAge := int(csrfTokenTTL.Seconds())

	c.SetSameSite(sameSiteMode(h.cfg.SSOCookieSameSite))
	c.SetCookie(csrfCookieName, token, maxAge, "/", h.cfg.SSOCookieDomain, h.cfg.SSOCookieSecure, false)

	c.JSON(http.StatusOK, gin.H{
		"csrf_token": token,
		"expires_in": maxAge,
	})
}

// verifyCSRF returns nil iff the request carries a non-empty CSRF token that
// matches the auth_csrf cookie. Action handlers that mutate user state call
// this before reading the rest of the request.
func (h Handler) verifyCSRF(c *gin.Context, suppliedToken string) error {
	if suppliedToken == "" {
		return errors.New("missing csrf token")
	}
	cookieToken, err := c.Cookie(csrfCookieName)
	if err != nil {
		return errors.New("missing csrf cookie")
	}
	if subtle.ConstantTimeCompare([]byte(suppliedToken), []byte(cookieToken)) != 1 {
		return errors.New("csrf token mismatch")
	}
	return nil
}
