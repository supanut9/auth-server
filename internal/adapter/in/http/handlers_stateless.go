package http

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/application/oauth"
)

// authorizeStateless implements the Shape-B variant of /v1/oauth2/authorize:
// no AuthorizationRequest record is created. The OAuth params travel in the
// URL across stages; the server validates them on every action endpoint.
//
// Stage-deciding rules:
//   - SSO + consent already granted: issue code directly, redirect to client.
//   - SSO without consent: redirect to auth-ui /consent with the original
//     query verbatim.
//   - No SSO and prompt=none: bounce back to the client with login_required.
//   - No SSO otherwise: redirect to auth-ui /login with the original query.
func (h Handler) authorizeStateless(c *gin.Context) {
	prompt := c.Query("prompt")

	validated, oauthErr := oauth.Validate(c.Request.Context(), h.app.Clients, oauth.Request{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.DefaultQuery("code_challenge_method", ""),
		Prompt:              prompt,
	})
	if oauthErr != nil {
		if oauthErr.Recoverable {
			h.redirectOAuthError(c, c.Query("redirect_uri"), c.Query("state"), oauthErr.Code, oauthErr.Description)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
		return
	}

	redirectURI := validated.Request.RedirectURI
	state := validated.Request.State

	// Try to reuse an active SSO session unless the caller forbade it.
	var accountID *string
	var ssoSessionID *string
	authTime := time.Now().UTC()
	if prompt != "login" {
		if session, err := h.currentSSOSession(c.Request.Context(), c); err == nil {
			accountID = stringPtr(session.AccountID)
			ssoSessionID = stringPtr(session.ID)
			authTime = session.AuthenticatedAt
		}
	}

	if prompt == "none" && accountID == nil {
		h.redirectOAuthError(c, redirectURI, state, "login_required", "no active SSO session")
		return
	}

	originalQuery := preservedAuthorizeQuery(c)

	if accountID != nil {
		if h.app.Flow.HasConsentForScopes(c.Request.Context(), *accountID, validated.Client.ClientID, validated.Scopes) {
			codeValue, _, err := h.app.Flow.IssueDirectCode(c.Request.Context(), flowapp.IssueDirectCodeRequest{
				AccountID:               *accountID,
				ClientID:                validated.Client.ClientID,
				SSOSessionID:            ssoSessionID,
				RedirectURI:             redirectURI,
				Scopes:                  validated.Scopes,
				PKCECodeChallenge:       validated.Request.CodeChallenge,
				PKCECodeChallengeMethod: validated.Request.CodeChallengeMethod,
				AuthTime:                authTime,
			})
			if err != nil {
				h.redirectOAuthError(c, redirectURI, state, "server_error", err.Error())
				return
			}
			h.redirectAuthorizationSuccess(c, redirectURI, codeValue, state)
			return
		}

		if prompt == "none" {
			h.redirectOAuthError(c, redirectURI, state, "consent_required", "consent required")
			return
		}
		c.Redirect(http.StatusFound, h.authUIRoute("/consent", originalQuery))
		return
	}

	// No SSO session yet. Send to the login screen with the original OAuth query.
	c.Redirect(http.StatusFound, h.authUIRoute("/login", originalQuery))
}

// preservedAuthorizeQuery returns the canonical OAuth query string we want to
// echo onto auth-ui URLs. We intentionally re-serialise from the validated
// request rather than echo the raw c.Request.URL.RawQuery so that any extra
// non-OAuth params the caller tacked on are dropped before the user sees the
// URL.
func preservedAuthorizeQuery(c *gin.Context) url.Values {
	q := url.Values{}
	addIfPresent(q, "response_type", c.Query("response_type"))
	addIfPresent(q, "client_id", c.Query("client_id"))
	addIfPresent(q, "redirect_uri", c.Query("redirect_uri"))
	addIfPresent(q, "scope", c.Query("scope"))
	addIfPresent(q, "state", c.Query("state"))
	addIfPresent(q, "nonce", c.Query("nonce"))
	addIfPresent(q, "code_challenge", c.Query("code_challenge"))
	addIfPresent(q, "code_challenge_method", c.Query("code_challenge_method"))
	addIfPresent(q, "prompt", c.Query("prompt"))
	return q
}

func addIfPresent(q url.Values, key, value string) {
	if value == "" {
		return
	}
	q.Set(key, value)
}

// authUIRoute builds an auth-ui URL with the original OAuth query string. Used
// by every stateless handler that bounces the user from auth-server to an
// auth-ui screen.
func (h Handler) authUIRoute(path string, query url.Values) string {
	base := strings.TrimRight(h.cfg.AuthUIBaseURL, "/") + path
	if len(query) == 0 {
		return base
	}
	return base + "?" + query.Encode()
}
