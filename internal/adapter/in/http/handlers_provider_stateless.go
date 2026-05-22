package http

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	identityapp "github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/application/oauth"
)

// authorizeRequestBody is the canonical OAuth-param payload action handlers
// receive from auth-ui in the stateless flow. It mirrors the query string the
// browser carries and is re-validated on every call.
type authorizeRequestBody struct {
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	Scope               string `json:"scope" binding:"required"`
	State               string `json:"state" binding:"required"`
	ResponseType        string `json:"response_type"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Prompt              string `json:"prompt"`
}

func (b authorizeRequestBody) toOAuthRequest() oauth.Request {
	rt := b.ResponseType
	if rt == "" {
		rt = "code"
	}
	return oauth.Request{
		ResponseType:        rt,
		ClientID:            b.ClientID,
		RedirectURI:         b.RedirectURI,
		Scope:               b.Scope,
		State:               b.State,
		Nonce:               b.Nonce,
		CodeChallenge:       b.CodeChallenge,
		CodeChallengeMethod: b.CodeChallengeMethod,
		Prompt:              b.Prompt,
	}
}

func (b authorizeRequestBody) toQuery() url.Values {
	q := url.Values{}
	addIfPresent(q, "response_type", b.ResponseType)
	addIfPresent(q, "client_id", b.ClientID)
	addIfPresent(q, "redirect_uri", b.RedirectURI)
	addIfPresent(q, "scope", b.Scope)
	addIfPresent(q, "state", b.State)
	addIfPresent(q, "nonce", b.Nonce)
	addIfPresent(q, "code_challenge", b.CodeChallenge)
	addIfPresent(q, "code_challenge_method", b.CodeChallengeMethod)
	addIfPresent(q, "prompt", b.Prompt)
	return q
}

// startProviderLoginStateless validates the OAuth params, signs them into an
// envelope (used as Google/GitHub `state`), and returns the provider's
// authorization URL for the UI to redirect to.
func (h Handler) startProviderLoginStateless(c *gin.Context, providerName string) {
	var body authorizeRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	validated, oauthErr := oauth.Validate(c.Request.Context(), h.app.Clients, body.toOAuthRequest())
	if oauthErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
		return
	}

	if _, ok := h.app.Providers[providerName]; !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "provider_unavailable"})
		return
	}

	envelopeToken, err := h.app.Envelope.Sign(oauth.Envelope{
		Provider:            providerName,
		ClientID:            validated.Client.ClientID,
		RedirectURI:         validated.Request.RedirectURI,
		Scope:               validated.Request.Scope,
		State:               validated.Request.State,
		Nonce:               validated.Request.Nonce,
		CodeChallenge:       validated.Request.CodeChallenge,
		CodeChallengeMethod: validated.Request.CodeChallengeMethod,
		Prompt:              validated.Request.Prompt,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": h.providerAuthorizationURLWithState(providerName, envelopeToken),
	})
}

func (h Handler) startGoogleLoginStateless(c *gin.Context) {
	h.startProviderLoginStateless(c, "google")
}

func (h Handler) startGitHubLoginStateless(c *gin.Context) {
	h.startProviderLoginStateless(c, "github")
}

// providerAuthorizationURLWithState is the stateless counterpart of
// providerAuthorizationURL — instead of stuffing the AuthorizationRequest.ID
// into `state`, we use the signed envelope JWT.
func (h Handler) providerAuthorizationURLWithState(providerName, state string) string {
	values := url.Values{}
	values.Set("client_id", h.providerClientID(providerName))
	values.Set("redirect_uri", h.providerRedirectURI(providerName))
	values.Set("response_type", "code")
	values.Set("state", state)
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

// handleProviderCallbackStateless verifies the envelope from the `state`
// parameter, exchanges the provider code, and signs the user in. Final
// redirect goes either directly to the client (if consent is already granted)
// or to auth-ui /consent (with the original OAuth params preserved in the URL).
func (h Handler) handleProviderCallbackStateless(c *gin.Context, providerName string) {
	stateToken := c.Query("state")
	code := c.Query("code")
	if stateToken == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	envelope, err := h.app.Envelope.Verify(stateToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_state", "error_description": err.Error()})
		return
	}
	if envelope.Provider != providerName {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_state", "error_description": "state provider mismatch"})
		return
	}

	provider, ok := h.app.Providers[providerName]
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "provider_unavailable"})
		return
	}

	// Re-validate OAuth params from the envelope against the current client
	// registration — defends against client config changes between sign and
	// verify, and gives us a canonicalised scope list.
	validated, oauthErr := oauth.Validate(c.Request.Context(), h.app.Clients, oauth.Request{
		ResponseType:        "code",
		ClientID:            envelope.ClientID,
		RedirectURI:         envelope.RedirectURI,
		Scope:               envelope.Scope,
		State:               envelope.State,
		Nonce:               envelope.Nonce,
		CodeChallenge:       envelope.CodeChallenge,
		CodeChallengeMethod: envelope.CodeChallengeMethod,
		Prompt:              envelope.Prompt,
	})
	if oauthErr != nil {
		h.redirectOAuthError(c, envelope.RedirectURI, envelope.State, oauthErr.Code, oauthErr.Description)
		return
	}

	profile, err := provider.ExchangeAuthorizationCode(c.Request.Context(), code, h.providerRedirectURI(providerName))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "provider_error", "error_description": err.Error()})
		return
	}

	result, err := h.app.Identity.HandleProviderLoginStateless(c.Request.Context(), identityapp.ProviderLoginStatelessRequest{
		ProviderName:      providerName,
		ProviderAccountID: profile.AccountID,
		Email:             profile.Email,
		EmailVerified:     profile.EmailVerified,
		DisplayName:       profile.DisplayName,
		AvatarURL:         profile.AvatarURL,
	})
	if err != nil {
		if errors.Is(err, identityapp.ErrProviderEmailVerificationRequired) {
			// Rare path: provider returned unverified email. Send the user back
			// to the login screen so they can use email OTP from scratch.
			h.redirectAuthUIError(c, validated.Request, "provider_email_unverified", "provider did not return a verified email; try email OTP")
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	h.setSSOCookie(c, result.Session.ID, result.Session.ExpiresAt)
	h.redirectPostAuthenticationStateless(c, validated, result.Session.ID, result.Session.AuthenticatedAt)
}

func (h Handler) handleGoogleCallbackStateless(c *gin.Context) {
	h.handleProviderCallbackStateless(c, "google")
}

func (h Handler) handleGitHubCallbackStateless(c *gin.Context) {
	h.handleProviderCallbackStateless(c, "github")
}

// redirectPostAuthenticationStateless decides where the user goes after a
// fresh authentication: directly to the client if consent is already granted,
// otherwise to auth-ui /consent with the OAuth params preserved.
func (h Handler) redirectPostAuthenticationStateless(c *gin.Context, validated oauth.Validated, sessionID string, authTime time.Time) {
	accountID := ""
	if session, err := h.currentSSOSession(c.Request.Context(), c); err == nil {
		accountID = session.AccountID
	}
	if accountID == "" {
		// fall back to a fresh lookup via cookie that we just set
		if session, err := h.app.SSOSessions.FindByID(c.Request.Context(), sessionID); err == nil {
			accountID = session.AccountID
		}
	}
	if accountID == "" {
		// Best-effort: should never happen since we just set the SSO cookie.
		c.Redirect(http.StatusFound, h.authUIRoute("/consent", oauthValuesFromValidated(validated)))
		return
	}

	if h.app.Flow.HasConsentForScopes(c.Request.Context(), accountID, validated.Client.ClientID, validated.Scopes) {
		ssoSessionID := sessionID
		codeValue, _, err := h.app.Flow.IssueDirectCode(c.Request.Context(), flowapp.IssueDirectCodeRequest{
			AccountID:               accountID,
			ClientID:                validated.Client.ClientID,
			SSOSessionID:            &ssoSessionID,
			RedirectURI:             validated.Request.RedirectURI,
			Scopes:                  validated.Scopes,
			PKCECodeChallenge:       validated.Request.CodeChallenge,
			PKCECodeChallengeMethod: validated.Request.CodeChallengeMethod,
			AuthTime:                authTime,
		})
		if err != nil {
			h.redirectOAuthError(c, validated.Request.RedirectURI, validated.Request.State, "server_error", err.Error())
			return
		}
		h.redirectAuthorizationSuccess(c, validated.Request.RedirectURI, codeValue, validated.Request.State)
		return
	}

	c.Redirect(http.StatusFound, h.authUIRoute("/consent", oauthValuesFromValidated(validated)))
}

// redirectAuthUIError redirects to auth-ui /error preserving OAuth params plus
// an error code, used for non-protocol-spec failures we want the user to see in
// the UI rather than as a JSON response.
func (h Handler) redirectAuthUIError(c *gin.Context, req oauth.Request, errCode, errDescription string) {
	q := oauthValuesFromRequest(req)
	q.Set("error", errCode)
	if errDescription != "" {
		q.Set("error_description", errDescription)
	}
	c.Redirect(http.StatusFound, h.authUIRoute("/error", q))
}

func oauthValuesFromValidated(v oauth.Validated) url.Values {
	return oauthValuesFromRequest(v.Request)
}

func oauthValuesFromRequest(r oauth.Request) url.Values {
	q := url.Values{}
	addIfPresent(q, "response_type", r.ResponseType)
	addIfPresent(q, "client_id", r.ClientID)
	addIfPresent(q, "redirect_uri", r.RedirectURI)
	addIfPresent(q, "scope", r.Scope)
	addIfPresent(q, "state", r.State)
	addIfPresent(q, "nonce", r.Nonce)
	addIfPresent(q, "code_challenge", r.CodeChallenge)
	addIfPresent(q, "code_challenge_method", r.CodeChallengeMethod)
	addIfPresent(q, "prompt", r.Prompt)
	return q
}

// helper kept here to avoid pulling strings into handlers_stateless.go.
var _ = strings.TrimSpace
