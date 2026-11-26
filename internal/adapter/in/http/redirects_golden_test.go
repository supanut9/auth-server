package http

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/supanut9/auth-server/internal/application"
	"github.com/supanut9/auth-server/internal/application/oauth"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
)

type goldenCookieConfig struct {
	Secure   bool   `json:"sso_cookie_secure"`
	SameSite string `json:"sso_cookie_same_site"`
	Domain   string `json:"sso_cookie_domain"`
}

func (g goldenCookieConfig) handler() Handler {
	return Handler{cfg: config.Config{SSOCookieSecure: g.Secure, SSOCookieSameSite: g.SameSite, SSOCookieDomain: g.Domain}}
}

func TestGoldenCookies(t *testing.T) {
	type ssoCase struct {
		Name      string             `json:"name"`
		Config    goldenCookieConfig `json:"config"`
		Action    string             `json:"action"`
		Value     string             `json:"value,omitempty"`
		MaxAge    int                `json:"max_age"`
		SetCookie []string           `json:"set_cookie"`
	}
	const sessionID = "0195f0a2-0000-7000-8000-000000000001"
	inputs := []ssoCase{
		{Name: "default_lax_insecure_no_domain", Config: goldenCookieConfig{SameSite: "lax"}, Action: "set", Value: sessionID, MaxAge: 2592000},
		{Name: "secure_strict_domain", Config: goldenCookieConfig{Secure: true, SameSite: "strict", Domain: "auth.example.com"}, Action: "set", Value: sessionID, MaxAge: 86400},
		{Name: "secure_none_leading_dot_domain", Config: goldenCookieConfig{Secure: true, SameSite: "none", Domain: ".example.com"}, Action: "set", Value: sessionID, MaxAge: 3600},
		{Name: "empty_same_site_is_lax", Config: goldenCookieConfig{SameSite: ""}, Action: "set", Value: sessionID, MaxAge: 60},
		{Name: "unknown_same_site_is_lax", Config: goldenCookieConfig{SameSite: "bogus"}, Action: "set", Value: sessionID, MaxAge: 60},
		{Name: "ip_domain", Config: goldenCookieConfig{SameSite: "lax", Domain: "127.0.0.1"}, Action: "set", Value: sessionID, MaxAge: 60},
		{Name: "localhost_domain", Config: goldenCookieConfig{SameSite: "lax", Domain: "localhost"}, Action: "set", Value: sessionID, MaxAge: 60},
		{Name: "invalid_domain_dropped", Config: goldenCookieConfig{SameSite: "lax", Domain: "bad domain"}, Action: "set", Value: sessionID, MaxAge: 60},
		{Name: "value_needs_query_escape", Config: goldenCookieConfig{SameSite: "lax"}, Action: "set", Value: "a b+c/d=e;f,g\"h\\i~j*k@ü", MaxAge: 60},
		{Name: "expired_session_max_age_0", Config: goldenCookieConfig{Secure: true, SameSite: "lax", Domain: "auth.example.com"}, Action: "set", Value: sessionID, MaxAge: 0},
		{Name: "clear_insecure", Config: goldenCookieConfig{SameSite: "lax"}, Action: "clear", MaxAge: -1},
		{Name: "clear_secure_none_domain", Config: goldenCookieConfig{Secure: true, SameSite: "none", Domain: ".example.com"}, Action: "clear", MaxAge: -1},
	}
	var ssoCases []ssoCase
	for _, in := range inputs {
		h := in.Config.handler()
		c, rec := goldenContext(http.MethodGet, "/")
		switch {
		case in.Action == "clear":
			h.clearSSOCookie(c)
		case in.MaxAge > 0:
			// setSSOCookie derives Max-Age = int(time.Until(expiresAt).Seconds()),
			// truncating; +0.5s keeps the result exactly MaxAge.
			h.setSSOCookie(c, in.Value, time.Now().Add(time.Duration(in.MaxAge)*time.Second+500*time.Millisecond))
		default:
			h.setSSOCookie(c, in.Value, time.Now().Add(-time.Hour))
		}
		in.SetCookie = rec.Header().Values("Set-Cookie")
		ssoCases = append(ssoCases, in)
	}
	goldenSection(t, "cookies", "sso_cookie", map[string]any{
		"description": "auth_sso_session cookie (router.go setSSOCookie / clearSSOCookie via gin c.SetCookie -> net/http Cookie.String). value is url.QueryEscape'd (space -> '+'). set: Max-Age = int(time.Until(session.ExpiresAt).Seconds()) truncated, clamped to >= 0; Max-Age 0 omits the attribute entirely (session cookie!). clear: MaxAge -1 renders \"Max-Age=0\". Path=/, HttpOnly. Domain: leading '.' stripped; invalid domains are silently dropped (Go logs). SameSite from SSO_COOKIE_SAME_SITE: strict/none, anything else => Lax. No Expires attribute is ever sent. Attribute order: Name=Value; Path; Domain; Max-Age; HttpOnly; Secure; SameSite.",
		"cases":       ssoCases,
	})

	type csrfCase struct {
		Name     string             `json:"name"`
		Config   goldenCookieConfig `json:"config"`
		RawHex   string             `json:"random_raw_hex"`
		Token    string             `json:"token"`
		Response goldenResponse     `json:"response"`
	}
	var csrfCases []csrfCase
	for i, cfg := range []goldenCookieConfig{
		{SameSite: "lax"},
		{Secure: true, SameSite: "strict", Domain: "auth.example.com"},
		{Secure: true, SameSite: "none", Domain: ".example.com"},
	} {
		cryptotest.SetGlobalRandom(t, uint64(500+i))
		h := cfg.handler()
		c, rec := goldenContext(http.MethodGet, "/v1/auth/csrf")
		h.csrfToken(c)
		resp := goldenCapture(c, rec)
		var body struct {
			Token string `json:"csrf_token"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
			t.Fatalf("csrf body: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(body.Token)
		if err != nil || len(raw) != 32 || len(body.Token) != 43 {
			t.Fatalf("unexpected csrf token %q", body.Token)
		}
		csrfCases = append(csrfCases, csrfCase{
			Name:     cfg.SameSite + map[bool]string{true: "_secure", false: ""}[cfg.Secure],
			Config:   cfg,
			RawHex:   goldenHex(raw),
			Token:    body.Token,
			Response: resp,
		})
	}
	goldenSection(t, "cookies", "csrf_cookie", map[string]any{
		"description": "GET /v1/auth/csrf (helpers.go csrfToken): token = base64url_nopad(32 random bytes); cookie auth_csrf, Max-Age=1800, Path=/, NOT HttpOnly, Secure/SameSite/Domain from the SSO_COOKIE_* config; body {\"csrf_token\",\"expires_in\":1800} (sorted keys).",
		"cases":       csrfCases,
	})
}

func TestGoldenRedirects(t *testing.T) {
	const authUI = "https://auth-ui.example.com"
	h := Handler{cfg: config.Config{
		AuthUIBaseURL:               authUI + "/",
		PostLogoutRedirectAllowlist: []string{"https://trading.example.com", "https://language.example.com/some/path"},
		GoogleClientID:              "google-client-id.apps.googleusercontent.com",
		GoogleRedirectURL:           "https://auth.example.com/v1/auth/login/callback/google",
		GitHubClientID:              "Iv1.githubclientid",
		GitHubRedirectURL:           "https://auth.example.com/v1/auth/login/callback/github",
	}}

	// 1. Authorization success redirect.
	type successCase struct {
		Name        string         `json:"name"`
		RedirectURI string         `json:"redirect_uri"`
		Code        string         `json:"code"`
		State       string         `json:"state"`
		OK          bool           `json:"ok"`
		URL         string         `json:"url,omitempty"`
		Response    goldenResponse `json:"response"`
	}
	const code = "SplxlOBeZQQYbYS6WxSbIA-0123456789abcdefghij"
	successInputs := []successCase{
		{Name: "plain", RedirectURI: "https://app.example.com/callback", Code: code, State: "xyz"},
		{Name: "no_state", RedirectURI: "https://app.example.com/callback", Code: code},
		{Name: "existing_query_merged_and_sorted", RedirectURI: "https://app.example.com/cb?z=1&a=2&a=3", Code: code, State: "s"},
		{Name: "existing_code_and_state_replaced", RedirectURI: "https://app.example.com/cb?code=old&state=old&keep=1", Code: code, State: "new"},
		{Name: "existing_state_kept_when_state_empty", RedirectURI: "https://app.example.com/cb?state=old", Code: code},
		{Name: "fragment_kept", RedirectURI: "https://app.example.com/cb#frag", Code: code, State: "s"},
		{Name: "state_needs_escaping", RedirectURI: "https://app.example.com/cb", Code: code, State: "a b&c=d/é+%"},
		{Name: "raw_query_reencoded", RedirectURI: "https://app.example.com/cb?q=a+b&r=%20x&empty=&flag", Code: code, State: "s"},
		{Name: "non_ascii_path_and_fragment", RedirectURI: "https://app.example.com/é/cb#ü", Code: code, State: "s"},
		{Name: "custom_scheme", RedirectURI: "com.example.app:/oauth2redirect", Code: code, State: "s"},
		{Name: "loopback_port", RedirectURI: "http://127.0.0.1:53682/callback", Code: code, State: "s"},
		{Name: "empty_redirect_uri", RedirectURI: "", Code: code, State: "s"},
		{Name: "unparseable_redirect_uri", RedirectURI: "http://[::1", Code: code, State: "s"},
	}
	var successCases []successCase
	for _, in := range successInputs {
		in.URL, in.OK = h.authorizationSuccessURL(in.RedirectURI, in.Code, in.State)
		c, rec := goldenContext(http.MethodGet, "/v1/oauth2/authorize")
		h.redirectAuthorizationSuccess(c, in.RedirectURI, in.Code, in.State)
		in.Response = goldenCapture(c, rec)
		successCases = append(successCases, in)
	}
	goldenSection(t, "redirects", "authorization_success", map[string]any{
		"description": "router.go authorizationSuccessURL / redirectAuthorizationSuccess. url.Parse(redirect_uri); query = existing query parsed (url.ParseQuery semantics), Set(code), Set(state) only if non-empty, then url.Values.Encode (keys byte-sorted, values in original order, QueryEscape: space => '+'); fragment preserved; RawQuery replaced. Parse failure or empty redirect_uri => 400 {\"error\":\"invalid_request\"}. Response is 302 with Location; the HTML body of http.Redirect is an accepted deviation and omitted.",
		"cases":       successCases,
	})

	// 2. OAuth error redirect back to the client.
	type errorCase struct {
		Name        string         `json:"name"`
		RedirectURI string         `json:"redirect_uri"`
		State       string         `json:"state"`
		Error       string         `json:"error"`
		Description string         `json:"error_description"`
		OK          bool           `json:"ok"`
		URL         string         `json:"url,omitempty"`
		Response    goldenResponse `json:"response"`
	}
	errorInputs := []errorCase{
		{Name: "login_required", RedirectURI: "https://app.example.com/callback", State: "xyz", Error: "login_required", Description: "no active SSO session"},
		{Name: "no_description_no_state", RedirectURI: "https://app.example.com/callback", Error: "access_denied"},
		{Name: "merged_query_and_fragment", RedirectURI: "https://app.example.com/cb?error=old&b=2#f", State: "s t", Error: "invalid_scope", Description: "requested scopes are not allowed for this client"},
		{Name: "unicode_description", RedirectURI: "https://app.example.com/cb", State: "s", Error: "invalid_request", Description: "code_challenge length must be 43–128 characters"},
		{Name: "empty_redirect_uri_renders_json", RedirectURI: "", State: "s", Error: "invalid_request", Description: "state is required"},
	}
	var errorCases []errorCase
	for _, in := range errorInputs {
		in.URL, in.OK = h.oauthErrorURL(in.RedirectURI, in.State, in.Error, in.Description)
		c, rec := goldenContext(http.MethodGet, "/v1/oauth2/authorize")
		h.redirectOAuthError(c, in.RedirectURI, in.State, in.Error, in.Description)
		in.Response = goldenCapture(c, rec)
		errorCases = append(errorCases, in)
	}
	goldenSection(t, "redirects", "oauth_error", map[string]any{
		"description": "router.go oauthErrorURL / redirectOAuthError: like authorization_success but sets error, error_description (only if non-empty) and state (only if non-empty). Unusable redirect_uri => 400 JSON {\"error\",\"error_description\"} (both keys always present).",
		"cases":       errorCases,
	})

	// 3. Raw authorize query -> auth-ui /login (and /consent) query.
	type authUICase struct {
		Name     string `json:"name"`
		RawQuery string `json:"raw_query"`
		Path     string `json:"path"`
		URL      string `json:"url"`
	}
	var authUICases []authUICase
	for _, in := range []authUICase{
		{Name: "full_params", Path: "/login", RawQuery: "response_type=code&client_id=trading-web&redirect_uri=https%3A%2F%2Ftrading.example.com%2Fcallback&scope=openid%20email%20profile&state=abc&nonce=n1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&prompt=login"},
		{Name: "extra_params_dropped_and_empty_omitted", Path: "/login", RawQuery: "client_id=trading-web&utm_source=x&nonce=&scope=openid&state=s&redirect_uri=https://a.example/cb"},
		{Name: "repeated_param_first_wins", Path: "/consent", RawQuery: "client_id=a&client_id=b&state=1&state=2"},
		{Name: "plus_and_percent_decoding", Path: "/login", RawQuery: "scope=openid+email%2Cprofile&state=a%2Bb+c%26d&redirect_uri=https%3A%2F%2Fa.example%2Fcb%3Fx%3D1%26y%3D2"},
		{Name: "unicode_state", Path: "/login", RawQuery: "state=%E0%B8%AA%E0%B8%A7%E0%B8%B1%E0%B8%AA%E0%B8%94%E0%B8%B5&client_id=c"},
		{Name: "no_params_no_question_mark", Path: "/login", RawQuery: ""},
		{Name: "only_unknown_params", Path: "/login", RawQuery: "foo=bar"},
	} {
		c, _ := goldenContext(http.MethodGet, "/v1/oauth2/authorize?"+in.RawQuery)
		in.URL = h.authUIRoute(in.Path, preservedAuthorizeQuery(c))
		authUICases = append(authUICases, in)
	}
	goldenSection(t, "redirects", "auth_ui_from_raw_query", map[string]any{
		"description":      "handlers_stateless.go preservedAuthorizeQuery + authUIRoute (authorize => auth-ui /login or /consent). Only response_type, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, prompt are copied, each via c.Query (first value, decoded; '+' => space) and only if non-empty; re-encoded with url.Values.Encode (sorted). URL = TrimRight(AUTH_UI_BASE_URL, \"/\") + path, plus \"?\" + query only when at least one param survives.",
		"auth_ui_base_url": authUI + "/",
		"cases":            authUICases,
	})

	// 4. Canonical request -> auth-ui /consent, /error, /otp.
	type requestCase struct {
		Name       string         `json:"name"`
		Request    oauth.Request  `json:"request"`
		ConsentURL string         `json:"consent_url"`
		ErrorCode  string         `json:"error_code"`
		ErrorDesc  string         `json:"error_description"`
		ErrorResp  goldenResponse `json:"error_response"`
	}
	var requestCases []requestCase
	for _, in := range []requestCase{
		{
			Name: "canonical_s256",
			Request: oauth.Request{ResponseType: "code", ClientID: "trading-web", RedirectURI: "https://trading.example.com/callback",
				Scope: "email openid profile", State: "abc", Nonce: "n1", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256"},
			ErrorCode: "provider_email_unverified", ErrorDesc: "provider did not return a verified email; try email OTP",
		},
		{
			Name:      "minimal_with_specials",
			Request:   oauth.Request{ClientID: "c&d", RedirectURI: "https://a.example/cb?x=1&y=2", Scope: "openid", State: "a b+c", Prompt: "login"},
			ErrorCode: "access_denied",
		},
	} {
		in.ConsentURL = h.authUIRoute("/consent", oauthValuesFromRequest(in.Request))
		c, rec := goldenContext(http.MethodGet, "/v1/auth/login/callback/google")
		h.redirectAuthUIError(c, in.Request, in.ErrorCode, in.ErrorDesc)
		in.ErrorResp = goldenCapture(c, rec)
		requestCases = append(requestCases, in)
	}
	goldenSection(t, "redirects", "auth_ui_from_request", map[string]any{
		"description":      "consent_url: oauthValuesFromRequest(validated.Request) => auth-ui /consent (after provider callback / OTP verify without consent); the request is the CANONICAL one from oauth.Validate (scope sorted+space-joined, code_challenge_method defaulted). error_response: redirectAuthUIError => 302 to auth-ui /error with the same params plus error and error_description (if non-empty). All via url.Values.Encode (sorted keys).",
		"auth_ui_base_url": authUI + "/",
		"cases":            requestCases,
	})

	// 5. Provider authorization URL.
	type providerCase struct {
		Provider string `json:"provider"`
		State    string `json:"state"`
		URL      string `json:"url"`
	}
	const envelopeToken = "eyJwcm92aWRlciI6Imdvb2dsZSJ9.c2lnbmF0dXJl"
	var providerCases []providerCase
	for _, p := range []string{"google", "github", "unknown"} {
		providerCases = append(providerCases, providerCase{Provider: p, State: envelopeToken, URL: h.providerAuthorizationURLWithState(p, envelopeToken)})
	}
	goldenSection(t, "redirects", "provider_authorization_url", map[string]any{
		"description": "handlers_provider_stateless.go providerAuthorizationURLWithState (POST /v1/auth/login/{google,github} => {\"authorization_url\"}). Params set: client_id, redirect_uri, response_type=code, state=<envelope>, prompt=select_account, scope (google: \"openid email profile\" + access_type=offline; github: \"read:user user:email\"); url.Values.Encode (sorted). Unknown provider => \"\".",
		"config": map[string]string{
			"google_client_id":    h.cfg.GoogleClientID,
			"google_redirect_url": h.cfg.GoogleRedirectURL,
			"github_client_id":    h.cfg.GitHubClientID,
			"github_redirect_url": h.cfg.GitHubRedirectURL,
		},
		"cases": providerCases,
	})

	// 6. Post-logout redirect.
	type logoutCase struct {
		Candidate string `json:"post_logout_redirect_uri"`
		Target    string `json:"location"`
	}
	var logoutCases []logoutCase
	for _, cand := range []string{
		"",
		"https://auth-ui.example.com/signed-out?x=1",
		"HTTPS://AUTH-UI.EXAMPLE.COM/x",
		"https://trading.example.com/after-logout",
		"https://language.example.com/anything",
		"https://trading.example.com:443/x",
		"http://trading.example.com/x",
		"https://evil.example.com/",
		"//trading.example.com/x",
		"/relative",
		"https://trading.example.com.evil.example/x",
	} {
		logoutCases = append(logoutCases, logoutCase{Candidate: cand, Target: h.postLogoutRedirect(cand)})
	}
	goldenSection(t, "redirects", "post_logout", map[string]any{
		"description":                    "router.go postLogoutRedirect (GET /v1/auth/logout and /logout/global => 302). Default = TrimRight(AUTH_UI_BASE_URL, \"/\") + \"/logout\". A candidate is returned verbatim when its scheme and host (host includes any explicit port) case-insensitively equal those of AUTH_UI_BASE_URL or any POST_LOGOUT_REDIRECT_ALLOWLIST entry (paths ignored); relative or scheme-less URLs fall back to the default.",
		"auth_ui_base_url":               h.cfg.AuthUIBaseURL,
		"post_logout_redirect_allowlist": h.cfg.PostLogoutRedirectAllowlist,
		"cases":                          logoutCases,
	})

	// 7. End-to-end /v1/oauth2/authorize without an SSO cookie.
	clients := goldenClientRepo{
		"trading-web": {ClientID: "trading-web", ClientType: domain.ClientTypePublic, Status: domain.ClientStatusActive,
			RedirectURIs: []string{"https://trading.example.com/callback", "https://trading.example.com/cb?tenant=a"}, AllowedScopes: "openid email profile offline_access trading.read"},
	}
	ah := Handler{cfg: h.cfg, app: application.App{Clients: clients}}
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	type authorizeCase struct {
		Name     string         `json:"name"`
		RawQuery string         `json:"raw_query"`
		Response goldenResponse `json:"response"`
	}
	base := url.Values{
		"response_type": {"code"}, "client_id": {"trading-web"}, "redirect_uri": {"https://trading.example.com/callback"},
		"scope": {"profile openid email"}, "state": {"st 1"}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	with := func(mod func(v url.Values)) string {
		v := url.Values{}
		for k, vals := range base {
			v[k] = append([]string(nil), vals...)
		}
		mod(v)
		return v.Encode()
	}
	var authorizeCases []authorizeCase
	for _, in := range []authorizeCase{
		{Name: "no_session_to_login", RawQuery: with(func(url.Values) {})},
		{Name: "no_session_extra_param_dropped", RawQuery: with(func(v url.Values) { v.Set("utm", "x") })},
		{Name: "prompt_none_login_required", RawQuery: with(func(v url.Values) { v.Set("prompt", "none") })},
		{Name: "registered_uri_with_query", RawQuery: with(func(v url.Values) {
			v.Set("redirect_uri", "https://trading.example.com/cb?tenant=a")
			v.Set("prompt", "none")
		})},
		{Name: "recoverable_missing_state", RawQuery: with(func(v url.Values) { v.Del("state") })},
		{Name: "recoverable_scope_not_allowed", RawQuery: with(func(v url.Values) { v.Set("scope", "openid trading.write") })},
		{Name: "recoverable_plain_pkce_public", RawQuery: with(func(v url.Values) { v.Set("code_challenge_method", "plain") })},
		{Name: "fatal_unknown_client", RawQuery: with(func(v url.Values) { v.Set("client_id", "nope") })},
		{Name: "fatal_unregistered_redirect", RawQuery: with(func(v url.Values) { v.Set("redirect_uri", "https://evil.example.com/cb") })},
	} {
		c, rec := goldenContext(http.MethodGet, "/v1/oauth2/authorize?"+in.RawQuery)
		ah.authorizeStateless(c)
		in.Response = goldenCapture(c, rec)
		authorizeCases = append(authorizeCases, in)
	}
	goldenSection(t, "redirects", "authorize_without_session", map[string]any{
		"description":      "GET /v1/oauth2/authorize with no SSO cookie (handlers_stateless.go authorizeStateless). Client registry: see clients. Fatal validation errors => 400 JSON; recoverable => 302 to redirect_uri with error params; prompt=none => login_required; otherwise 302 to auth-ui /login with the preserved query.",
		"auth_ui_base_url": h.cfg.AuthUIBaseURL,
		"clients":          clients,
		"cases":            authorizeCases,
	})
}
