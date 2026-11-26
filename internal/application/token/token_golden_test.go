package token

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/supanut9/auth-server/internal/adapter/out/jwks"
	"github.com/supanut9/auth-server/internal/domain"
)

type goldenIDs struct {
	ids []string
}

func (g *goldenIDs) NewID() (string, error) {
	id := g.ids[0]
	g.ids = g.ids[1:]
	return id, nil
}

type goldenJWT struct {
	Header       string `json:"header_json"`
	Claims       string `json:"claims_json"`
	SigningInput string `json:"signing_input"`
	Signature    string `json:"signature_b64url"`
	Compact      string `json:"compact"`
}

func goldenSplitJWT(t *testing.T, compact string) goldenJWT {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return goldenJWT{
		Header:       string(header),
		Claims:       string(claims),
		SigningInput: parts[0] + "." + parts[1],
		Signature:    parts[2],
		Compact:      compact,
	}
}

func goldenSigner(t *testing.T) jwks.Manager {
	t.Helper()
	m, err := jwks.NewManagerWithSources("RS256", "", "",
		string(goldenReadFile(t, "keys/test-only-rsa-2048-private-pkcs1.pem")),
		string(goldenReadFile(t, "keys/test-only-rsa-2048-public-pkix.pem")))
	if err != nil {
		t.Fatalf("golden signer: %v", err)
	}
	return m
}

// TestGoldenJWT records the exact JWTs token.Service mints for fixed inputs.
// RS256 (RSASSA-PKCS1-v1_5) is deterministic, so the signatures reproduce.
func TestGoldenJWT(t *testing.T) {
	signer := goldenSigner(t)
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	type configInput struct {
		Issuer                    string   `json:"issuer"`
		Audience                  string   `json:"audience"`
		AccessTokenTTLSeconds     int64    `json:"access_token_ttl_seconds"`
		IDTokenTTLSeconds         int64    `json:"id_token_ttl_seconds"`
		RefreshAbsoluteTTLSeconds int64    `json:"refresh_token_absolute_ttl_seconds"`
		RefreshInactiveTTLSeconds int64    `json:"refresh_token_inactive_ttl_seconds"`
		RefreshReuseGraceSeconds  int64    `json:"refresh_reuse_grace_seconds"`
		KeyFile                   string   `json:"private_key_file"`
		NowUnix                   int64    `json:"now_unix"`
		NowRFC3339                string   `json:"now_rfc3339"`
		GeneratedIDsInOrder       []string `json:"generated_ids_in_order"`
		RandomSourceSeedNote      string   `json:"random_source_note"`
	}
	type userCase struct {
		Name          string         `json:"name"`
		Config        configInput    `json:"config"`
		Request       map[string]any `json:"request"`
		AccessToken   goldenJWT      `json:"access_token"`
		IDToken       goldenJWT      `json:"id_token"`
		TokenResponse map[string]any `json:"token_fields"`
	}

	cfgFor := func(issuer string) Config {
		return Config{
			Issuer:                  issuer,
			Audience:                "platform-api",
			AccessTokenTTL:          10 * time.Minute,
			IDTokenTTL:              10 * time.Minute,
			RefreshTokenAbsoluteTTL: 30 * 24 * time.Hour,
			RefreshTokenInactiveTTL: 7 * 24 * time.Hour,
			RefreshReuseGrace:       60 * time.Second,
		}
	}
	cfgInput := func(cfg Config, ids []string) configInput {
		return configInput{
			Issuer:                    cfg.Issuer,
			Audience:                  cfg.Audience,
			AccessTokenTTLSeconds:     int64(cfg.AccessTokenTTL.Seconds()),
			IDTokenTTLSeconds:         int64(cfg.IDTokenTTL.Seconds()),
			RefreshAbsoluteTTLSeconds: int64(cfg.RefreshTokenAbsoluteTTL.Seconds()),
			RefreshInactiveTTLSeconds: int64(cfg.RefreshTokenInactiveTTL.Seconds()),
			RefreshReuseGraceSeconds:  int64(cfg.RefreshReuseGrace.Seconds()),
			KeyFile:                   "keys/test-only-rsa-2048-private-pkcs1.pem",
			NowUnix:                   now.Unix(),
			NowRFC3339:                now.Format(time.RFC3339),
			GeneratedIDsInOrder:       ids,
			RandomSourceSeedNote:      "refresh token bytes come from crypto/rand (seeded in the Go test); they do not affect any JWT",
		}
	}
	newService := func(cfg Config, ids []string, sessions map[string]domain.SSOSession) (Service, *memoryRefreshTokenRepo) {
		refreshRepo := &memoryRefreshTokenRepo{}
		return NewService(cfg, fixedClock{now: now}, &goldenIDs{ids: append([]string(nil), ids...)}, signer,
			&memoryAccessTokenRepo{}, &memorySSOSessionRepo{sessions: sessions}, &memoryRefreshTokenChainRepo{}, refreshRepo), refreshRepo
	}

	userRequests := []struct {
		name   string
		issuer string
		req    UserTokenRequest
	}{
		{
			name:   "user_basic",
			issuer: "https://auth.example.com",
			req: UserTokenRequest{
				AccountID:       "0195f0a2-7c4e-7b2a-9d1e-3f4a5b6c7d8e",
				ClientID:        "trading-web",
				Scope:           []string{"profile", "openid", "trading.read", "email", "openid"},
				SSOSessionID:    "0195f0a2-0000-7000-8000-000000000001",
				DeviceSessionID: "0195f0a2-0000-7000-8000-0000000000c0",
				AuthTime:        time.Date(2026, 4, 1, 11, 55, 0, 0, time.UTC),
				Email:           "user@example.com",
				EmailVerified:   true,
				Name:            "Trader",
				Picture:         "https://example.com/avatar.png",
			},
		},
		{
			name:   "user_untrimmed_issuer_and_html_escaping",
			issuer: "https://auth.example.com/",
			req: UserTokenRequest{
				AccountID:       "0195f0a2-7c4e-7b2a-9d1e-3f4a5b6c7d8f",
				ClientID:        "language-web",
				Scope:           []string{"openid"},
				SSOSessionID:    "0195f0a2-0000-7000-8000-000000000002",
				DeviceSessionID: "0195f0a2-0000-7000-8000-0000000000c1",
				AuthTime:        time.Date(2026, 4, 1, 4, 0, 0, 0, time.FixedZone("ICT", 7*3600)),
				Email:           "o'neil+tag@example.co.th",
				EmailVerified:   true,
				Name:            "สมชาย <Admin> & \"Co\"",
				Picture:         "https://cdn.example.com/a.png?w=64&h=64",
			},
		},
		{
			name:   "user_empty_profile_fields",
			issuer: "http://localhost:8050",
			req: UserTokenRequest{
				AccountID:     "0195f0a2-7c4e-7b2a-9d1e-3f4a5b6c7d90",
				ClientID:      "knowledge-web",
				Scope:         nil,
				SSOSessionID:  "",
				AuthTime:      time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
				EmailVerified: false,
			},
		},
	}

	var userCases []userCase
	for i, ur := range userRequests {
		cryptotest.SetGlobalRandom(t, uint64(100+i))
		ids := []string{"access-jti-" + ur.name, "chain-" + ur.name}
		cfg := cfgFor(ur.issuer)
		svc, _ := newService(cfg, ids, nil)
		issued, err := svc.IssueUserTokens(context.Background(), ur.req)
		if err != nil {
			t.Fatalf("%s: issue: %v", ur.name, err)
		}
		userCases = append(userCases, userCase{
			Name:   ur.name,
			Config: cfgInput(cfg, ids),
			Request: map[string]any{
				"account_id":        ur.req.AccountID,
				"client_id":         ur.req.ClientID,
				"scope":             ur.req.Scope,
				"sso_session_id":    ur.req.SSOSessionID,
				"device_session_id": ur.req.DeviceSessionID,
				"auth_time_rfc3339": ur.req.AuthTime.Format(time.RFC3339),
				"email":             ur.req.Email,
				"email_verified":    ur.req.EmailVerified,
				"name":              ur.req.Name,
				"picture":           ur.req.Picture,
			},
			AccessToken: goldenSplitJWT(t, issued.AccessToken),
			IDToken:     goldenSplitJWT(t, issued.IDToken),
			TokenResponse: map[string]any{
				"token_type": issued.TokenType,
				"expires_in": issued.ExpiresIn,
				"scope":      issued.Scope,
			},
		})
	}
	goldenSection(t, "jwt", "user_tokens", map[string]any{
		"description": "token.Service.IssueUserTokens (authorization_code grant). Generated IDs are consumed in order: access jti, then refresh chain id. Header = {alg,kid,typ} and claims are Go maps, so keys are sorted and encoding/json HTML-escapes &, <, > as \\u0026 etc. iss is cfg.Issuer verbatim (NOT trimmed); id_token aud = client_id; auth_time is AuthTime in unix seconds; scope is trimmed/deduped/byte-sorted and space-joined. In production the HTTP handler always passes email_verified=true.",
		"cases":       userCases,
	})

	type ccCase struct {
		Name          string         `json:"name"`
		Config        configInput    `json:"config"`
		Request       map[string]any `json:"request"`
		AccessToken   goldenJWT      `json:"access_token"`
		TokenResponse map[string]any `json:"token_fields"`
	}
	ccRequests := []struct {
		name string
		req  ClientCredentialsTokenRequest
	}{
		{name: "client_credentials_scoped", req: ClientCredentialsTokenRequest{ClientID: "support-console", Scope: []string{"trading.write", "trading.read", "trading.read"}}},
		{name: "client_credentials_no_scope", req: ClientCredentialsTokenRequest{ClientID: "batch-worker", Scope: nil}},
	}
	var ccCases []ccCase
	for _, cr := range ccRequests {
		ids := []string{"access-jti-" + cr.name}
		cfg := cfgFor("https://auth.example.com")
		svc, _ := newService(cfg, ids, nil)
		issued, err := svc.IssueClientCredentialsToken(context.Background(), cr.req)
		if err != nil {
			t.Fatalf("%s: issue: %v", cr.name, err)
		}
		ccCases = append(ccCases, ccCase{
			Name:          cr.name,
			Config:        cfgInput(cfg, ids),
			Request:       map[string]any{"client_id": cr.req.ClientID, "scope": cr.req.Scope},
			AccessToken:   goldenSplitJWT(t, issued.AccessToken),
			TokenResponse: map[string]any{"token_type": issued.TokenType, "expires_in": issued.ExpiresIn, "scope": issued.Scope},
		})
	}
	goldenSection(t, "jwt", "client_credentials_tokens", map[string]any{
		"description": "token.Service.IssueClientCredentialsToken: sub = client_id, no sid claim, no id/refresh token.",
		"cases":       ccCases,
	})

	// Refresh grant: issue, then rotate at now+5m. The refreshed access token
	// takes sub/sid/client_id/scope from the stored chain.
	cryptotest.SetGlobalRandom(t, 200)
	ids := []string{"access-jti-initial", "chain-refresh", "access-jti-refreshed"}
	cfg := cfgFor("https://auth.example.com")
	sessionID := "0195f0a2-0000-7000-8000-000000000003"
	sessions := map[string]domain.SSOSession{sessionID: {ID: sessionID, Status: domain.SSOSessionStatusActive, ExpiresAt: now.Add(24 * time.Hour)}}
	svc, _ := newService(cfg, ids, sessions)
	issued, err := svc.IssueUserTokens(context.Background(), UserTokenRequest{
		AccountID:    "0195f0a2-7c4e-7b2a-9d1e-3f4a5b6c7d91",
		ClientID:     "trading-web",
		Scope:        []string{"openid", "offline_access", "trading.read"},
		SSOSessionID: sessionID,
		AuthTime:     now,
		Email:        "refresh@example.com",
	})
	if err != nil {
		t.Fatalf("refresh: issue: %v", err)
	}
	refreshNow := now.Add(5 * time.Minute)
	svc.clock = fixedClock{now: refreshNow}
	refreshed, err := svc.RefreshUserTokens(context.Background(), RefreshTokenRequest{ClientID: "trading-web", RefreshToken: issued.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: rotate: %v", err)
	}
	goldenSection(t, "jwt", "refresh_token_grant", map[string]any{
		"description": "token.Service.RefreshUserTokens access token. Inputs: the chain created by IssueUserTokens below; rotation happens at refresh_now_unix. The refreshed access token has no id_token sibling.",
		"config":      cfgInput(cfg, ids),
		"initial": map[string]any{
			"account_id":     "0195f0a2-7c4e-7b2a-9d1e-3f4a5b6c7d91",
			"client_id":      "trading-web",
			"scope":          []string{"openid", "offline_access", "trading.read"},
			"sso_session_id": sessionID,
			"access_token":   goldenSplitJWT(t, issued.AccessToken),
		},
		"refresh_now_unix": refreshNow.Unix(),
		"refreshed": map[string]any{
			"access_token": goldenSplitJWT(t, refreshed.AccessToken),
			"token_fields": map[string]any{"token_type": refreshed.TokenType, "expires_in": refreshed.ExpiresIn, "scope": refreshed.Scope},
		},
	})
}

// goldenScopeInputs is shared by the scope sections of every package so the
// differences between the Go splitters line up case-by-case in scopes.json.
var goldenScopeInputs = []string{
	"",
	"openid profile email",
	"email openid email profile",
	"openid,profile email",
	"openid\temail\nprofile",
	"  openid   email  ",
	"openid\remail",
	"openid email",
	"trading.write Trading.read trading.read",
	"a,,b , c",
}

func TestGoldenTokenHashesAndScopes(t *testing.T) {
	type hashCase struct {
		Input string `json:"input"`
		Hash  string `json:"hash,omitempty"`
		Error string `json:"error,omitempty"`
	}
	var hashCases []hashCase
	for _, v := range []string{"", "abc", "refresh-token-value", "dGhpcyBpcyBub3QgYSByZWFsIHRva2VuLCBqdXN0IHRlc3Q"} {
		_, hash, err := hashOpaqueToken(v)
		c := hashCase{Input: v, Hash: hash}
		if err != nil {
			c.Error = err.Error()
		}
		hashCases = append(hashCases, c)
	}
	goldenSection(t, "hashes", "refresh_token_hash", map[string]any{
		"description": "Refresh token_hash = base64url_nopad(SHA-256(token)), unsalted. Source: internal/application/token/service.go hashOpaqueToken.",
		"cases":       hashCases,
	})

	type randomCase struct {
		RawHex string `json:"raw_hex"`
		Value  string `json:"value"`
		Hash   string `json:"hash"`
	}
	cryptotest.SetGlobalRandom(t, 3)
	var randomCases []randomCase
	for range 3 {
		value, hash, err := newOpaqueToken()
		if err != nil {
			t.Fatalf("new opaque token: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) != 32 || len(value) != 43 {
			t.Fatalf("unexpected refresh token shape %q", value)
		}
		randomCases = append(randomCases, randomCase{RawHex: goldenHex(raw), Value: value, Hash: hash})
	}
	goldenSection(t, "hashes", "refresh_token_random", map[string]any{
		"description": "Refresh token value = base64url_nopad(32 random bytes) -> 43 chars; hash as refresh_token_hash. raw_hex is the random input. Source: token/service.go newOpaqueToken.",
		"cases":       randomCases,
	})

	type scopeCase struct {
		Input  string   `json:"input"`
		Output []string `json:"output"`
		Joined string   `json:"joined"`
	}
	var splitCases []scopeCase
	for _, in := range goldenScopeInputs {
		out := splitScopes(in)
		splitCases = append(splitCases, scopeCase{Input: in, Output: out, Joined: strings.Join(out, " ")})
	}
	goldenSection(t, "scopes", "token_split_scopes", map[string]any{
		"description": "token/service.go splitScopes (used on refresh: chain.Scope -> new access token scope): \"\" -> null; otherwise strings.Fields (splits on any Unicode whitespace incl. \\r and U+00A0, NOT on commas), then normalizeScopes (trim, drop empty, dedupe, byte-wise sort).",
		"cases":       splitCases,
	})

	type normCase struct {
		Input  []string `json:"input"`
		Output []string `json:"output"`
		Joined string   `json:"joined"`
	}
	var normCases []normCase
	for _, in := range [][]string{
		nil,
		{"openid", "profile", "email"},
		{" openid ", "openid", "", "  "},
		{"trading.write", "Trading.read", "trading.read", "a,b"},
		{"z", "Z", "é", "e", "_", "1"},
	} {
		out := normalizeScopes(in)
		normCases = append(normCases, normCase{Input: in, Output: out, Joined: strings.Join(out, " ")})
	}
	goldenSection(t, "scopes", "token_normalize_scopes", map[string]any{
		"description": "token/service.go normalizeScopes: applied to every requested scope list before signing (user + client_credentials). Trim each, drop empty, dedupe, sort.Strings (byte-wise). Empty input -> [] and joined \"\".",
		"cases":       normCases,
	})
}
