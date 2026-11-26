package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
)

// goldenScopeInputs is shared (by copy) with the oauth, token and flow golden
// tests so the Go splitters line up case-by-case in scopes.json.
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

func goldenContext(method, target string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, target, nil)
	return c, rec
}

type goldenResponse struct {
	Status      int      `json:"status"`
	Location    string   `json:"location,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	SetCookie   []string `json:"set_cookie,omitempty"`
	Body        string   `json:"body,omitempty"`
}

// goldenCapture records the response. Redirect bodies (Go's http.Redirect
// HTML) are an accepted deviation and are dropped.
func goldenCapture(c *gin.Context, rec *httptest.ResponseRecorder) goldenResponse {
	c.Writer.WriteHeaderNow()
	res := goldenResponse{
		Status:      rec.Code,
		Location:    rec.Header().Get("Location"),
		ContentType: rec.Header().Get("Content-Type"),
		SetCookie:   rec.Header().Values("Set-Cookie"),
	}
	if res.Location == "" {
		res.Body = rec.Body.String()
	} else {
		res.ContentType = ""
	}
	return res
}

func TestGoldenHTTPHashes(t *testing.T) {
	type pkceCase struct {
		Name      string `json:"name"`
		Method    string `json:"method"`
		Challenge string `json:"challenge"`
		Verifier  string `json:"verifier"`
		Valid     bool   `json:"valid"`
	}
	const (
		rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	pkce := []pkceCase{
		{Name: "s256_rfc7636_appendix_b", Method: "S256", Challenge: rfcChallenge, Verifier: rfcVerifier},
		{Name: "s256_wrong_verifier", Method: "S256", Challenge: rfcChallenge, Verifier: rfcVerifier + "x"},
		{Name: "s256_padded_challenge", Method: "S256", Challenge: rfcChallenge + "=", Verifier: rfcVerifier},
		{Name: "s256_lowercase_method_rejected", Method: "s256", Challenge: rfcChallenge, Verifier: rfcVerifier},
		{Name: "plain_match", Method: "plain", Challenge: rfcVerifier, Verifier: rfcVerifier},
		{Name: "plain_mismatch", Method: "plain", Challenge: rfcVerifier, Verifier: rfcChallenge},
		{Name: "empty_method_is_plain", Method: "", Challenge: rfcVerifier, Verifier: rfcVerifier},
		{Name: "empty_method_does_not_hash", Method: "", Challenge: rfcChallenge, Verifier: rfcVerifier},
		{Name: "unknown_method", Method: "S512", Challenge: rfcChallenge, Verifier: rfcVerifier},
		{Name: "no_challenge_no_verifier", Method: "", Challenge: "", Verifier: ""},
		{Name: "no_challenge_with_method_no_verifier", Method: "S256", Challenge: "", Verifier: ""},
		{Name: "no_challenge_but_verifier_sent", Method: "", Challenge: "", Verifier: rfcVerifier},
		{Name: "challenge_but_no_verifier", Method: "S256", Challenge: rfcChallenge, Verifier: ""},
	}
	for i := range pkce {
		pkce[i].Valid = validatePKCE(pkce[i].Method, pkce[i].Challenge, pkce[i].Verifier)
	}
	goldenSection(t, "hashes", "pkce_verify", map[string]any{
		"description": "Token-endpoint PKCE check (internal/adapter/in/http/router.go validatePKCE) on the stored code_challenge(_method). Empty challenge => valid iff verifier is empty. Method \"\" or \"plain\" => constant-time equality; \"S256\" => challenge == base64url_nopad(SHA-256(verifier)); any other method (case-sensitive) => invalid. Failure => 400 {\"error\":\"invalid_grant\",\"error_description\":\"pkce validation failed\"}.",
		"cases":       pkce,
	})

	type secretCase struct {
		Name     string `json:"name"`
		Stored   string `json:"stored"`
		Provided string `json:"provided"`
		Match    bool   `json:"match"`
	}
	// sha256:base64url_nopad(SHA-256("s3cret")) as written by cmd/devseed.
	const hashedS3cret = "sha256:HsHCa1DV08WNlYMYGvgHZlX-AHVr9yhZQLo2cPmfy6A"
	secrets := []secretCase{
		{Name: "hashed_match", Stored: hashedS3cret, Provided: "s3cret"},
		{Name: "hashed_mismatch", Stored: hashedS3cret, Provided: "S3cret"},
		{Name: "hashed_provided_is_the_hash", Stored: hashedS3cret, Provided: hashedS3cret},
		{Name: "hashed_prefix_case_sensitive", Stored: "SHA256:HsHCa1DV08WNlYMYGvgHZlX-AHVr9yhZQLo2cPmfy6A", Provided: "s3cret"},
		{Name: "plaintext_match", Stored: "plain-secret", Provided: "plain-secret"},
		{Name: "plaintext_mismatch", Stored: "plain-secret", Provided: "plain-secret "},
		{Name: "empty_stored", Stored: "", Provided: "anything"},
		{Name: "empty_provided", Stored: "plain-secret", Provided: ""},
		{Name: "hashed_empty_digest", Stored: "sha256:", Provided: "x"},
	}
	for i := range secrets {
		secrets[i].Match = matchSecret(secrets[i].Stored, secrets[i].Provided)
	}
	goldenSection(t, "hashes", "client_secret_match", map[string]any{
		"description": "Confidential-client secret check (router.go matchSecret). Empty stored or provided => false. Stored \"sha256:<b64url_nopad(SHA-256(secret))>\" (case-sensitive prefix) => constant-time compare of the digest text; otherwise constant-time plaintext compare.",
		"cases":       secrets,
	})

	type hashCase struct {
		Input string `json:"input"`
		Hash  string `json:"hash,omitempty"`
		Error string `json:"error,omitempty"`
	}
	var hashCases []hashCase
	for _, v := range []string{"", "abc", "refresh-token-value"} {
		_, hash, err := hashOpaqueToken(v)
		c := hashCase{Input: v, Hash: hash}
		if err != nil {
			c.Error = err.Error()
		}
		hashCases = append(hashCases, c)
	}
	goldenSection(t, "hashes", "http_opaque_token_hash", map[string]any{
		"description": "router.go hashOpaqueToken (revoke + refresh introspection lookups): same digest as refresh_token_hash; empty token short-circuits (revoke => 200, introspect => {\"active\":false}).",
		"cases":       hashCases,
	})
}

func TestGoldenHTTPScopes(t *testing.T) {
	type splitCase struct {
		Input  string   `json:"input"`
		Output []string `json:"output"`
	}
	var split []splitCase
	for _, in := range goldenScopeInputs {
		split = append(split, splitCase{Input: in, Output: splitProtocolList(in)})
	}
	goldenSection(t, "scopes", "http_split_protocol_list", map[string]any{
		"description": "router.go splitProtocolList (client_credentials scope, code granted_scopes, access-token scope claim in userinfo, client.allowed_scopes for public-info): split on ' ', ',', '\\n', '\\t', trim, drop empty, dedupe keeping FIRST occurrence order — NOT sorted. Always a non-null list.",
		"cases":       split,
	})

	type ccCase struct {
		Name          string   `json:"name"`
		RequestScope  string   `json:"request_scope"`
		AllowedScopes string   `json:"client_allowed_scopes"`
		Split         []string `json:"split"`
		Outcome       string   `json:"outcome"`
	}
	ccInputs := []ccCase{
		{Name: "subset_ok", RequestScope: "trading.write trading.read", AllowedScopes: "trading.read,trading.write"},
		{Name: "empty_scope_ok", RequestScope: "", AllowedScopes: "trading.read"},
		{Name: "duplicate_and_comma", RequestScope: "trading.read,trading.read", AllowedScopes: "trading.read"},
		{Name: "not_allowed", RequestScope: "trading.admin", AllowedScopes: "trading.read"},
		{Name: "openid_rejected_even_if_allowed", RequestScope: "openid", AllowedScopes: "openid trading.read"},
		{Name: "email_rejected", RequestScope: "trading.read email", AllowedScopes: "email trading.read"},
		{Name: "profile_rejected", RequestScope: "profile", AllowedScopes: "profile"},
		{Name: "offline_access_allowed_if_listed", RequestScope: "offline_access", AllowedScopes: "offline_access"},
	}
	for i := range ccInputs {
		c := &ccInputs[i]
		c.Split = splitProtocolList(c.RequestScope)
		switch {
		case containsValue(c.Split, "openid") || containsValue(c.Split, "email") || containsValue(c.Split, "profile"):
			c.Outcome = "invalid_scope"
		case !scopeSubset(c.Split, splitProtocolList(c.AllowedScopes)):
			c.Outcome = "invalid_scope"
		default:
			c.Outcome = "issue"
		}
	}
	goldenSection(t, "scopes", "client_credentials_scope_rules", map[string]any{
		"description": "client_credentials grant scope handling in router.go handleClientCredentials (after client auth): split = splitProtocolList(form scope); any of openid/email/profile => 400 invalid_scope; not a subset of splitProtocolList(client.allowed_scopes) => 400 invalid_scope; else the token service normalizes (see token_normalize_scopes) so the response/claim scope is sorted and space-joined. The outcome column mirrors the handler's branch order exactly.",
		"cases":       ccInputs,
	})
}

func TestGoldenMasking(t *testing.T) {
	type maskCase struct {
		Input        string `json:"input"`
		InputHex     string `json:"input_hex"`
		Output       string `json:"output"`
		OutputHex    string `json:"output_hex"`
		ValidUTF8    bool   `json:"output_valid_utf8"`
		JSONRendered string `json:"json_rendered"`
	}
	var cases []maskCase
	for _, in := range []string{
		"alice@example.com",
		"bob@example.com",
		"ab@example.com",
		"a@example.com",
		"@example.com",
		"",
		"no-at-sign",
		"a@b@example.com",
		"alice@",
		"Al.Ice+tag@Example.COM",
		"éa@example.com",
		"ผู้ใช้@example.com",
		"é@example.com",
	} {
		out := maskEmail(in)
		rendered, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		cases = append(cases, maskCase{
			Input: in, InputHex: goldenHex([]byte(in)),
			Output: out, OutputHex: goldenHex([]byte(out)),
			ValidUTF8:    utf8.ValidString(out),
			JSONRendered: string(rendered),
		})
	}
	goldenSection(t, "masking", "mask_email", map[string]any{
		"description": "router.go maskEmail (OTP start/resend response \"email\"). BYTE-based: split on every '@'; if not exactly 2 parts or the local part is empty => unchanged; local <= 2 bytes => local[0] + \"*\" + \"@\" + domain; else local[0] + \"*\" x (len-2) + local[len-1] + \"@\" + domain. Multi-byte local parts are cut mid-rune, producing invalid UTF-8 (see output_hex); gin's c.JSON then renders each invalid byte as \\ufffd (json_rendered is the exact JSON string token on the wire). output is lossy for invalid UTF-8 — use output_hex.",
		"cases":       cases,
	})
}

func TestGoldenDiscovery(t *testing.T) {
	type discoveryCase struct {
		Issuer   string         `json:"jwt_issuer"`
		Alg      string         `json:"jwt_signing_alg"`
		Response goldenResponse `json:"response"`
	}
	var cases []discoveryCase
	for _, issuer := range []string{"https://auth.example.com", "https://auth.example.com/", "http://localhost:8050//"} {
		h := Handler{cfg: config.Config{JWTIssuer: issuer, JWTSigningAlg: "RS256"}}
		c, rec := goldenContext(http.MethodGet, "/.well-known/openid-configuration")
		h.openIDConfiguration(c)
		cases = append(cases, discoveryCase{Issuer: issuer, Alg: "RS256", Response: goldenCapture(c, rec)})
	}
	goldenSection(t, "discovery", "openid_configuration", map[string]any{
		"description": "GET /.well-known/openid-configuration (router.go openIDConfiguration). issuer = strings.TrimRight(JWT_ISSUER, \"/\") (all trailing slashes) — unlike the JWT iss claim, which is untrimmed. Body is gin c.JSON of a map, so keys are sorted; Content-Type \"application/json; charset=utf-8\".",
		"cases":       cases,
	})
}

// goldenClientRepo is a fixed client registry for the authorize vectors.
type goldenClientRepo map[string]domain.OAuthClient

func (r goldenClientRepo) Create(_ context.Context, c domain.OAuthClient) (domain.OAuthClient, error) {
	return c, nil
}

func (r goldenClientRepo) FindByClientID(_ context.Context, id string) (domain.OAuthClient, error) {
	c, ok := r[id]
	if !ok {
		return domain.OAuthClient{}, errors.New("not found")
	}
	return c, nil
}
