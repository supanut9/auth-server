package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"
)

const goldenEnvelopeSecret = "golden-envelope-secret-TEST-ONLY-0123456789abcdef"

func goldenEnvelopeSigner(t *testing.T, now time.Time) *EnvelopeSigner {
	t.Helper()
	s, err := NewEnvelopeSigner([]byte(goldenEnvelopeSecret), 10*time.Minute, NewMemoryJTIStore())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s.now = func() time.Time { return now }
	return s
}

// goldenHMAC signs an arbitrary payload exactly as EnvelopeSigner.Sign does,
// used only to build verify inputs Sign itself can never emit (missing jti,
// non-JSON payload).
func goldenHMAC(payload []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(goldenEnvelopeSecret))
	mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestGoldenEnvelope(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

	type signCase struct {
		Name         string   `json:"name"`
		Envelope     Envelope `json:"envelope"`
		JTI          string   `json:"jti"`
		PayloadJSON  string   `json:"payload_json"`
		PayloadB64   string   `json:"payload_b64url"`
		SignatureB64 string   `json:"signature_b64url"`
		Token        string   `json:"token"`
	}
	inputs := []struct {
		name string
		env  Envelope
	}{
		{"required_fields_only", Envelope{
			Provider: "google", ClientID: "trading-web", RedirectURI: "https://trading.example.com/callback",
			Scope: "openid email profile", State: "st-123",
		}},
		{"all_fields", Envelope{
			Provider: "github", ClientID: "language-web", RedirectURI: "https://language.example.com/auth/callback",
			Scope: "email openid profile", State: "s", Nonce: "n-456",
			CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256", Prompt: "login",
		}},
		{"html_escapable_chars", Envelope{
			Provider: "google", ClientID: "c&<>", RedirectURI: "https://app.example.com/cb?a=1&b=<2>",
			Scope: "openid", State: "x&y<z>'\"", Nonce: "a>b",
		}},
		{"unicode_and_line_separators", Envelope{
			Provider: "google", ClientID: "trading-web", RedirectURI: "https://trading.example.com/callback",
			Scope: "openid", State: "สวัสดี  \t/\\", CodeChallengeMethod: "plain",
		}},
		{"empty_required_fields", Envelope{}},
	}
	var signCases []signCase
	for i, in := range inputs {
		cryptotest.SetGlobalRandom(t, uint64(1000+i))
		token, err := goldenEnvelopeSigner(t, now).Sign(in.env)
		if err != nil {
			t.Fatalf("%s: sign: %v", in.name, err)
		}
		payloadB64, sig, _ := strings.Cut(token, ".")
		payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
		if err != nil {
			t.Fatalf("%s: decode: %v", in.name, err)
		}
		var claims envelopeClaims
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("%s: claims: %v", in.name, err)
		}
		signCases = append(signCases, signCase{
			Name: in.name, Envelope: in.env, JTI: claims.JTI,
			PayloadJSON: string(payload), PayloadB64: payloadB64, SignatureB64: sig, Token: token,
		})
	}
	goldenSection(t, "envelope", "sign", map[string]any{
		"description": "EnvelopeSigner.Sign (internal/application/oauth/envelope.go). token = b64url_nopad(payload) + \".\" + b64url_nopad(HMAC-SHA256(secret, b64url_nopad(payload))) — the MAC covers the base64 text, not the raw JSON. payload = encoding/json of {provider,client_id,redirect_uri,scope,state,nonce?,code_challenge?,code_challenge_method?,prompt?,iat,exp,jti} in exactly that order; optional fields are omitted when empty; encoding/json escapes & < > as \\u0026 \\u003c \\u003e and U+2028/U+2029 as \\u2028/\\u2029. jti = b64url_nopad(16 random bytes) (22 chars; Go draws it from crypto/rand, recorded here as an input). iat = now (unix s), exp = now + ttl.",
		"secret":      goldenEnvelopeSecret,
		"ttl_seconds": 600,
		"now_unix":    now.Unix(),
		"cases":       signCases,
	})

	// Verify cases. Every case uses a fresh signer (fresh JTI store) unless it
	// is the replay case.
	base := signCases[1]
	exp := now.Add(10 * time.Minute)
	type verifyCase struct {
		Name     string    `json:"name"`
		Token    string    `json:"token"`
		NowUnix  int64     `json:"now_unix"`
		Attempt  int       `json:"attempt"`
		OK       bool      `json:"ok"`
		Envelope *Envelope `json:"envelope,omitempty"`
		Error    string    `json:"error,omitempty"`
		Note     string    `json:"note,omitempty"`
	}
	tamperSig := base.PayloadB64 + "." + flipLast(base.SignatureB64)
	tamperPayload := flipLast(base.PayloadB64) + "." + base.SignatureB64
	missingJTI := goldenHMAC([]byte(`{"provider":"google","client_id":"trading-web","redirect_uri":"https://trading.example.com/callback","scope":"openid","state":"s","iat":1775044800,"exp":1775045400}`))
	emptyJTI := goldenHMAC([]byte(`{"provider":"google","client_id":"trading-web","redirect_uri":"https://trading.example.com/callback","scope":"openid","state":"s","iat":1775044800,"exp":1775045400,"jti":""}`))
	expiredNoJTI := goldenHMAC([]byte(`{"provider":"google","exp":1775045400}`))
	notJSON := goldenHMAC([]byte(`not json`))
	unknownFields := goldenHMAC([]byte(`{"provider":"google","client_id":"c","redirect_uri":"https://a.example/cb","scope":"openid","state":"s","extra":true,"iat":1,"exp":1775045400,"jti":"jti-unknown-fields"}`))
	badB64 := func() string {
		encoded := "@@@"
		mac := hmac.New(sha256.New, []byte(goldenEnvelopeSecret))
		mac.Write([]byte(encoded))
		return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}()

	verifyInputs := []verifyCase{
		{Name: "valid_at_iat", Token: base.Token, NowUnix: now.Unix()},
		{Name: "valid_at_exactly_exp", Token: base.Token, NowUnix: exp.Unix(), Note: "expiry check is now > exp"},
		{Name: "expired_at_exp_plus_1", Token: base.Token, NowUnix: exp.Unix() + 1},
		{Name: "valid_before_iat", Token: base.Token, NowUnix: now.Unix() - 3600, Note: "iat is never checked"},
		{Name: "tampered_signature", Token: tamperSig, NowUnix: now.Unix()},
		{Name: "tampered_payload", Token: tamperPayload, NowUnix: now.Unix()},
		{Name: "signature_with_padding", Token: base.Token + "=", NowUnix: now.Unix()},
		{Name: "extra_dot_segment", Token: base.Token + ".x", NowUnix: now.Unix(), Note: "SplitN(token, \".\", 2): everything after the first dot is the signature"},
		{Name: "malformed_no_dot", Token: base.PayloadB64, NowUnix: now.Unix()},
		{Name: "malformed_empty", Token: "", NowUnix: now.Unix()},
		{Name: "wrong_secret", Token: wrongSecretToken(base.PayloadB64), NowUnix: now.Unix()},
		{Name: "missing_jti", Token: missingJTI, NowUnix: now.Unix()},
		{Name: "empty_jti", Token: emptyJTI, NowUnix: now.Unix()},
		{Name: "expired_checked_before_jti", Token: expiredNoJTI, NowUnix: exp.Unix() + 1},
		{Name: "payload_not_base64", Token: badB64, NowUnix: now.Unix(), Note: "error text wraps Go's base64 error (returned to the client as error_description)"},
		{Name: "payload_not_json", Token: notJSON, NowUnix: now.Unix(), Note: "error text wraps Go's encoding/json error (returned to the client as error_description)"},
		{Name: "unknown_fields_ignored", Token: unknownFields, NowUnix: now.Unix()},
	}
	var verifyCases []verifyCase
	for _, vc := range verifyInputs {
		vc.Attempt = 1
		verifyCases = append(verifyCases, runVerify(t, vc.NowUnix, vc.Token, func(env *Envelope, err error) verifyCase {
			vc.OK = err == nil
			if err != nil {
				vc.Error = err.Error()
			} else {
				vc.Envelope = env
			}
			return vc
		}))
	}
	// Replay: the same signer verifies the same token twice.
	replaySigner := goldenEnvelopeSigner(t, now)
	for attempt := 1; attempt <= 2; attempt++ {
		env, err := replaySigner.Verify(base.Token)
		vc := verifyCase{Name: "replay", Token: base.Token, NowUnix: now.Unix(), Attempt: attempt, OK: err == nil}
		if err != nil {
			vc.Error = err.Error()
		} else {
			vc.Envelope = &env
		}
		verifyCases = append(verifyCases, vc)
	}
	goldenSection(t, "envelope", "verify", map[string]any{
		"description": "EnvelopeSigner.Verify with the sign section's secret. Order: split on first \".\" -> HMAC compare (constant time, over the base64 text) -> base64 decode -> JSON decode -> now > exp -> jti != \"\" -> JTI store insert (replay => \"oauth: jti replay\"). The callback handler returns error as {\"error\":\"invalid_state\",\"error_description\":<error>}. attempt counts verifications of the same token against one JTI store.",
		"secret":      goldenEnvelopeSecret,
		"cases":       verifyCases,
	})

	_, shortErr := NewEnvelopeSigner([]byte("too-short"), time.Minute, NewMemoryJTIStore())
	defaulted, _ := NewEnvelopeSigner([]byte(goldenEnvelopeSecret), 0, NewMemoryJTIStore())
	goldenSection(t, "envelope", "constructor", map[string]any{
		"description":                  "NewEnvelopeSigner: secret must be >= 32 bytes; ttl <= 0 defaults to 10m.",
		"short_secret_error":           shortErr.Error(),
		"zero_ttl_defaults_to_seconds": int64(defaulted.ttl.Seconds()),
	})

	cryptotest.SetGlobalRandom(t, 16)
	type jtiCase struct {
		RawHex string `json:"raw_hex"`
		Value  string `json:"value"`
	}
	var jtiCases []jtiCase
	for range 3 {
		v, err := randomJTI()
		if err != nil {
			t.Fatalf("jti: %v", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(v)
		if len(raw) != 16 || len(v) != 22 {
			t.Fatalf("unexpected jti shape %q", v)
		}
		jtiCases = append(jtiCases, jtiCase{RawHex: goldenHex(raw), Value: v})
	}
	goldenSection(t, "hashes", "envelope_jti_random", map[string]any{
		"description": "Envelope jti = base64url_nopad(16 random bytes) -> 22 chars. Source: oauth/envelope.go randomJTI.",
		"cases":       jtiCases,
	})
}

func runVerify[T any](t *testing.T, nowUnix int64, token string, build func(*Envelope, error) T) T {
	t.Helper()
	env, err := goldenEnvelopeSigner(t, time.Unix(nowUnix, 0).UTC()).Verify(token)
	if err != nil {
		return build(nil, err)
	}
	return build(&env, nil)
}

func wrongSecretToken(payloadB64 string) string {
	mac := hmac.New(sha256.New, []byte("a-different-secret-of-at-least-32-bytes!"))
	mac.Write([]byte(payloadB64))
	return payloadB64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// flipLast changes the final base64url character to a different valid one.
func flipLast(s string) string {
	last := s[len(s)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return s[:len(s)-1] + string(repl)
}

// goldenScopeInputs is shared (by copy) with the token, flow and http golden
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

func TestGoldenOAuthScopes(t *testing.T) {
	type scopeCase struct {
		Input  string   `json:"input"`
		Output []string `json:"output"`
		Joined string   `json:"joined"`
	}
	var cases []scopeCase
	for _, in := range goldenScopeInputs {
		out := splitScopes(in)
		cases = append(cases, scopeCase{Input: in, Output: out, Joined: strings.Join(out, " ")})
	}
	goldenSection(t, "scopes", "oauth_split_scopes", map[string]any{
		"description": "oauth/validate.go splitScopes, used by Validate for the request scope and client.AllowedScopes: \"\" -> null; split on ' ', ',', '\\n', '\\t' only (NOT \\r or U+00A0), trim each field (TrimSpace strips \\r, U+00A0, ...), drop empty, dedupe, byte-wise sort. Validated.Request.Scope is the space-joined result (canonical scope echoed to auth-ui /consent).",
		"cases":       cases,
	})
}
