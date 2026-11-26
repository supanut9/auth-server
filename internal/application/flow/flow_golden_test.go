package flow

import (
	"encoding/base64"
	"strings"
	"testing"
	"testing/cryptotest"
)

// goldenScopeInputs is shared (by copy) with the oauth, token and http golden
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

func TestGoldenFlowHashes(t *testing.T) {
	type hashCase struct {
		Input string `json:"input"`
		Hash  string `json:"hash,omitempty"`
		Error string `json:"error,omitempty"`
	}
	var hashCases []hashCase
	for _, v := range []string{"", "abc", "authorization-code-value", "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"} {
		_, hash, err := hashSecret(v)
		c := hashCase{Input: v, Hash: hash}
		if err != nil {
			c.Error = err.Error()
		}
		hashCases = append(hashCases, c)
	}
	goldenSection(t, "hashes", "authorization_code_hash", map[string]any{
		"description": "authorization_codes.code_hash = base64url_nopad(SHA-256(code)), unsalted. An empty code fails with ErrAuthorizationCodeExpired (the token endpoint maps every consume failure to invalid_grant). Source: internal/application/flow/service.go hashSecret.",
		"cases":       hashCases,
	})

	type randomCase struct {
		RawHex string `json:"raw_hex"`
		Value  string `json:"value"`
		Hash   string `json:"hash"`
	}
	cryptotest.SetGlobalRandom(t, 32)
	var randomCases []randomCase
	for range 3 {
		value, hash, err := newOpaqueSecret()
		if err != nil {
			t.Fatalf("new opaque secret: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) != 32 || len(value) != 43 {
			t.Fatalf("unexpected code shape %q", value)
		}
		randomCases = append(randomCases, randomCase{RawHex: goldenHex(raw), Value: value, Hash: hash})
	}
	goldenSection(t, "hashes", "authorization_code_random", map[string]any{
		"description": "Authorization code = base64url_nopad(32 random bytes) -> 43 chars. Source: flow/service.go newOpaqueSecret.",
		"cases":       randomCases,
	})
}

func TestGoldenFlowScopes(t *testing.T) {
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
	goldenSection(t, "scopes", "flow_split_scopes", map[string]any{
		"description": "flow/service.go splitScopes (stored consent_grants.scope -> list): \"\" -> null; strings.Fields (any Unicode whitespace, NOT commas), then normalizeScopes (trim, drop empty, dedupe, byte-wise sort). Same behavior as token_split_scopes.",
		"cases":       splitCases,
	})

	type unionCase struct {
		Base   []string `json:"base"`
		Extra  []string `json:"extra"`
		Output []string `json:"output"`
		Joined string   `json:"joined"`
	}
	var unionCases []unionCase
	for _, in := range [][2][]string{
		{nil, nil},
		{{"openid", "profile"}, {"email", "openid"}},
		{{"trading.read"}, {" trading.write ", ""}},
		{{"b", "a"}, nil},
	} {
		out := unionScopes(in[0], in[1])
		unionCases = append(unionCases, unionCase{Base: in[0], Extra: in[1], Output: out, Joined: strings.Join(out, " ")})
	}
	goldenSection(t, "scopes", "flow_union_scopes", map[string]any{
		"description": "flow/service.go unionScopes (consent accept merges the existing grant with the newly approved scopes): normalizeScopes(base ++ extra). Empty -> [] and joined \"\".",
		"cases":       unionCases,
	})

	type subsetCase struct {
		Requested []string `json:"requested"`
		Granted   []string `json:"granted"`
		Subset    bool     `json:"subset"`
	}
	var subsetCases []subsetCase
	for _, in := range [][2][]string{
		{nil, nil},
		{nil, {"openid"}},
		{{"openid"}, nil},
		{{"openid", "email"}, {"email", "openid", "profile"}},
		{{"openid", "trading.write"}, {"openid", "trading.read"}},
		{{"OpenID"}, {"openid"}},
	} {
		subsetCases = append(subsetCases, subsetCase{Requested: in[0], Granted: in[1], Subset: scopeSubset(in[0], in[1])})
	}
	goldenSection(t, "scopes", "flow_scope_subset", map[string]any{
		"description": "flow/service.go scopeSubset (HasConsentForScopes): every requested scope must be in granted; exact, case-sensitive; empty requested -> true.",
		"cases":       subsetCases,
	})
}
