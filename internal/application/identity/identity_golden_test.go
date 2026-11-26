package identity

import (
	"encoding/base64"
	"testing"
	"testing/cryptotest"
)

func TestGoldenOTPHashes(t *testing.T) {
	type hashCase struct {
		Input string `json:"input"`
		Hash  string `json:"hash,omitempty"`
		Error string `json:"error,omitempty"`
	}
	var hashCases []hashCase
	for _, v := range []string{"", "AbCd-_12", "12345678", "abc", " AbCd-_12"} {
		_, hash, err := hashOTPCode(v)
		c := hashCase{Input: v, Hash: hash}
		if err != nil {
			c.Error = err.Error()
		}
		hashCases = append(hashCases, c)
	}
	goldenSection(t, "hashes", "otp_code_hash", map[string]any{
		"description": "otp_challenges.code_hash = base64url_nopad(SHA-256(code)), unsalted, no trimming or case folding of the submitted code. Source: internal/application/identity/service.go hashOTPCode.",
		"cases":       hashCases,
	})

	cryptotest.SetGlobalRandom(t, 6)
	type codeCase struct {
		RawHex string `json:"raw_hex"`
		Code   string `json:"code"`
		Hash   string `json:"hash"`
	}
	var codeCases []codeCase
	for range 4 {
		code, err := randomOTPCodeGenerator{}.NewCode()
		if err != nil {
			t.Fatalf("otp code: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(code)
		if err != nil || len(raw) != 6 || len(code) != 8 {
			t.Fatalf("unexpected otp shape %q", code)
		}
		_, hash, _ := hashOTPCode(code)
		codeCases = append(codeCases, codeCase{RawHex: goldenHex(raw), Code: code, Hash: hash})
	}
	goldenSection(t, "hashes", "otp_code_random", map[string]any{
		"description": "OTP code = base64url_nopad(6 random bytes) -> 8 chars from [A-Za-z0-9_-] (not digits). Source: identity/service.go randomOTPCodeGenerator.",
		"cases":       codeCases,
	})
}
