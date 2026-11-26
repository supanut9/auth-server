package jwks

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"
)

// Test-only RSA key material for golden vectors. NEVER a production key.
const (
	goldenKeyPKCS1 = "keys/test-only-rsa-2048-private-pkcs1.pem"
	goldenKeyPKCS8 = "keys/test-only-rsa-2048-private-pkcs8.pem"
	goldenKeyPKIX  = "keys/test-only-rsa-2048-public-pkix.pem"
	goldenKeyCert  = "keys/test-only-rsa-2048-cert.pem"

	goldenKeySeed = 27 // AUTH-027
)

// TestGoldenGenerateTestKey (re)creates the throwaway key from a fixed seed.
// It only runs with GOLDEN_KEYGEN=1; the committed key is the source of truth
// for every other golden test.
func TestGoldenGenerateTestKey(t *testing.T) {
	if os.Getenv("GOLDEN_KEYGEN") != "1" {
		t.Skip("set GOLDEN_KEYGEN=1 to regenerate the test-only golden key")
	}
	cryptotest.SetGlobalRandom(t, goldenKeySeed)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := filepath.Join(goldenRoot(t), "keys")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(goldenRoot(t), goldenKeyPKCS1), pkcs1, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	for rel, data := range goldenDerivedKeyFiles(t, key) {
		if err := os.WriteFile(filepath.Join(goldenRoot(t), rel), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

// goldenDerivedKeyFiles re-derives the PKCS#8 / PKIX / certificate encodings
// from the PKCS#1 key. All three encodings are deterministic.
func goldenDerivedKeyFiles(t *testing.T, key *rsa.PrivateKey) map[string][]byte {
	t.Helper()
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pkixDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(27),
		Subject:               pkix.Name{CommonName: "auth-server golden vectors TEST ONLY"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		SubjectKeyId:          []byte{0x27},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return map[string][]byte{
		goldenKeyPKCS8: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
		goldenKeyPKIX:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER}),
		goldenKeyCert:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	}
}

func goldenLoadKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := parsePrivateKey(goldenReadFile(t, goldenKeyPKCS1))
	if err != nil {
		t.Fatalf("parse golden key: %v", err)
	}
	return key
}

// TestGoldenKeyFilesConsistent guards the committed key files: the derived
// encodings must still be exactly what Go produces from the PKCS#1 key.
func TestGoldenKeyFilesConsistent(t *testing.T) {
	key := goldenLoadKey(t)
	for rel, want := range goldenDerivedKeyFiles(t, key) {
		if got := goldenReadFile(t, rel); !bytes.Equal(got, want) {
			t.Fatalf("%s does not match the encoding derived from %s; rerun GOLDEN_KEYGEN=1", rel, goldenKeyPKCS1)
		}
	}
}

func TestGoldenJWKS(t *testing.T) {
	key := goldenLoadKey(t)
	pkcs1 := string(goldenReadFile(t, goldenKeyPKCS1))
	pkcs8 := string(goldenReadFile(t, goldenKeyPKCS8))
	pkix := string(goldenReadFile(t, goldenKeyPKIX))
	cert := string(goldenReadFile(t, goldenKeyCert))

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	sum := sha256.Sum256(spki)
	kid, err := computeKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("compute kid: %v", err)
	}
	goldenSection(t, "jwks", "kid", map[string]any{
		"description":     "kid = base64url_nopad(SHA-256(SPKI/PKIX DER of the RSA public key)). Source: internal/adapter/out/jwks/manager.go computeKeyID.",
		"public_key_file": goldenKeyPKIX,
		"spki_der_hex":    goldenHex(spki),
		"sha256_hex":      goldenHex(sum[:]),
		"kid":             kid,
	})

	manager, err := NewManagerWithSources("RS256", "", "", pkcs1, pkix)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	doc, err := manager.PublicJWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	goldenSection(t, "jwks", "jwks_document", map[string]any{
		"description": "Exact bytes of GET /.well-known/jwks.json (Manager.PublicJWKS, served with c.Data so Content-Type is exactly \"application/json\"). Field order kty,use,alg,kid,n,e; n = base64url_nopad(big-endian modulus, no leading zero); e via encodeInt.",
		"alg":         "RS256",
		"document":    string(doc),
		"n":           base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":           encodeInt(key.E),
	})

	type intCase struct {
		Input  int    `json:"input"`
		Output string `json:"output"`
	}
	var intCases []intCase
	for _, v := range []int{65537, 3, 1, 255, 256, 0} {
		intCases = append(intCases, intCase{Input: v, Output: encodeInt(v)})
	}
	goldenSection(t, "jwks", "encode_int", map[string]any{
		"description": "JWK exponent encoding: minimal big-endian bytes, base64url_nopad; 0 encodes to the empty string. Source: manager.go encodeInt.",
		"cases":       intCases,
	})

	type pemCase struct {
		Name          string `json:"name"`
		PrivateSource string `json:"private_source"`
		PublicSource  string `json:"public_source"`
		PrivatePEM    string `json:"private_pem,omitempty"`
		PublicPEM     string `json:"public_pem,omitempty"`
		PrivateTweak  string `json:"private_transform,omitempty"`
		Accepted      bool   `json:"accepted"`
		KID           string `json:"kid,omitempty"`
		Error         string `json:"error,omitempty"`
		ErrorNote     string `json:"error_note,omitempty"`
	}
	sources := map[string]string{
		goldenKeyPKCS1: pkcs1,
		goldenKeyPKCS8: pkcs8,
		goldenKeyPKIX:  pkix,
		goldenKeyCert:  cert,
	}
	cases := []pemCase{
		{Name: "pkcs1_private+pkix_public", PrivateSource: goldenKeyPKCS1, PublicSource: goldenKeyPKIX},
		{Name: "pkcs8_private+pkix_public", PrivateSource: goldenKeyPKCS8, PublicSource: goldenKeyPKIX},
		{Name: "pkcs1_private+x509_certificate_public", PrivateSource: goldenKeyPKCS1, PublicSource: goldenKeyCert},
		{Name: "leading_text_before_pem_is_skipped", PrivateSource: goldenKeyPKCS1, PublicSource: goldenKeyPKIX,
			PrivateTweak: "prepend_text_line"},
		{Name: "private_not_pem", PrivateSource: "inline", PublicSource: goldenKeyPKIX, PrivatePEM: "not a pem"},
		{Name: "private_escaped_newlines", PrivateSource: goldenKeyPKCS1, PublicSource: goldenKeyPKIX,
			PrivateTweak: "escape_newlines"},
		{Name: "public_not_pem", PrivateSource: goldenKeyPKCS1, PublicSource: "inline", PublicPEM: "not a pem"},
		{Name: "private_is_public_key", PrivateSource: goldenKeyPKIX, PublicSource: goldenKeyPKIX,
			ErrorNote: "Go x509 error text; informational (boot-time config error)"},
		{Name: "public_is_private_key", PrivateSource: goldenKeyPKCS1, PublicSource: goldenKeyPKCS1,
			ErrorNote: "Go x509 error text; informational (boot-time config error)"},
	}
	for i := range cases {
		c := &cases[i]
		privatePEM := c.PrivatePEM
		if c.PrivateSource != "inline" {
			privatePEM = sources[c.PrivateSource]
		}
		switch c.PrivateTweak {
		case "prepend_text_line":
			privatePEM = "comment line before the block\n" + privatePEM
		case "escape_newlines":
			privatePEM = strings.ReplaceAll(strings.TrimSpace(privatePEM), "\n", `\n`)
		}
		publicPEM := c.PublicPEM
		if c.PublicSource != "inline" {
			publicPEM = sources[c.PublicSource]
		}
		m, err := NewManagerWithSources("RS256", "", "", privatePEM, publicPEM)
		if err != nil {
			c.Error = err.Error()
			continue
		}
		c.Accepted = true
		c.KID = m.keyID
	}
	goldenSection(t, "jwks", "pem_variants", map[string]any{
		"description": "PEM sources accepted by NewManagerWithSources (JWT_PRIVATE_KEY_PEM / JWT_PUBLIC_KEY_PEM). Private: PKCS#1 then PKCS#8 (RSA only). Public: PKIX then X.509 certificate. Text before the first PEM block is ignored by pem.Decode. Go never checks that the private and public keys match. *_source names a file under testdata/golden or \"inline\" (then *_pem holds the value). private_transform: prepend_text_line = \"comment line before the block\\n\" + file; escape_newlines = TrimSpace(file) with every newline replaced by the two characters backslash-n (a common env-var mistake; Go rejects it).",
		"cases":       cases,
	})

	_, err = Manager{alg: "ES256", keyID: kid, privateKey: key, publicKey: &key.PublicKey}.Sign(map[string]any{"sub": "x"})
	goldenSection(t, "jwks", "sign_errors", map[string]any{
		"description": "Manager.Sign only supports RS256 (JWT_SIGNING_ALG).",
		"cases": []map[string]string{
			{"alg": "ES256", "error": err.Error()},
		},
	})
}
