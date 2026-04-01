package jwks

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestManagerSignsAndPublishesJWKS(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	dir := t.TempDir()
	privatePath := filepath.Join(dir, "jwt-private.pem")
	publicPath := filepath.Join(dir, "jwt-public.pem")

	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	}), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	manager, err := NewManager("RS256", privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	signed, err := manager.Sign(map[string]any{
		"iss": "http://localhost:8050",
		"sub": "account-123",
		"aud": "platform-api",
		"exp": float64(4102444800),
		"iat": float64(1700000000),
	})
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	if signed.Token == "" {
		t.Fatal("expected signed token")
	}
	if signed.KeyID == "" {
		t.Fatal("expected key id")
	}

	parsed, err := jwt.Parse(signed.Token, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("expected signed jwt to be valid")
	}

	jwksJSON, err := manager.PublicJWKS()
	if err != nil {
		t.Fatalf("public jwks: %v", err)
	}
	if len(jwksJSON) == 0 {
		t.Fatal("expected jwks json")
	}
}
