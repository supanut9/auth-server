package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/supanut9/auth-server/internal/port"
)

type Manager struct {
	alg        string
	keyID      string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewManager(alg string, privateKeyPath string, publicKeyPath string) (Manager, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return Manager{}, err
	}

	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return Manager{}, err
	}

	keyID, err := computeKeyID(publicKey)
	if err != nil {
		return Manager{}, err
	}

	return Manager{
		alg:        alg,
		keyID:      keyID,
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
}

func (m Manager) Sign(claims map[string]any) (port.SignedJWT, error) {
	if m.alg != "RS256" {
		return port.SignedJWT{}, fmt.Errorf("unsupported signing alg: %s", m.alg)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = m.keyID
	token.Header["typ"] = "JWT"

	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return port.SignedJWT{}, err
	}

	return port.SignedJWT{
		Token: signed,
		KeyID: m.keyID,
		Alg:   m.alg,
	}, nil
}

func (m Manager) PublicJWKS() ([]byte, error) {
	doc := jwksDocument{
		Keys: []jwkKey{
			{
				KTY: "RSA",
				Use: "sig",
				Alg: m.alg,
				KID: m.keyID,
				N:   base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes()),
				E:   encodeInt(m.publicKey.E),
			},
		},
	}

	return json.Marshal(doc)
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("decode private key PEM: no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parse private key: expected RSA private key")
	}

	return key, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("decode public key PEM: no PEM block found")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("parse public key: expected RSA public key")
		}
		return key, nil
	}

	cert, certErr := x509.ParseCertificate(block.Bytes)
	if certErr != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parse public key: expected RSA public key in certificate")
	}

	return key, nil
}

func computeKeyID(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func encodeInt(v int) string {
	if v == 0 {
		return ""
	}

	buf := []byte{}
	for n := v; n > 0; n >>= 8 {
		buf = append([]byte{byte(n & 0xff)}, buf...)
	}

	return base64.RawURLEncoding.EncodeToString(buf)
}
