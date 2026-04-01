package port

type SignedJWT struct {
	Token string
	KeyID string
	Alg   string
}

type JWTSigner interface {
	Sign(claims map[string]any) (SignedJWT, error)
}

type JWKSProvider interface {
	PublicJWKS() ([]byte, error)
}
