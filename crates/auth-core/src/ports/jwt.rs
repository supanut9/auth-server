use super::JwtError;

/// JWT claim set. `serde_json::Map` is a `BTreeMap`, so keys serialize sorted
/// like Go's `map[string]any`.
pub type JwtClaims = serde_json::Map<String, serde_json::Value>;

/// A signed compact JWT (`port.SignedJWT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedJwt {
    pub token: String,
    pub key_id: String,
    pub alg: String,
}

/// `port.JWTSigner`.
pub trait JwtSigner: Send + Sync {
    fn sign(&self, claims: &JwtClaims) -> Result<SignedJwt, JwtError>;
}

/// `port.JWKSProvider`: the serialized public JWK Set document.
pub trait JwksProvider: Send + Sync {
    fn public_jwks(&self) -> Result<Vec<u8>, JwtError>;
}

/// `port.JWTVerifier`: checks signature and expiry, returns the claims.
pub trait JwtVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<JwtClaims, JwtError>;
}
