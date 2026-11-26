//! PKCE verification at the token endpoint (Go `router.go validatePKCE`).

use crate::crypto::{constant_time_eq, sha256_b64url};

/// `code_challenge_method=S256`.
pub const METHOD_S256: &str = "S256";
/// `code_challenge_method=plain`.
pub const METHOD_PLAIN: &str = "plain";

/// The S256 challenge for `verifier`: `base64url_nopad(SHA-256(verifier))`.
#[must_use]
pub fn s256_challenge(verifier: &str) -> String {
    sha256_b64url(verifier)
}

/// Checks `verifier` against the challenge stored with the authorization code.
///
/// - No stored challenge: valid only when no verifier was sent either.
/// - A stored challenge with an empty verifier is invalid.
/// - Method `""` or `"plain"`: constant-time equality.
/// - Method `"S256"` (case-sensitive): challenge equals
///   [`s256_challenge`]`(verifier)`, constant time.
/// - Any other method is invalid.
///
/// Failure maps to `400 invalid_grant` / `pkce validation failed`.
#[must_use]
pub fn verify(stored_challenge: &str, stored_method: &str, verifier: &str) -> bool {
    if stored_challenge.is_empty() {
        return verifier.is_empty();
    }
    if verifier.is_empty() {
        return false;
    }
    match stored_method {
        "" | METHOD_PLAIN => constant_time_eq(stored_challenge.as_bytes(), verifier.as_bytes()),
        METHOD_S256 => constant_time_eq(
            stored_challenge.as_bytes(),
            s256_challenge(verifier).as_bytes(),
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b() {
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(verify(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "S256",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
        assert!(!verify("x", "S512", "x"));
        assert!(verify("", "", ""));
    }
}
