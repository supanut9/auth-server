//! `testdata/golden/jwt.json`: every recorded compact JWS must be reproduced
//! byte for byte from its claims (RS256 PKCS#1 v1.5 is deterministic), and
//! must verify with golang-jwt v5 default semantics.

mod golden_support;

use std::sync::Arc;

use auth_adapters::jwks::JwksManager;
use auth_core::crypto::decode_b64url_go;
use auth_core::ports::{JwtClaims, JwtSigner, JwtVerifier};
use golden_support::{FixedClock, load, read_text, s, unix};
use serde_json::Value;

const PKCS1: &str = "keys/test-only-rsa-2048-private-pkcs1.pem";
const PKIX: &str = "keys/test-only-rsa-2048-public-pkix.pem";

/// Every object carrying a recorded token, with a path for messages.
fn recorded_tokens<'a>(value: &'a Value, path: String, out: &mut Vec<(String, &'a Value)>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("compact") && map.contains_key("claims_json") {
                out.push((path, value));
                return;
            }
            for (key, child) in map {
                recorded_tokens(child, format!("{path}.{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let name = child["name"]
                    .as_str()
                    .map_or_else(|| index.to_string(), str::to_owned);
                recorded_tokens(child, format!("{path}[{name}]"), out);
            }
        }
        _ => {}
    }
}

fn decoded_segment(compact: &str, index: usize) -> String {
    let segment = compact.split('.').nth(index).expect("segment");
    String::from_utf8(decode_b64url_go(segment.as_bytes()).expect("b64")).expect("utf8")
}

#[test]
fn every_recorded_token_reproduces_and_verifies() {
    let doc = load("jwt.json");
    let mut tokens = Vec::new();
    recorded_tokens(&doc, "jwt".into(), &mut tokens);
    // user_tokens: 3 access + 2 id; client_credentials: 2; refresh: 1 + 1 + 1.
    assert_eq!(
        tokens.len(),
        10,
        "{:?}",
        tokens.iter().map(|t| &t.0).collect::<Vec<_>>()
    );

    let manager = JwksManager::from_pem(
        "RS256",
        read_text(PKCS1).as_bytes(),
        read_text(PKIX).as_bytes(),
    )
    .expect("manager");

    for (path, token) in tokens {
        let claims: JwtClaims = serde_json::from_str(s(token, "claims_json")).expect("claims");
        let signed = manager.sign(&claims).expect("sign");
        assert_eq!(signed.alg, "RS256");
        assert_eq!(signed.key_id, manager.key_id());
        assert_eq!(
            decoded_segment(&signed.token, 0),
            s(token, "header_json"),
            "{path}: header"
        );
        assert_eq!(
            decoded_segment(&signed.token, 1),
            s(token, "claims_json"),
            "{path}: claims"
        );
        let (signing_input, signature) = signed.token.rsplit_once('.').expect("dots");
        assert_eq!(
            signing_input,
            s(token, "signing_input"),
            "{path}: signing input"
        );
        assert_eq!(signature, s(token, "signature_b64url"), "{path}: signature");
        assert_eq!(signed.token, s(token, "compact"), "{path}: compact");

        let iat = claims["iat"].as_i64().expect("iat");
        let exp = claims["exp"].as_i64().expect("exp");
        let at = |now: i64| manager.clone().with_clock(Arc::new(FixedClock(unix(now))));
        assert_eq!(
            at(iat).verify(s(token, "compact")).expect("valid at iat"),
            claims,
            "{path}"
        );
        assert!(at(exp - 1).verify(s(token, "compact")).is_ok(), "{path}");
        assert_eq!(
            at(exp)
                .verify(s(token, "compact"))
                .expect_err("expired at exp")
                .to_string(),
            "token has invalid claims: token is expired",
            "{path}"
        );
    }
}

#[test]
fn verifier_rejects_tampering_and_other_algs() {
    let manager = JwksManager::from_pem(
        "RS256",
        read_text(PKCS1).as_bytes(),
        read_text(PKIX).as_bytes(),
    )
    .expect("manager")
    .with_clock(Arc::new(FixedClock(unix(1_775_044_800))));
    let mut claims = JwtClaims::new();
    claims.insert("sub".into(), Value::from("abc"));
    claims.insert("exp".into(), Value::from(1_775_045_400_i64));
    let token = manager.sign(&claims).expect("sign").token;
    assert_eq!(manager.verify(&token).expect("valid"), claims);

    let (header, rest) = token.split_once('.').expect("dot");
    let (_, signature) = rest.split_once('.').expect("dot");
    let forged_claims = auth_core::crypto::b64url_encode(r#"{"exp":1775045400,"sub":"evil"}"#);
    let cases = [
        (
            format!("{header}.{forged_claims}.{signature}"),
            "token signature is invalid: crypto/rsa: verification error",
        ),
        (
            "a.b".to_owned(),
            "token is malformed: token contains an invalid number of segments",
        ),
        (
            format!(
                "{}.{rest}",
                auth_core::crypto::b64url_encode(r#"{"alg":"HS256","typ":"JWT"}"#)
            ),
            "token is unverifiable: error while executing keyfunc: unexpected signing alg: HS256",
        ),
        (
            format!(
                "{}.{rest}",
                auth_core::crypto::b64url_encode(r#"{"alg":"XX1"}"#)
            ),
            "token is unverifiable: signing method (alg) is unavailable",
        ),
        (
            format!(
                "{}.{rest}",
                auth_core::crypto::b64url_encode(r#"{"typ":"JWT"}"#)
            ),
            "token is unverifiable: signing method (alg) is unspecified",
        ),
        (
            format!("@{token}"),
            "token is malformed: could not base64 decode header: illegal base64 data at input byte 0",
        ),
    ];
    for (input, want) in cases {
        assert_eq!(manager.verify(&input).expect_err(want).to_string(), want);
    }
}
