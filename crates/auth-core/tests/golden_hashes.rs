//! `testdata/golden/hashes.json`: digests, random encodings, client secrets
//! and PKCE.

mod golden_support;

use std::collections::BTreeSet;
use std::sync::Arc;

use auth_core::crypto::{
    RandomOtpCodeGenerator, client_secret_storage, hash_opaque, match_client_secret, new_jti,
    new_opaque_secret, new_otp_code,
};
use auth_core::flow::FlowError;
use auth_core::identity::IdentityError;
use auth_core::oauth::pkce;
use auth_core::ports::OtpCodeGenerator;
use auth_core::token::TokenError;
use golden_support::{ScriptedRandom, cases, load, opt, s, sections};

fn doc() -> serde_json::Value {
    load("hashes.json")
}

#[test]
fn every_section_is_covered() {
    let want: BTreeSet<String> = [
        "authorization_code_hash",
        "authorization_code_random",
        "client_secret_match",
        "client_secret_storage",
        "envelope_jti_random",
        "http_opaque_token_hash",
        "otp_code_hash",
        "otp_code_random",
        "pkce_verify",
        "refresh_token_hash",
        "refresh_token_random",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        sections(&doc()),
        want,
        "a new hashes.json section needs a test"
    );
}

/// Hash sections: empty input yields `None`; the caller's error must carry
/// Go's text.
fn check_hash_section(section: &str, empty_error: Option<String>) -> usize {
    let doc = doc();
    let cases = cases(&doc, section);
    for case in cases {
        let input = s(case, "input");
        match case.get("hash").and_then(|h| h.as_str()) {
            Some(hash) => assert_eq!(
                hash_opaque(input).as_deref(),
                Some(hash),
                "{section} {input:?}"
            ),
            None => {
                assert_eq!(hash_opaque(input), None, "{section} {input:?}");
                if let Some(text) = &empty_error {
                    assert_eq!(s(case, "error"), text, "{section} empty-input error text");
                }
            }
        }
    }
    cases.len()
}

#[test]
fn authorization_code_hash() {
    let n = check_hash_section(
        "authorization_code_hash",
        Some(FlowError::AuthorizationCodeExpired.to_string()),
    );
    assert_eq!(n, 4);
}

#[test]
fn refresh_token_hash() {
    let n = check_hash_section(
        "refresh_token_hash",
        Some(TokenError::EmptyToken.to_string()),
    );
    assert_eq!(n, 4);
}

#[test]
fn otp_code_hash() {
    let n = check_hash_section(
        "otp_code_hash",
        Some(IdentityError::EmptyOtpCode.to_string()),
    );
    assert_eq!(n, 5);
}

#[test]
fn http_opaque_token_hash() {
    // The HTTP layer owns the "empty token" short-circuit (revoke => 200,
    // introspect => inactive); only the digest rule is checked here.
    let n = check_hash_section("http_opaque_token_hash", None);
    assert_eq!(n, 3);
}

#[test]
fn opaque_random_encodings() {
    let doc = doc();
    for section in ["authorization_code_random", "refresh_token_random"] {
        for case in cases(&doc, section) {
            let random = ScriptedRandom::from_hex(s(case, "raw_hex"));
            let secret = new_opaque_secret(&random).expect("random");
            assert_eq!(secret.value, s(case, "value"), "{section}");
            assert_eq!(secret.value.len(), 43);
            assert_eq!(secret.hash, s(case, "hash"), "{section}");
        }
    }
}

#[test]
fn envelope_jti_random() {
    let doc = doc();
    let cases = cases(&doc, "envelope_jti_random");
    for case in cases {
        let random = ScriptedRandom::from_hex(s(case, "raw_hex"));
        let jti = new_jti(&random).expect("random");
        assert_eq!(jti, s(case, "value"));
        assert_eq!(jti.len(), 22);
    }
    assert_eq!(cases.len(), 3);
}

#[test]
fn otp_code_random() {
    let doc = doc();
    let cases = cases(&doc, "otp_code_random");
    for case in cases {
        let code = new_otp_code(&ScriptedRandom::from_hex(s(case, "raw_hex"))).expect("random");
        assert_eq!(code, s(case, "code"));
        assert_eq!(hash_opaque(&code).as_deref(), Some(s(case, "hash")));

        let generator =
            RandomOtpCodeGenerator::new(Arc::new(ScriptedRandom::from_hex(s(case, "raw_hex"))));
        assert_eq!(generator.new_code().expect("random"), s(case, "code"));
    }
    assert_eq!(cases.len(), 4);
}

#[test]
fn client_secret_storage_and_match() {
    let doc = doc();
    let storage = cases(&doc, "client_secret_storage");
    for case in storage {
        let stored = client_secret_storage(s(case, "secret"));
        assert_eq!(stored, s(case, "stored"));
        if !s(case, "secret").is_empty() {
            assert!(match_client_secret(&stored, s(case, "secret")));
        }
    }
    let matches = cases(&doc, "client_secret_match");
    for case in matches {
        assert_eq!(
            match_client_secret(s(case, "stored"), s(case, "provided")),
            case["match"].as_bool().expect("match"),
            "{}",
            s(case, "name")
        );
    }
    assert_eq!((storage.len(), matches.len()), (4, 9));
}

#[test]
fn pkce_verify() {
    let doc = doc();
    let cases = cases(&doc, "pkce_verify");
    for case in cases {
        assert_eq!(
            pkce::verify(
                opt(case, "challenge"),
                opt(case, "method"),
                opt(case, "verifier")
            ),
            case["valid"].as_bool().expect("valid"),
            "{}",
            s(case, "name")
        );
    }
    assert_eq!(cases.len(), 13);
}
