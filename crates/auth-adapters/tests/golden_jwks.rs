//! `testdata/golden/jwks.json`: kid derivation, JWKS bytes, PEM variants and
//! sign errors.

mod golden_support;

use std::collections::BTreeSet;

use auth_adapters::jwks::{
    JwksManager, KeyError, compute_key_id, encode_int, parse_public_key, spki_der,
};
use auth_core::ports::{JwksProvider, JwtClaims, JwtSigner};
use golden_support::{cases, i, load, read_text, s, sections};
use rsa::sha2::{Digest as _, Sha256};
use serde_json::Value;

const PKCS1: &str = "keys/test-only-rsa-2048-private-pkcs1.pem";
const PKIX: &str = "keys/test-only-rsa-2048-public-pkix.pem";

#[test]
fn every_section_is_covered() {
    let want: BTreeSet<String> = [
        "encode_int",
        "jwks_document",
        "kid",
        "pem_variants",
        "sign_errors",
    ]
    .map(String::from)
    .into();
    assert_eq!(sections(&load("jwks.json")), want);
}

#[test]
fn encode_int_cases() {
    let doc = load("jwks.json");
    let cases = cases(&doc, "encode_int");
    for case in cases {
        assert_eq!(encode_int(i(case, "input")), s(case, "output"), "{case}");
    }
    assert_eq!(cases.len(), 6);
}

#[test]
fn kid_from_spki_der() {
    let doc = load("jwks.json");
    let section = &doc["kid"];
    let public =
        parse_public_key(read_text(s(section, "public_key_file")).as_bytes()).expect("public key");
    let der = spki_der(&public).expect("der");
    assert_eq!(hex::encode(&der), s(section, "spki_der_hex"));
    assert_eq!(hex::encode(Sha256::digest(&der)), s(section, "sha256_hex"));
    assert_eq!(compute_key_id(&public).expect("kid"), s(section, "kid"));
}

#[test]
fn jwks_document_bytes() {
    let doc = load("jwks.json");
    let section = &doc["jwks_document"];
    let manager = JwksManager::from_pem(
        s(section, "alg"),
        read_text(PKCS1).as_bytes(),
        read_text(PKIX).as_bytes(),
    )
    .expect("manager");
    let bytes = manager.public_jwks().expect("jwks");
    assert_eq!(
        String::from_utf8(bytes).expect("utf8"),
        s(section, "document")
    );

    let parsed: Value = serde_json::from_str(s(section, "document")).expect("json");
    assert_eq!(parsed["keys"][0]["n"], section["n"]);
    assert_eq!(parsed["keys"][0]["e"], section["e"]);
}

fn source(case: &Value, which: &str) -> String {
    let file = s(case, &format!("{which}_source"));
    let raw = if file == "inline" {
        s(case, &format!("{which}_pem")).to_owned()
    } else {
        read_text(file)
    };
    match case[format!("{which}_transform")].as_str() {
        None => raw,
        Some("prepend_text_line") => format!("comment line before the block\n{raw}"),
        Some("escape_newlines") => raw.trim().replace('\n', "\\n"),
        Some(other) => panic!("unknown transform {other}"),
    }
}

#[test]
fn pem_variants() {
    let doc = load("jwks.json");
    let cases = cases(&doc, "pem_variants");
    for case in cases {
        let name = s(case, "name");
        let result = JwksManager::from_pem(
            "RS256",
            source(case, "private").as_bytes(),
            source(case, "public").as_bytes(),
        );
        if case["accepted"].as_bool().expect("accepted") {
            let manager = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(manager.key_id(), s(case, "kid"), "{name}");
            continue;
        }
        let error = result.expect_err(name);
        let want = s(case, "error");
        if case.get("error_note").is_some() {
            // Go wraps x509/asn1 parser text here (boot-time only); the
            // prefix and the failing key are what must match.
            let (prefix, _) = want.split_once(": ").expect("prefix");
            assert!(
                error.to_string().starts_with(&format!("{prefix}: ")),
                "{name}: {error}"
            );
            assert!(
                matches!(
                    (prefix, &error),
                    ("parse private key", KeyError::ParsePrivateKey(_))
                        | ("parse public key", KeyError::ParsePublicKey(_))
                ),
                "{name}: {error:?}"
            );
        } else {
            assert_eq!(error.to_string(), want, "{name}");
        }
    }
    assert_eq!(cases.len(), 9);
}

#[test]
fn sign_errors() {
    let doc = load("jwks.json");
    let cases = cases(&doc, "sign_errors");
    for case in cases {
        let manager = JwksManager::from_pem(
            s(case, "alg"),
            read_text(PKCS1).as_bytes(),
            read_text(PKIX).as_bytes(),
        )
        .expect("manager loads; alg is only checked when signing");
        let error = manager
            .sign(&JwtClaims::new())
            .expect_err("unsupported alg");
        assert_eq!(error.to_string(), s(case, "error"));
    }
    assert_eq!(cases.len(), 1);
}

#[test]
fn mismatched_key_pair_is_rejected() {
    // NEW vs Go: a public key that is not the private key's half fails loading.
    use rsa::traits::PublicKeyParts as _;

    let golden = parse_public_key(read_text(PKIX).as_bytes()).expect("public key");
    let other = rsa::PublicKey::new(golden.n().as_ref().clone(), rsa::BoxedUint::from(3_u64))
        .expect("same modulus, different exponent");
    let other_pem =
        rsa::pkcs8::EncodePublicKey::to_public_key_pem(&other, rsa::pkcs8::LineEnding::LF)
            .expect("pem");
    let error = JwksManager::from_pem("RS256", read_text(PKCS1).as_bytes(), other_pem.as_bytes())
        .expect_err("mismatch");
    assert!(matches!(error, KeyError::KeyPairMismatch), "{error:?}");
}
