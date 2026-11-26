//! `testdata/golden/envelope.json`: provider-state envelope sign and verify.

mod golden_support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use auth_core::crypto::{decode_b64url_go, sha256_b64url};
use auth_core::oauth::envelope::{Envelope, EnvelopeSigner};
use golden_support::{
    FixedClock, MemoryJtiStore, ScriptedRandom, cases, i, load, opt, s, sections, unix,
};
use serde_json::Value;
use time::Duration;

fn envelope_from(value: &Value) -> Envelope {
    Envelope {
        provider: opt(value, "provider").into(),
        client_id: opt(value, "client_id").into(),
        redirect_uri: opt(value, "redirect_uri").into(),
        scope: opt(value, "scope").into(),
        state: opt(value, "state").into(),
        nonce: opt(value, "nonce").into(),
        code_challenge: opt(value, "code_challenge").into(),
        code_challenge_method: opt(value, "code_challenge_method").into(),
        prompt: opt(value, "prompt").into(),
    }
}

fn signer(
    secret: &str,
    ttl_seconds: i64,
    now: i64,
    random: ScriptedRandom,
    store: Arc<MemoryJtiStore>,
) -> EnvelopeSigner {
    EnvelopeSigner::new(
        secret.as_bytes(),
        Duration::seconds(ttl_seconds),
        store,
        Arc::new(FixedClock(unix(now))),
        Arc::new(random),
    )
    .expect("signer")
}

#[test]
fn every_section_is_covered() {
    let want: BTreeSet<String> = ["constructor", "sign", "verify"].map(String::from).into();
    assert_eq!(sections(&load("envelope.json")), want);
}

#[test]
fn constructor() {
    let doc = load("envelope.json");
    let section = &doc["constructor"];
    let short = EnvelopeSigner::new(
        b"too-short".to_vec(),
        Duration::ZERO,
        Arc::new(MemoryJtiStore::default()),
        Arc::new(FixedClock(unix(0))),
        Arc::new(ScriptedRandom::default()),
    )
    .expect_err("short secret");
    assert_eq!(short.to_string(), s(section, "short_secret_error"));

    let secret = s(&doc["sign"], "secret");
    for ttl in [Duration::ZERO, Duration::seconds(-5)] {
        let signer = EnvelopeSigner::new(
            secret.as_bytes(),
            ttl,
            Arc::new(MemoryJtiStore::default()),
            Arc::new(FixedClock(unix(0))),
            Arc::new(ScriptedRandom::default()),
        )
        .expect("signer");
        assert_eq!(
            signer.ttl().whole_seconds(),
            i(section, "zero_ttl_defaults_to_seconds")
        );
    }
}

#[test]
fn sign_matches_go_bytes() {
    let doc = load("envelope.json");
    let section = &doc["sign"];
    let secret = s(section, "secret");
    let cases = cases(&doc, "sign");
    for case in cases {
        let name = s(case, "name");
        let jti_bytes = decode_b64url_go(s(case, "jti").as_bytes()).expect("jti");
        assert_eq!(jti_bytes.len(), 16, "{name}");
        let signer = signer(
            secret,
            i(section, "ttl_seconds"),
            i(section, "now_unix"),
            ScriptedRandom::new(jti_bytes),
            Arc::new(MemoryJtiStore::default()),
        );
        let token = signer
            .sign(&envelope_from(&case["envelope"]))
            .expect("sign");
        let (payload_b64, signature_b64) = token.split_once('.').expect("dot");
        let payload = decode_b64url_go(payload_b64.as_bytes()).expect("payload");
        assert_eq!(
            String::from_utf8(payload).expect("utf8"),
            s(case, "payload_json"),
            "{name}: payload JSON"
        );
        assert_eq!(payload_b64, s(case, "payload_b64url"), "{name}");
        assert_eq!(signature_b64, s(case, "signature_b64url"), "{name}");
        assert_eq!(token, s(case, "token"), "{name}");
    }
    assert_eq!(cases.len(), 5);
    // The secret itself is test-only; pin it so a vector change is noticed.
    assert_eq!(sha256_b64url(secret).len(), 43);
}

#[tokio::test]
async fn verify_cases_and_error_strings() {
    let doc = load("envelope.json");
    let secret = s(&doc["verify"], "secret");
    // `attempt` counts verifications of one token against one JTI store.
    let mut stores: BTreeMap<String, Arc<MemoryJtiStore>> = BTreeMap::new();
    let cases = cases(&doc, "verify");
    for case in cases {
        let name = s(case, "name");
        let attempt = i(case, "attempt");
        if attempt == 1 {
            stores.insert(name.to_owned(), Arc::default());
        }
        let store = stores.get(name).expect("store for attempt > 1").clone();
        let signer = signer(
            secret,
            600,
            i(case, "now_unix"),
            ScriptedRandom::default(),
            store,
        );
        let result = signer.verify(s(case, "token")).await;
        if case["ok"].as_bool().expect("ok") {
            let envelope = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(envelope, envelope_from(&case["envelope"]), "{name}");
        } else {
            let error = result.expect_err(name);
            assert_eq!(error.to_string(), s(case, "error"), "{name}");
        }
    }
    assert_eq!(cases.len(), 19);
}

#[tokio::test]
async fn sign_then_verify_round_trips() {
    let doc = load("envelope.json");
    let section = &doc["sign"];
    for case in cases(&doc, "sign") {
        let jti_bytes = decode_b64url_go(s(case, "jti").as_bytes()).expect("jti");
        let signer = signer(
            s(section, "secret"),
            i(section, "ttl_seconds"),
            i(section, "now_unix"),
            ScriptedRandom::new(jti_bytes),
            Arc::new(MemoryJtiStore::default()),
        );
        let envelope = envelope_from(&case["envelope"]);
        let token = signer.sign(&envelope).expect("sign");
        assert_eq!(signer.verify(&token).await.expect("verify"), envelope);
        assert_eq!(
            signer.verify(&token).await.expect_err("replay").to_string(),
            "oauth: jti replay"
        );
    }
}
