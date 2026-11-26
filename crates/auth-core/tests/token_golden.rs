//! `testdata/golden/jwt.json`: rebuild every recorded claim set through
//! `TokenService` with the recorded clock, IDs and requests, and compare the
//! Go `json.Marshal` bytes of the claims (the signer is a recording fake;
//! byte-exact signatures are covered by `auth-adapters/tests/golden_jwt.rs`).

mod golden_support;
mod token_support;

use std::collections::BTreeSet;

use auth_core::domain::{AccountId, ClientId, SessionId};
use auth_core::token::{
    ClientCredentialsTokenRequest, IssuedTokens, RefreshTokenRequest, TokenConfig, UserTokenRequest,
};
use golden_support::{cases, i, load, s, sections, unix};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use token_support::{Harness, MemorySessions, TestIds};

fn doc() -> Value {
    load("jwt.json")
}

fn config(value: &Value) -> TokenConfig {
    TokenConfig {
        issuer: s(value, "issuer").to_owned(),
        audience: s(value, "audience").to_owned(),
        access_token_ttl: Duration::seconds(i(value, "access_token_ttl_seconds")),
        id_token_ttl: Duration::seconds(i(value, "id_token_ttl_seconds")),
        refresh_token_absolute_ttl: Duration::seconds(i(
            value,
            "refresh_token_absolute_ttl_seconds",
        )),
        refresh_token_inactive_ttl: Duration::seconds(i(
            value,
            "refresh_token_inactive_ttl_seconds",
        )),
        refresh_reuse_grace: Duration::seconds(i(value, "refresh_reuse_grace_seconds")),
    }
}

fn harness(cfg: &Value) -> Harness {
    let ids: Vec<&str> = cfg["generated_ids_in_order"]
        .as_array()
        .expect("ids")
        .iter()
        .map(|id| id.as_str().expect("id"))
        .collect();
    let h = Harness::new(config(cfg), TestIds::scripted(&ids));
    h.clock.set(unix(i(cfg, "now_unix")));
    h
}

/// Go `[]string` (a JSON `null` is a nil slice).
fn strings(value: &Value) -> Vec<String> {
    value.as_array().map_or_else(Vec::new, |items| {
        items
            .iter()
            .map(|item| item.as_str().expect("string").to_owned())
            .collect()
    })
}

fn check_token_fields(name: &str, issued: &IssuedTokens, want: &Value) {
    assert_eq!(issued.token_type, s(want, "token_type"), "{name}");
    assert_eq!(issued.expires_in, i(want, "expires_in"), "{name}");
    assert_eq!(issued.scope, s(want, "scope"), "{name}");
}

#[test]
fn every_section_is_covered() {
    let want: BTreeSet<String> = [
        "client_credentials_tokens",
        "refresh_token_grant",
        "user_tokens",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        sections(&doc()),
        want,
        "a new jwt.json section needs a test"
    );
}

#[tokio::test]
async fn user_tokens() {
    let doc = doc();
    let cases = cases(&doc, "user_tokens");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = s(case, "name");
        let h = harness(&case["config"]);
        let req = &case["request"];
        let issued = h
            .service
            .issue_user_tokens(UserTokenRequest {
                account_id: AccountId::new(s(req, "account_id")),
                client_id: ClientId::new(s(req, "client_id")),
                scope: strings(&req["scope"]),
                sso_session_id: SessionId::new(s(req, "sso_session_id")),
                device_session_id: s(req, "device_session_id").to_owned(),
                auth_time: OffsetDateTime::parse(s(req, "auth_time_rfc3339"), &Rfc3339)
                    .expect("auth_time"),
                // The Go vectors predate AUTH-041 and carry no nonce.
                nonce: String::new(),
                email: s(req, "email").to_owned(),
                email_verified: req["email_verified"].as_bool().expect("email_verified"),
                name: s(req, "name").to_owned(),
                picture: s(req, "picture").to_owned(),
            })
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(h.signer.recorded().len(), 2, "{name}");
        assert_eq!(
            h.signer.claims_json(0),
            s(&case["access_token"], "claims_json"),
            "{name}: access token claims"
        );
        assert_eq!(
            h.signer.claims_json(1),
            s(&case["id_token"], "claims_json"),
            "{name}: id token claims"
        );
        check_token_fields(name, &issued, &case["token_fields"]);
        assert!(issued.id_token.is_some() && issued.refresh_token.is_some());

        let chain = h.chains.only();
        assert_eq!(
            chain.id.as_str(),
            case["config"]["generated_ids_in_order"][1],
            "{name}: chain id is the second generated id"
        );
        assert_eq!(chain.device_session_id, s(req, "device_session_id"));
    }
}

#[tokio::test]
async fn client_credentials_tokens() {
    let doc = doc();
    let cases = cases(&doc, "client_credentials_tokens");
    assert_eq!(cases.len(), 2);
    for case in cases {
        let name = s(case, "name");
        let h = harness(&case["config"]);
        let req = &case["request"];
        let issued = h
            .service
            .issue_client_credentials_token(ClientCredentialsTokenRequest {
                client_id: ClientId::new(s(req, "client_id")),
                scope: strings(&req["scope"]),
            })
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(h.signer.recorded().len(), 1, "{name}");
        assert_eq!(
            h.signer.claims_json(0),
            s(&case["access_token"], "claims_json"),
            "{name}"
        );
        check_token_fields(name, &issued, &case["token_fields"]);
        assert!(issued.id_token.is_none() && issued.refresh_token.is_none());
    }
}

#[tokio::test]
async fn refresh_token_grant() {
    let doc = doc();
    let section = &doc["refresh_token_grant"];
    let h = harness(&section["config"]);
    let initial = &section["initial"];
    let now = unix(i(&section["config"], "now_unix"));
    // The Go test's session: active, expiring 24h after `now`.
    h.sessions.put(MemorySessions::active(
        s(initial, "sso_session_id"),
        now + Duration::hours(24),
    ));

    let issued = h
        .service
        .issue_user_tokens(UserTokenRequest {
            account_id: AccountId::new(s(initial, "account_id")),
            client_id: ClientId::new(s(initial, "client_id")),
            scope: strings(&initial["scope"]),
            sso_session_id: SessionId::new(s(initial, "sso_session_id")),
            device_session_id: String::new(),
            auth_time: now,
            nonce: String::new(),
            email: "refresh@example.com".into(),
            email_verified: false,
            name: String::new(),
            picture: String::new(),
        })
        .await
        .expect("issue");
    assert_eq!(
        h.signer.claims_json(0),
        s(&initial["access_token"], "claims_json")
    );

    h.clock.set(unix(i(section, "refresh_now_unix")));
    let refreshed = h
        .service
        .refresh_user_tokens(RefreshTokenRequest {
            client_id: ClientId::new(s(initial, "client_id")),
            refresh_token: issued.refresh_token.clone().expect("refresh token"),
        })
        .await
        .expect("refresh");
    let recorded = h.signer.recorded();
    assert_eq!(recorded.len(), 3, "refresh signs only an access token");
    assert_eq!(
        h.signer.claims_json(2),
        s(&section["refreshed"]["access_token"], "claims_json")
    );
    check_token_fields("refresh", &refreshed, &section["refreshed"]["token_fields"]);
    assert!(refreshed.id_token.is_none());
}
