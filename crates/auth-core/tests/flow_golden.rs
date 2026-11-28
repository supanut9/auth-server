//! Go golden vectors (`flow_golden_test.go` sections of `hashes.json` and
//! `scopes.json`) driven through `FlowService` rather than the bare helpers.

mod flow_fakes;
mod golden_support;

use auth_core::domain::{
    AccountId, AuthorizationCode, AuthorizationCodeId, ClientId, ConsentGrant, SessionId,
};
use auth_core::flow::{
    ConsumeAuthorizationCodeRequest, FlowError, IssueDirectCodeRequest, UpsertConsentRequest,
};
use flow_fakes::{Harness, NOW};
use golden_support::{cases, load, s};
use serde_json::Value;
use time::Duration;

const REDIRECT: &str = "https://app.example.com/callback";

fn list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("string item").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn consume(code: &str) -> ConsumeAuthorizationCodeRequest {
    ConsumeAuthorizationCodeRequest {
        code: code.to_owned(),
        client_id: ClientId::from("client-1"),
        redirect_uri: REDIRECT.to_owned(),
        code_verifier: String::new(),
    }
}

/// `authorization_code_random`: the issued value and stored `code_hash` for
/// recorded random bytes, then the value redeems.
#[tokio::test]
async fn issue_direct_code_matches_go_random_vectors() {
    let doc = load("hashes.json");
    let cases = cases(&doc, "authorization_code_random");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let h = Harness::new();
        h.random
            .push(hex::decode(s(case, "raw_hex")).expect("raw_hex"));
        let (value, code) = h
            .service
            .issue_direct_code(IssueDirectCodeRequest {
                account_id: AccountId::from("account-1"),
                client_id: ClientId::from("client-1"),
                sso_session_id: Some(SessionId::from("sso-1")),
                redirect_uri: REDIRECT.to_owned(),
                scopes: vec!["openid".to_owned()],
                pkce_code_challenge: String::new(),
                pkce_code_challenge_method: String::new(),
                nonce: String::new(),
                auth_time: NOW,
            })
            .await
            .expect("issue");
        assert_eq!(value, s(case, "value"));
        assert_eq!(code.code_hash, s(case, "hash"));

        let consumed = h
            .service
            .consume_authorization_code(consume(&value))
            .await
            .expect("consume");
        assert_eq!(consumed.code_hash, s(case, "hash"));
    }
}

/// `authorization_code_hash`: `consume` looks codes up by the Go digest, and
/// an empty code fails with Go's error text.
#[tokio::test]
async fn consume_uses_go_code_hash() {
    let doc = load("hashes.json");
    let cases = cases(&doc, "authorization_code_hash");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let h = Harness::new();
        let input = s(case, "input");
        match case.get("hash").and_then(Value::as_str) {
            Some(hash) => {
                h.codes.insert(AuthorizationCode {
                    id: AuthorizationCodeId::from("code-1"),
                    code_hash: hash.to_owned(),
                    client_id: ClientId::from("client-1"),
                    redirect_uri: REDIRECT.to_owned(),
                    expires_at: NOW + Duration::minutes(5),
                    ..AuthorizationCode::default()
                });
                let consumed = h
                    .service
                    .consume_authorization_code(consume(input))
                    .await
                    .expect("consume");
                assert_eq!(consumed.code_hash, hash, "{input:?}");
                assert_eq!(h.log.calls()[0], format!("codes.find_by_code_hash({hash})"));
            }
            None => {
                let error = h
                    .service
                    .consume_authorization_code(consume(input))
                    .await
                    .expect_err("empty");
                assert!(matches!(error, FlowError::AuthorizationCodeExpired));
                assert_eq!(error.to_string(), s(case, "error"));
            }
        }
    }
}

/// `flow_union_scopes`: request scopes are `base`, the stored grant holds
/// `extra` (space-joined), and the saved grant is Go's `joined`.
#[tokio::test]
async fn upsert_consent_matches_go_union_vectors() {
    let doc = load("scopes.json");
    let cases = cases(&doc, "flow_union_scopes");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let h = Harness::new();
        h.consents.insert(ConsentGrant {
            account_id: AccountId::from("account-1"),
            client_id: ClientId::from("client-1"),
            granted_scopes: list(&case["extra"]).join(" "),
            ..ConsentGrant::default()
        });
        let saved = h
            .service
            .upsert_consent(UpsertConsentRequest {
                account_id: AccountId::from("account-1"),
                client_id: ClientId::from("client-1"),
                scopes: list(&case["base"]),
            })
            .await
            .expect("upsert");
        assert_eq!(saved.granted_scopes, s(case, "joined"), "{case}");
        assert_eq!(
            saved
                .granted_scopes
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            list(&case["output"]),
            "{case}"
        );
    }
}

/// `flow_scope_subset`: `has_consent_for_scopes` against a grant holding the
/// `granted` list.
#[tokio::test]
async fn has_consent_matches_go_subset_vectors() {
    let doc = load("scopes.json");
    let cases = cases(&doc, "flow_scope_subset");
    assert_eq!(cases.len(), 6);
    let account = AccountId::from("account-1");
    let client = ClientId::from("client-1");
    for case in cases {
        let h = Harness::new();
        h.consents.insert(ConsentGrant {
            account_id: account.clone(),
            client_id: client.clone(),
            granted_scopes: list(&case["granted"]).join(" "),
            ..ConsentGrant::default()
        });
        let got = h
            .service
            .has_consent_for_scopes(&account, &client, &list(&case["requested"]))
            .await;
        assert_eq!(got, case["subset"].as_bool().expect("subset"), "{case}");
    }
}

/// `flow_split_scopes`: a grant stored as `input` covers exactly Go's
/// `output`, and not a comma-split reading of it.
#[tokio::test]
async fn has_consent_splits_stored_scopes_like_go() {
    let doc = load("scopes.json");
    let cases = cases(&doc, "flow_split_scopes");
    assert_eq!(cases.len(), 10);
    let account = AccountId::from("account-1");
    let client = ClientId::from("client-1");
    for case in cases {
        let h = Harness::new();
        h.consents.insert(ConsentGrant {
            account_id: account.clone(),
            client_id: client.clone(),
            granted_scopes: s(case, "input").to_owned(),
            ..ConsentGrant::default()
        });
        let output = list(&case["output"]);
        assert!(
            h.service
                .has_consent_for_scopes(&account, &client, &output)
                .await,
            "{case}"
        );
        assert!(
            !h.service
                .has_consent_for_scopes(&account, &client, &["not-granted"])
                .await,
            "{case}"
        );

        // Through upsert the stored string is re-normalized to Go's `joined`.
        let saved = h
            .service
            .upsert_consent(UpsertConsentRequest {
                account_id: account.clone(),
                client_id: client.clone(),
                scopes: Vec::new(),
            })
            .await
            .expect("upsert");
        assert_eq!(saved.granted_scopes, s(case, "joined"), "{case}");
    }
}
