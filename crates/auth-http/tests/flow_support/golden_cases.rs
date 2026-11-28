//! `testdata/golden/redirects.json` and `masking.json` (Go output, read-only)
//! against the flow redirect helpers and handlers.

use auth_core::oauth::AuthorizeRequest;
use auth_http::handlers::flow::{
    redirects::{
        QueryValues, auth_ui_error_route, auth_ui_route, authorization_success_url,
        oauth_error_url, oauth_values_from_request, preserved_authorize_query,
    },
    respond::{redirect_authorization_success, redirect_oauth_error},
};
use axum::{body::to_bytes, http::StatusCode, response::Response};
use serde_json::Value;

use crate::flow_support::{CALLBACK, CLIENT, harness, public_client};

fn golden(name: &str) -> Value {
    let path = format!(
        "{}/../../testdata/golden/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("golden file")).expect("JSON")
}

fn s<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {value}"))
}

fn cases<'a>(file: &'a Value, section: &str) -> &'a [Value] {
    file[section]["cases"].as_array().expect("cases")
}

/// Asserts `response` matches a golden `response` object (302 + location,
/// or status + content type + body).
async fn assert_response(response: Response, want: &Value, name: &str) {
    let status = response.status();
    assert_eq!(
        u64::from(status.as_u16()),
        want["status"].as_u64().unwrap(),
        "{name}"
    );
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    if status == StatusCode::FOUND {
        assert_eq!(headers["location"], s(want, "location"), "{name}");
    } else {
        assert_eq!(headers["content-type"], s(want, "content_type"), "{name}");
        assert_eq!(String::from_utf8_lossy(&body), s(want, "body"), "{name}");
    }
}

#[tokio::test]
async fn authorization_success_url_matches_go() {
    let file = golden("redirects.json");
    for case in cases(&file, "authorization_success") {
        let name = s(case, "name");
        let (redirect_uri, code, state) =
            (s(case, "redirect_uri"), s(case, "code"), s(case, "state"));
        let url = authorization_success_url(redirect_uri, code, state);
        if case["ok"].as_bool().unwrap() {
            assert_eq!(url.as_deref(), Some(s(case, "url")), "{name}");
        } else {
            assert_eq!(url, None, "{name}");
        }
        assert_response(
            redirect_authorization_success(redirect_uri, code, state),
            &case["response"],
            name,
        )
        .await;
    }
}

#[tokio::test]
async fn oauth_error_url_matches_go() {
    let file = golden("redirects.json");
    for case in cases(&file, "oauth_error") {
        let name = s(case, "name");
        let (redirect_uri, state, error, description) = (
            s(case, "redirect_uri"),
            s(case, "state"),
            s(case, "error"),
            s(case, "error_description"),
        );
        let url = oauth_error_url(redirect_uri, state, error, description);
        if case["ok"].as_bool().unwrap() {
            assert_eq!(url.as_deref(), Some(s(case, "url")), "{name}");
        } else {
            assert_eq!(url, None, "{name}");
        }
        assert_response(
            redirect_oauth_error(redirect_uri, state, error, description),
            &case["response"],
            name,
        )
        .await;
    }
}

#[test]
fn auth_ui_from_raw_query_matches_go() {
    let file = golden("redirects.json");
    let base = s(&file["auth_ui_from_raw_query"], "auth_ui_base_url");
    for case in cases(&file, "auth_ui_from_raw_query") {
        let query = preserved_authorize_query(&QueryValues::parse(s(case, "raw_query")));
        assert_eq!(
            auth_ui_route(base, s(case, "path"), &query),
            s(case, "url"),
            "{}",
            s(case, "name")
        );
    }
}

#[test]
fn auth_ui_from_request_matches_go() {
    let file = golden("redirects.json");
    let base = s(&file["auth_ui_from_request"], "auth_ui_base_url");
    for case in cases(&file, "auth_ui_from_request") {
        let name = s(case, "name");
        let r = &case["request"];
        let request = AuthorizeRequest {
            response_type: s(r, "ResponseType").to_owned(),
            client_id: s(r, "ClientID").to_owned(),
            redirect_uri: s(r, "RedirectURI").to_owned(),
            scope: s(r, "Scope").to_owned(),
            state: s(r, "State").to_owned(),
            nonce: s(r, "Nonce").to_owned(),
            code_challenge: s(r, "CodeChallenge").to_owned(),
            code_challenge_method: s(r, "CodeChallengeMethod").to_owned(),
            prompt: s(r, "Prompt").to_owned(),
        };
        assert_eq!(
            auth_ui_route(base, "/consent", &oauth_values_from_request(&request)),
            s(case, "consent_url"),
            "{name}"
        );
        assert_eq!(case["error_response"]["status"], 302, "{name}");
        assert_eq!(
            auth_ui_error_route(
                base,
                &request,
                s(case, "error_code"),
                s(case, "error_description")
            ),
            s(&case["error_response"], "location"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn authorize_without_session_matches_go() {
    let file = golden("redirects.json");
    let section = &file["authorize_without_session"];
    let h = harness();
    assert_eq!(
        h.state.config.auth_ui_base_url,
        s(section, "auth_ui_base_url")
    );
    let client = &section["clients"][CLIENT];
    let uris: Vec<&str> = client["RedirectURIs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|uri| uri.as_str().unwrap())
        .collect();
    h.db.add_client(public_client(CLIENT, &uris, s(client, "AllowedScopes")));
    for case in cases(&file, "authorize_without_session") {
        let name = s(case, "name");
        let reply = h
            .get(
                &format!("/v1/oauth2/authorize?{}", s(case, "raw_query")),
                None,
            )
            .await;
        let want = &case["response"];
        assert_eq!(
            u64::from(reply.status.as_u16()),
            want["status"].as_u64().unwrap(),
            "{name}"
        );
        if reply.status == StatusCode::FOUND {
            assert_eq!(reply.location(), s(want, "location"), "{name}");
            assert_eq!(
                reply.header("content-type"),
                Some("text/html; charset=utf-8")
            );
        } else {
            assert_eq!(
                reply.header("content-type"),
                Some(s(want, "content_type")),
                "{name}"
            );
            assert_eq!(reply.body, s(want, "body"), "{name}");
        }
    }
}

#[tokio::test]
async fn otp_start_response_matches_fixture_with_normalized_email() {
    let file = golden("redirects.json");
    let section = &file["otp_start_response"];
    let h = harness();
    assert_eq!(
        h.clock.now().unix_timestamp(),
        section["now_unix"].as_i64().unwrap()
    );
    let client = &section["clients"][CLIENT];
    h.db.add_client(public_client(
        CLIENT,
        &[CALLBACK],
        s(client, "AllowedScopes"),
    ));
    for case in cases(&file, "otp_start_response") {
        let name = s(case, "name");
        h.db.ids.queue(s(section, "otp_challenge_id"));
        let reply = h
            .post("/v1/auth/otp/start", s(case, "request_body"), None)
            .await;
        let want = &case["response"];
        assert_eq!(
            u64::from(reply.status.as_u16()),
            want["status"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            reply.header("content-type"),
            Some(s(want, "content_type")),
            "{name}"
        );
        // AUTH-049 changes the email spelling in the masked value and redirect.
        let expected = s(want, "body")
            .replace("A*********h@Example.com", "a*********h@example.com")
            .replace("Alice.Smith%40Example.com", "alice.smith%40example.com");
        assert_eq!(reply.body, expected, "{name}");
        if reply.status != StatusCode::OK {
            // The queued ID was not consumed.
            let _ = h.db.ids_take();
        }
    }
}

#[tokio::test]
async fn provider_authorization_url_matches_go() {
    let file = golden("redirects.json");
    let section = &file["provider_authorization_url"];
    let config = &section["config"];
    let h = harness();
    assert_eq!(
        h.state.config.google_client_id,
        s(config, "google_client_id")
    );
    assert_eq!(
        h.state.config.google_redirect_url,
        s(config, "google_redirect_url")
    );
    assert_eq!(
        h.state.config.github_client_id,
        s(config, "github_client_id")
    );
    assert_eq!(
        h.state.config.github_redirect_url,
        s(config, "github_redirect_url")
    );
    let body = crate::flow_support::json_body(&crate::flow_support::oauth_params("openid"));
    for case in cases(&file, "provider_authorization_url") {
        let provider = s(case, "provider");
        if provider == "unknown" {
            continue;
        }
        let reply = h
            .post_json(&format!("/v1/auth/login/{provider}"), &body, None)
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let url = reply.json()["authorization_url"]
            .as_str()
            .unwrap()
            .to_owned();
        let (prefix, token) = url.rsplit_once("&state=").unwrap();
        let want = s(case, "url");
        let (want_prefix, _) = want.rsplit_once("&state=").unwrap();
        assert_eq!(prefix, want_prefix, "{provider}");
        assert!(h.state.envelope.verify(token).await.is_ok(), "{provider}");
    }
}

#[tokio::test]
async fn otp_start_masks_email_byte_exact() {
    let file = golden("masking.json");
    let h = harness();
    let body = crate::flow_support::json_body(&crate::flow_support::oauth_params("openid"));
    for case in cases(&file, "mask_email") {
        let input = s(case, "input");
        if input.trim().is_empty() {
            continue;
        }
        let mut body = body.clone();
        body["email"] = Value::from(input);
        let reply = h.post_json("/v1/auth/otp/start", &body, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{input}: {}", reply.body);
        // AUTH-049 lowercases the email before applying the frozen masking rules.
        let masked = s(case, "json_rendered").to_lowercase();
        let prefix = format!("{{\"email\":{masked},\"expires_at\":");
        assert!(
            reply.body.starts_with(&prefix),
            "{input}: {} does not start with {prefix}",
            reply.body
        );
    }
}
