//! `POST /v1/auth/consent/{accept,reject}`.

use auth_http::handlers::flow::redirects::oauth_error_url;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::{
    authorize_cases::code_from,
    flow_support::{CALLBACK, CLIENT, harness, json_body, oauth_params, with},
};

const SCOPE: &str = "profile openid email";
const CSRF: &str = "csrf-token-1";
const COOKIES: &str = "auth_csrf=csrf-token-1; auth_sso_session=sess-a";

fn accept_body(params: &[(&'static str, String)]) -> Value {
    let mut body = json_body(params);
    body["csrf_token"] = Value::from(CSRF);
    body
}

#[tokio::test]
async fn accept_upserts_consent_and_returns_code_redirect() {
    let h = harness();
    h.db.add_account("acct-a", "a@example.com");
    h.db.add_session("sess-a", "acct-a", h.clock.now());
    h.db.add_consent("acct-a", CLIENT, "trading.read");
    let reply = h
        .post_json(
            "/v1/auth/consent/accept",
            &accept_body(&oauth_params(SCOPE)),
            Some(COOKIES),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    // Go HTML-escapes `&` in JSON strings.
    assert!(
        reply
            .body
            .starts_with(r#"{"redirect_to":"https://trading.example.com/callback?code="#)
    );
    assert!(reply.body.contains("\\u0026state=st+1%26x\"}"));
    let json = reply.json();
    let code = code_from(json["redirect_to"].as_str().unwrap(), CALLBACK, "st 1&x");
    let stored = h.db.code(&code);
    assert_eq!(stored.account_id, "acct-a");
    assert_eq!(
        stored
            .sso_session_id
            .as_ref()
            .map(auth_core::domain::SessionId::as_str),
        Some("sess-a")
    );
    assert_eq!(stored.auth_time, h.db.session("sess-a").authenticated_at);
    // The new scopes are unioned into the existing grant.
    assert_eq!(
        h.db.consent("acct-a").unwrap().granted_scopes,
        "email openid profile trading.read"
    );
    assert!(reply.set_cookies().is_empty());
}

#[tokio::test]
async fn accept_checks_in_go_order() {
    let h = harness();
    let path = "/v1/auth/consent/accept";
    // Bind: csrf_token is required.
    h.post_json(path, &json_body(&oauth_params(SCOPE)), Some(COOKIES))
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request","error_description":"csrf_token is required"}"#,
        );
    // CSRF before validation (the client is unknown here).
    let unknown = accept_body(&with(oauth_params(SCOPE), "client_id", "nope"));
    h.post_json(path, &unknown, Some("auth_sso_session=sess-a"))
        .await
        .assert_json(
            StatusCode::FORBIDDEN,
            r#"{"error":"csrf","error_description":"missing csrf cookie"}"#,
        );
    h.post_json(path, &unknown, Some("auth_csrf=other"))
        .await
        .assert_json(
            StatusCode::FORBIDDEN,
            r#"{"error":"csrf","error_description":"csrf token mismatch"}"#,
        );
    // Validation before the session.
    h.post_json(path, &unknown, Some(COOKIES))
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_client","error_description":"client_id is unknown"}"#,
        );
    h.post_json(
        path,
        &accept_body(&with(oauth_params(SCOPE), "code_challenge_method", "plain")),
        Some(COOKIES),
    )
    .await
    .assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"public clients must use S256 for code_challenge_method"}"#,
    );
    // No usable session.
    h.post_json(path, &accept_body(&oauth_params(SCOPE)), Some(COOKIES))
        .await
        .assert_json(StatusCode::UNAUTHORIZED, r#"{"error":"unauthenticated"}"#);
    assert!(h.db.codes.lock().unwrap().is_empty());
    assert!(h.db.consents.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reject_returns_access_denied_redirect() {
    let h = harness();
    // No scope, PKCE or SSO session needed.
    let body = json!({
        "client_id": CLIENT,
        "redirect_uri": CALLBACK,
        "state": "st 1&x",
        "csrf_token": CSRF,
    });
    let reply = h
        .post_json(
            "/v1/auth/consent/reject",
            &body,
            Some("auth_csrf=csrf-token-1"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        reply.json(),
        json!({"redirect_to": oauth_error_url(CALLBACK, "st 1&x", "access_denied", "user denied consent").unwrap()})
    );
    assert_eq!(
        reply.json()["redirect_to"],
        "https://trading.example.com/callback?error=access_denied&error_description=user+denied+consent&state=st+1%26x"
    );
}

#[tokio::test]
async fn reject_checks_in_go_order() {
    let h = harness();
    let path = "/v1/auth/consent/reject";
    let cookie = Some("auth_csrf=csrf-token-1");
    let body = |client: &str, redirect: &str, state: &str, csrf: &str| json!({"client_id": client, "redirect_uri": redirect, "state": state, "csrf_token": csrf});
    h.post_json(path, &body(CLIENT, CALLBACK, "", CSRF), cookie)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request","error_description":"state is required"}"#,
        );
    h.post_json(path, &body("nope", CALLBACK, "s", "wrong"), cookie)
        .await
        .assert_json(
            StatusCode::FORBIDDEN,
            r#"{"error":"csrf","error_description":"csrf token mismatch"}"#,
        );
    h.post_json(path, &body("nope", CALLBACK, "s", CSRF), cookie)
        .await
        .assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_client"}"#);
    h.post_json(
        path,
        &body(CLIENT, "https://evil.example/cb", "s", CSRF),
        cookie,
    )
    .await
    .assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#);
}
