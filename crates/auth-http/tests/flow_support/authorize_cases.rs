//! `GET /v1/oauth2/authorize`.

use auth_http::handlers::flow::redirects::{authorization_success_url, oauth_error_url};
use axum::http::StatusCode;
use time::Duration;

use crate::flow_support::{CALLBACK, CLIENT, Harness, UI, encode, harness, oauth_params, with};

const SCOPE: &str = "profile openid email";

fn authorize_path(params: &[(&'static str, String)]) -> String {
    format!("/v1/oauth2/authorize?{}", encode(params))
}

/// Extracts the `code` from a success redirect and checks the full URL.
pub fn code_from(location: &str, redirect_uri: &str, state: &str) -> String {
    let code = location
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("code="))
        .expect("code in location")
        .to_owned();
    assert_eq!(
        authorization_success_url(redirect_uri, &code, state).as_deref(),
        Some(location)
    );
    code
}

/// Signed-in browser: account `acct-a`, session `sess-a`.
fn signed_in(h: &Harness) -> &'static str {
    h.db.add_account("acct-a", "a@example.com");
    h.db.add_session("sess-a", "acct-a", h.clock.now());
    "auth_sso_session=sess-a"
}

#[tokio::test]
async fn no_session_redirects_to_login_with_oauth_params_only() {
    let h = harness();
    let params = oauth_params(SCOPE);
    let mut query = params.clone();
    query.push(("utm_source", "x".to_owned()));
    let reply = h.get(&authorize_path(&query), None).await;
    reply.assert_found(&format!("{UI}login?{}", encode(&params)));
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(
        reply
            .body
            .starts_with("<a href=\"https://auth-ui.example.com/login?")
    );
    assert!(reply.set_cookies().is_empty());
}

#[tokio::test]
async fn prompt_none_without_session_is_login_required() {
    let h = harness();
    let reply = h
        .get(
            &authorize_path(&with(oauth_params(SCOPE), "prompt", "none")),
            None,
        )
        .await;
    reply.assert_found(
        &oauth_error_url(
            CALLBACK,
            "st 1&x",
            "login_required",
            "no active SSO session",
        )
        .unwrap(),
    );
}

#[tokio::test]
async fn fatal_errors_render_json() {
    let h = harness();
    for (key, value, body) in [
        (
            "client_id",
            "",
            r#"{"error":"invalid_request","error_description":"client_id is required"}"#,
        ),
        (
            "client_id",
            "nope",
            r#"{"error":"invalid_client","error_description":"client_id is unknown"}"#,
        ),
        (
            "redirect_uri",
            "",
            r#"{"error":"invalid_request","error_description":"redirect_uri is required"}"#,
        ),
        (
            "redirect_uri",
            "https://evil.example/cb",
            r#"{"error":"invalid_request","error_description":"redirect_uri does not match a registered URI"}"#,
        ),
    ] {
        let reply = h
            .get(
                &authorize_path(&with(oauth_params(SCOPE), key, value)),
                None,
            )
            .await;
        reply.assert_json(StatusCode::BAD_REQUEST, body);
    }
}

#[tokio::test]
async fn recoverable_errors_redirect_to_raw_redirect_uri() {
    let h = harness();
    // Even with a session and consent, validation comes first.
    let cookie = signed_in(&h);
    h.db.add_consent("acct-a", CLIENT, "email openid profile");
    for (key, value, error, description) in [
        (
            "response_type",
            "",
            "invalid_request",
            "response_type is required",
        ),
        (
            "response_type",
            "token",
            "unsupported_response_type",
            "response_type must be code",
        ),
        (
            "scope",
            "openid trading.write",
            "invalid_scope",
            "requested scopes are not allowed for this client",
        ),
        (
            "nonce",
            "",
            "invalid_request",
            "nonce is required for openid",
        ),
        (
            "code_challenge_method",
            "plain",
            "invalid_request",
            "public clients must use S256 for code_challenge_method",
        ),
    ] {
        let reply = h
            .get(
                &authorize_path(&with(oauth_params(SCOPE), key, value)),
                Some(cookie),
            )
            .await;
        reply.assert_found(&oauth_error_url(CALLBACK, "st 1&x", error, description).unwrap());
    }
    // A missing state is simply not echoed.
    let params: Vec<_> = oauth_params(SCOPE)
        .into_iter()
        .filter(|(k, _)| *k != "state")
        .collect();
    let reply = h.get(&authorize_path(&params), None).await;
    reply.assert_found(
        &oauth_error_url(CALLBACK, "", "invalid_request", "state is required").unwrap(),
    );
}

#[tokio::test]
async fn session_with_consent_issues_code_with_session_auth_time() {
    let h = harness();
    let cookie = signed_in(&h);
    h.db.add_consent("acct-a", CLIENT, "email openid profile trading.read");
    let reply = h
        .get(&authorize_path(&oauth_params(SCOPE)), Some(cookie))
        .await;
    assert_eq!(reply.status, StatusCode::FOUND);
    let code = code_from(reply.location(), CALLBACK, "st 1&x");
    let stored = h.db.code(&code);
    let session = h.db.session("sess-a");
    assert_eq!(stored.account_id, "acct-a");
    assert_eq!(stored.client_id, CLIENT);
    assert_eq!(
        stored
            .sso_session_id
            .as_ref()
            .map(auth_core::domain::SessionId::as_str),
        Some("sess-a")
    );
    assert_eq!(stored.auth_time, session.authenticated_at);
    assert_eq!(stored.granted_scopes, "email openid profile");
    assert_eq!(stored.redirect_uri, CALLBACK);
    assert_eq!(stored.pkce_code_challenge_method, "S256");
    // The authorization request's nonce rides on the code (AUTH-041).
    assert_eq!(stored.nonce, "n");
    assert!(reply.set_cookies().is_empty());

    // prompt=none with consent also gets a code.
    let reply = h
        .get(
            &authorize_path(&with(oauth_params(SCOPE), "prompt", "none")),
            Some(cookie),
        )
        .await;
    code_from(reply.location(), CALLBACK, "st 1&x");
}

#[tokio::test]
async fn code_redirect_merges_registered_query() {
    let h = harness();
    let cookie = signed_in(&h);
    h.db.add_consent("acct-a", CLIENT, "email openid profile");
    let redirect = "https://trading.example.com/cb?tenant=a";
    let reply = h
        .get(
            &authorize_path(&with(oauth_params(SCOPE), "redirect_uri", redirect)),
            Some(cookie),
        )
        .await;
    let code = code_from(reply.location(), redirect, "st 1&x");
    assert!(
        reply
            .location()
            .ends_with(&format!("cb?code={code}&state=st+1%26x&tenant=a"))
    );
}

#[tokio::test]
async fn prompt_login_ignores_the_session() {
    let h = harness();
    let cookie = signed_in(&h);
    h.db.add_consent("acct-a", CLIENT, "email openid profile");
    let params = with(oauth_params(SCOPE), "prompt", "login");
    let reply = h.get(&authorize_path(&params), Some(cookie)).await;
    reply.assert_found(&format!("{UI}login?{}", encode(&params)));
}

#[tokio::test]
async fn session_without_consent_goes_to_consent_or_consent_required() {
    let h = harness();
    let cookie = signed_in(&h);
    // Consent for fewer scopes than requested does not count.
    h.db.add_consent("acct-a", CLIENT, "openid");
    let params = oauth_params(SCOPE);
    let reply = h.get(&authorize_path(&params), Some(cookie)).await;
    reply.assert_found(&format!("{UI}consent?{}", encode(&params)));

    let reply = h
        .get(
            &authorize_path(&with(params, "prompt", "none")),
            Some(cookie),
        )
        .await;
    reply.assert_found(
        &oauth_error_url(CALLBACK, "st 1&x", "consent_required", "consent required").unwrap(),
    );
}

#[tokio::test]
async fn unusable_sessions_count_as_none() {
    let h = harness();
    let cookie = signed_in(&h);
    h.db.add_consent("acct-a", CLIENT, "email openid profile");
    let params = oauth_params(SCOPE);
    let login = format!("{UI}login?{}", encode(&params));
    // Unknown session ID.
    h.get(&authorize_path(&params), Some("auth_sso_session=nope"))
        .await
        .assert_found(&login);
    // Revoked session.
    h.db.sessions.lock().unwrap()[0].revoked_at = Some(h.clock.now());
    h.get(&authorize_path(&params), Some(cookie))
        .await
        .assert_found(&login);
    // Expired session.
    h.db.sessions.lock().unwrap()[0].revoked_at = None;
    h.clock.advance(Duration::days(2));
    h.get(&authorize_path(&params), Some(cookie))
        .await
        .assert_found(&login);
}

#[tokio::test]
async fn first_query_value_wins_and_unknown_routes_stay_404() {
    let h = harness();
    let params = oauth_params(SCOPE);
    let query = format!("{}&client_id=other&state=second", encode(&params));
    let reply = h.get(&format!("/v1/oauth2/authorize?{query}"), None).await;
    reply.assert_found(&format!("{UI}login?{}", encode(&params)));
    let reply = h.post("/v1/oauth2/authorize", "{}", None).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}
