//! `POST /v1/auth/login/{google,github}` and the provider callbacks.

use auth_core::oauth::envelope::Envelope;
use auth_http::handlers::flow::redirects::oauth_error_url;
use axum::http::StatusCode;

use crate::{
    authorize_cases::code_from,
    flow_support::{
        CALLBACK, CHALLENGE, CLIENT, GITHUB_REDIRECT, GOOGLE_REDIRECT, Options, UI, encode,
        harness, harness_with, json_body, oauth_params, public_client, with,
    },
};

const SCOPE: &str = "profile openid email";

/// The canonical (validated) params, as the envelope carries them.
fn canonical() -> Vec<(&'static str, String)> {
    with(oauth_params(SCOPE), "scope", "email openid profile")
}

fn envelope(provider: &str) -> Envelope {
    Envelope {
        provider: provider.to_owned(),
        client_id: CLIENT.to_owned(),
        redirect_uri: CALLBACK.to_owned(),
        scope: "email openid profile".to_owned(),
        state: "st 1&x".to_owned(),
        nonce: "n".to_owned(),
        code_challenge: CHALLENGE.to_owned(),
        code_challenge_method: "S256".to_owned(),
        prompt: String::new(),
    }
}

fn callback_path(provider: &str, token: &str, code: &str) -> String {
    format!(
        "/v1/auth/login/callback/{provider}?{}",
        encode(&[("state", token.to_owned()), ("code", code.to_owned())])
    )
}

#[tokio::test]
async fn start_signs_canonical_envelope() {
    let h = harness();
    let body = json_body(&with(oauth_params(SCOPE), "prompt", "login"));
    let reply = h.post_json("/v1/auth/login/google", &body, None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let json = reply.json();
    let url = json["authorization_url"].as_str().unwrap();
    let token = url.rsplit_once("&state=").unwrap().1;
    assert!(url.starts_with(&format!(
        "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=google-client-id.apps.googleusercontent.com&prompt=select_account&redirect_uri={}&response_type=code&scope=openid+email+profile&state=",
        auth_http::go_url::query_escape(GOOGLE_REDIRECT)
    )));
    // `&` in the URL is HTML-escaped like Go's encoding/json.
    assert!(reply.body.contains("\\u0026client_id="));
    let mut want = envelope("google");
    want.prompt = "login".to_owned();
    assert_eq!(h.state.envelope.verify(token).await.unwrap(), want);

    // response_type defaults to code; github has its own URL.
    let body = json_body(
        &oauth_params(SCOPE)
            .into_iter()
            .filter(|(k, _)| *k != "response_type")
            .collect::<Vec<_>>(),
    );
    let reply = h.post_json("/v1/auth/login/github", &body, None).await;
    let url = reply.json()["authorization_url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(url.starts_with("https://github.com/login/oauth/authorize?client_id=Iv1.githubclientid&prompt=select_account&redirect_uri="));
    let token = url.rsplit_once("&state=").unwrap().1;
    let envelope = h.state.envelope.verify(token).await.unwrap();
    assert_eq!(envelope.provider, "github");
    assert_eq!(envelope.prompt, "");
}

#[tokio::test]
async fn start_bind_and_validation_errors() {
    let h = harness();
    for (body, description) in [
        ("", "invalid JSON body"),
        ("{", "invalid JSON body"),
        (r#"{"client_id":1}"#, "invalid JSON body"),
        ("{}", "client_id is required"),
        (
            r#"{"client_id":"trading-web","redirect_uri":"x","scope":"openid","state":""}"#,
            "state is required",
        ),
    ] {
        h.post("/v1/auth/login/google", body, None)
            .await
            .assert_json(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"invalid_request","error_description":"{description}"}}"#),
            );
    }
    // Recoverable validation errors are JSON here too.
    let body = json_body(&with(oauth_params(SCOPE), "scope", "openid trading.write"));
    h.post_json("/v1/auth/login/google", &body, None).await.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_scope","error_description":"requested scopes are not allowed for this client"}"#,
    );
}

#[tokio::test]
async fn start_provider_unavailable_after_validation() {
    let h = harness_with(Options {
        providers: false,
        ..Options::default()
    });
    let body = json_body(&oauth_params(SCOPE));
    h.post_json("/v1/auth/login/google", &body, None)
        .await
        .assert_json(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"provider_unavailable"}"#,
        );
    let body = json_body(&with(oauth_params(SCOPE), "client_id", "nope"));
    h.post_json("/v1/auth/login/github", &body, None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_client","error_description":"client_id is unknown"}"#,
        );
}

#[tokio::test]
async fn callback_rejects_bad_state() {
    let h = harness();
    h.get("/v1/auth/login/callback/google?code=c", None)
        .await
        .assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#);
    h.get("/v1/auth/login/callback/google?state=s&code=", None)
        .await
        .assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#);
    h.get(&callback_path("google", "garbage", "c"), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_state","error_description":"envelope: malformed token"}"#,
        );
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    h.get(&callback_path("github", &token, "c"), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_state","error_description":"state provider mismatch"}"#,
        );
    // The JTI was burned by the first verify: replay fails.
    h.get(&callback_path("google", &token, "c"), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_state","error_description":"oauth: jti replay"}"#,
        );
    assert!(h.google.exchanges.lock().unwrap().is_empty());
}

#[tokio::test]
async fn callback_provider_unavailable() {
    let h = harness_with(Options {
        providers: false,
        ..Options::default()
    });
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    h.get(&callback_path("google", &token, "c"), None)
        .await
        .assert_json(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"provider_unavailable"}"#,
        );
}

#[tokio::test]
async fn callback_revalidation_errors_redirect_to_envelope_redirect_uri() {
    let h = harness();
    // The client no longer allows `profile`: recoverable error.
    h.db.add_client(public_client(CLIENT, &[CALLBACK], "openid email"));
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    h.get(&callback_path("google", &token, "c"), None)
        .await
        .assert_found(
            &oauth_error_url(
                CALLBACK,
                "st 1&x",
                "invalid_scope",
                "requested scopes are not allowed for this client",
            )
            .unwrap(),
        );
    // Unknown client (fatal in authorize) still redirects here.
    h.db.clients.lock().unwrap().clear();
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    h.get(&callback_path("google", &token, "c"), None)
        .await
        .assert_found(
            &oauth_error_url(CALLBACK, "st 1&x", "invalid_client", "client_id is unknown").unwrap(),
        );
    // An empty envelope redirect URI falls back to JSON.
    let mut empty = envelope("google");
    empty.redirect_uri = String::new();
    let token = h.state.envelope.sign(&empty).unwrap();
    h.get(&callback_path("google", &token, "c"), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_client","error_description":"client_id is unknown"}"#,
        );
    assert!(h.google.exchanges.lock().unwrap().is_empty());
}

#[tokio::test]
async fn callback_exchange_and_identity_errors() {
    let h = harness();
    h.google
        .fails("google token exchange failed: 400 Bad Request");
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    h.get(&callback_path("google", &token, "the-code"), None)
        .await
        .assert_json(
            StatusCode::BAD_GATEWAY,
            r#"{"error":"provider_error","error_description":"google token exchange failed: 400 Bad Request"}"#,
        );
    assert_eq!(
        h.google.exchanges.lock().unwrap().as_slice(),
        [("the-code".to_owned(), GOOGLE_REDIRECT.to_owned())]
    );

    h.google.returns("g-1", "u@example.com", false);
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    let reply = h.get(&callback_path("google", &token, "c"), None).await;
    let mut query = canonical();
    query.push(("error", "provider_email_unverified".to_owned()));
    query.push((
        "error_description",
        "provider did not return a verified email; try email OTP".to_owned(),
    ));
    reply.assert_found(&format!("{UI}error?{}", encode(&query)));
    assert!(reply.set_cookies().is_empty());

    h.google.returns("g-1", "u@example.com", true);
    *h.db.fail_account_create.lock().unwrap() = true;
    let token = h.state.envelope.sign(&envelope("google")).unwrap();
    h.get(&callback_path("google", &token, "c"), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant","error_description":"db down"}"#,
        );
}

#[tokio::test]
async fn callback_without_consent_goes_to_consent_with_cookie() {
    let h = harness();
    h.github.returns("gh-7", "new@example.com", true);
    let token = h.state.envelope.sign(&envelope("github")).unwrap();
    let reply = h.get(&callback_path("github", &token, "c"), None).await;
    reply.assert_found(&format!("{UI}consent?{}", encode(&canonical())));
    let session_id = reply.sso_cookie().expect("SSO cookie");
    let session = h.db.session(&session_id);
    assert_eq!(session.login_method, "github");
    let account = h.db.accounts.lock().unwrap()[0].clone();
    assert_eq!(session.account_id, account.id);
    assert_eq!(account.primary_verified_email, "new@example.com");
    assert_eq!(
        reply.set_cookies(),
        [format!(
            "auth_sso_session={session_id}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax"
        )]
    );
    assert_eq!(
        h.github.exchanges.lock().unwrap()[0].1,
        GITHUB_REDIRECT.to_owned()
    );
}

/// AUTH-017: a browser signed in as A that logs in with the provider as B
/// gets a code for B, bound to B's new session.
#[tokio::test]
async fn callback_issues_code_for_the_fresh_session_not_the_cookie() {
    let h = harness();
    h.db.add_account("acct-a", "a@example.com");
    h.db.add_session("sess-a", "acct-a", h.clock.now());
    h.db.add_consent("acct-a", CLIENT, "email openid profile");
    let b = h.db.add_account("acct-b", "b@example.com");
    h.db.add_consent("acct-b", CLIENT, "email openid profile");
    h.google.returns("g-b", &b.primary_verified_email, true);

    let mut prompt_login = envelope("google");
    prompt_login.prompt = "login".to_owned();
    let token = h.state.envelope.sign(&prompt_login).unwrap();
    let reply = h
        .get(
            &callback_path("google", &token, "c"),
            Some("auth_sso_session=sess-a"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    let code = code_from(reply.location(), CALLBACK, "st 1&x");
    let stored = h.db.code(&code);
    let new_session = reply.sso_cookie().expect("SSO cookie");
    assert_ne!(new_session, "sess-a");
    assert_eq!(stored.account_id, "acct-b");
    // The authorization request's nonce rides on the code (AUTH-041).
    assert_eq!(stored.nonce, "n");
    assert_eq!(
        stored
            .sso_session_id
            .as_ref()
            .map(auth_core::domain::SessionId::as_str),
        Some(new_session.as_str())
    );
    assert_eq!(
        stored.auth_time,
        h.db.session(&new_session).authenticated_at
    );
    assert_eq!(stored.granted_scopes, "email openid profile");
}
