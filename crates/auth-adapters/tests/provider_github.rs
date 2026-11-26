//! GitHub adapter against a wiremock server.

use auth_adapters::provider::GitHubProvider;
use auth_core::ports::{IdentityProvider, ProviderProfile};
use secrecy::SecretString;
use serde_json::{Value, json};
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONFIG_REDIRECT: &str = "https://auth.example.com/v1/auth/login/callback/github";

fn provider(server: &MockServer) -> GitHubProvider {
    GitHubProvider::new(
        "Iv1.client",
        SecretString::from("gh-secret".to_owned()),
        CONFIG_REDIRECT,
    )
    .expect("client")
    .with_base_urls(
        format!("{}/login/oauth/access_token", server.uri()),
        server.uri(),
    )
}

async fn mount_token(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(header("accept", "application/json"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_api(server: &MockServer, route: &str, token: &str, status: u16, body: Value) {
    Mock::given(method("GET"))
        .and(path(route))
        .and(header("accept", "application/vnd.github+json"))
        .and(header("x-github-api-version", "2022-11-28"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

async fn login_with_emails(user: Value, emails: Value) -> ProviderProfile {
    let server = MockServer::start().await;
    mount_token(
        &server,
        json!({"access_token": "gho_tok", "token_type": "bearer"}),
    )
    .await;
    mount_api(&server, "/user", "gho_tok", 200, user).await;
    mount_api(&server, "/user/emails", "gho_tok", 200, emails).await;
    provider(&server)
        .exchange_authorization_code("code", "")
        .await
        .expect("profile")
}

#[tokio::test]
async fn happy_path_sends_go_form_and_maps_profile() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(body_string(
            "client_id=Iv1.client&client_secret=gh-secret&code=abc\
             &redirect_uri=https%3A%2F%2Fauth.example.com%2Fv1%2Fauth%2Flogin%2Fcallback%2Fgithub",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token": "gho_tok"})))
        .expect(1)
        .mount(&server)
        .await;
    mount_api(
        &server,
        "/user",
        "gho_tok",
        200,
        json!({"id": 583231, "login": "octocat", "name": "The Octocat", "avatar_url": "https://avatars.githubusercontent.com/u/583231"}),
    )
    .await;
    mount_api(
        &server,
        "/user/emails",
        "gho_tok",
        200,
        json!([
            {"email": "octocat@github.com", "primary": true, "verified": true, "visibility": "public"},
            {"email": "other@example.com", "primary": false, "verified": true, "visibility": null}
        ]),
    )
    .await;

    let profile = provider(&server)
        .exchange_authorization_code("abc", "")
        .await
        .expect("profile");
    assert_eq!(
        profile,
        ProviderProfile {
            name: "github".to_owned(),
            account_id: "583231".to_owned(),
            email: "octocat@github.com".to_owned(),
            email_verified: true,
            display_name: "The Octocat".to_owned(),
            avatar_url: "https://avatars.githubusercontent.com/u/583231".to_owned(),
        }
    );
}

#[tokio::test]
async fn display_name_falls_back_to_login() {
    let profile = login_with_emails(
        json!({"id": 7, "login": "octocat", "name": null}),
        json!([{"email": "a@x", "primary": true, "verified": true}]),
    )
    .await;
    assert_eq!(profile.display_name, "octocat");
    assert_eq!(profile.account_id, "7");
}

#[tokio::test]
async fn unverified_primary_wins_and_stays_unverified() {
    // The identity service then rejects the login (email verification required).
    let profile = login_with_emails(
        json!({"id": 1, "login": "u"}),
        json!([
            {"email": "verified@x", "primary": false, "verified": true},
            {"email": "primary@x", "primary": true, "verified": false}
        ]),
    )
    .await;
    assert_eq!(profile.email, "primary@x");
    assert!(!profile.email_verified);
}

#[tokio::test]
async fn first_verified_without_primary() {
    let profile = login_with_emails(
        json!({"id": 1, "login": "u"}),
        json!([
            {"email": "a@x", "primary": false, "verified": false},
            {"email": "b@x", "primary": false, "verified": true},
            {"email": "c@x", "primary": false, "verified": true}
        ]),
    )
    .await;
    assert_eq!(
        (profile.email.as_str(), profile.email_verified),
        ("b@x", true)
    );
}

#[tokio::test]
async fn first_entry_when_none_verified_and_empty_when_no_emails() {
    let profile = login_with_emails(
        json!({"id": 1, "login": "u"}),
        json!([
            {"email": "a@x", "primary": false, "verified": false},
            {"email": "b@x", "primary": false, "verified": false}
        ]),
    )
    .await;
    assert_eq!(
        (profile.email.as_str(), profile.email_verified),
        ("a@x", false)
    );

    let profile = login_with_emails(json!({"id": 1, "login": "u"}), json!([])).await;
    assert_eq!(
        (profile.email.as_str(), profile.email_verified),
        ("", false)
    );

    let profile = login_with_emails(json!({"id": 1, "login": "u"}), Value::Null).await;
    assert_eq!(
        (profile.email.as_str(), profile.email_verified),
        ("", false)
    );
}

#[tokio::test]
async fn error_object_in_200_fails_at_user_fetch() {
    let server = MockServer::start().await;
    mount_token(
        &server,
        json!({
            "error": "bad_verification_code",
            "error_description": "The code passed is incorrect or expired.",
            "error_uri": "https://docs.github.com/apps/managing-oauth-apps/troubleshooting-oauth-app-access-token-request-errors/#bad-verification-code"
        }),
    )
    .await;
    // The empty token is still sent as "Bearer " (the server sees "Bearer" once
    // trailing whitespace is trimmed), which GitHub answers with 401.
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", "Bearer"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "Bad credentials"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = provider(&server)
        .exchange_authorization_code("bad", "")
        .await
        .expect_err("401");
    assert_eq!(
        error.to_string(),
        "github user fetch failed: 401 Unauthorized"
    );
}

#[tokio::test]
async fn token_error_status_is_reported() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let error = provider(&server)
        .exchange_authorization_code("c", "")
        .await
        .expect_err("503");
    assert_eq!(
        error.to_string(),
        "github token exchange failed: 503 Service Unavailable"
    );
}

#[tokio::test]
async fn email_fetch_error_status_is_reported() {
    let server = MockServer::start().await;
    mount_token(&server, json!({"access_token": "t"})).await;
    mount_api(&server, "/user", "t", 200, json!({"id": 1, "login": "u"})).await;
    mount_api(
        &server,
        "/user/emails",
        "t",
        404,
        json!({"message": "Not Found"}),
    )
    .await;

    let error = provider(&server)
        .exchange_authorization_code("c", "")
        .await
        .expect_err("404");
    assert_eq!(
        error.to_string(),
        "github email fetch failed: 404 Not Found"
    );
}
