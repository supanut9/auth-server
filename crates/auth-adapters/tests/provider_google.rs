//! Google adapter against a wiremock server.

use auth_adapters::provider::GoogleProvider;
use auth_core::ports::IdentityProvider;
use secrecy::SecretString;
use serde_json::json;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONFIG_REDIRECT: &str = "https://auth.example.com/v1/auth/login/callback/google";

async fn provider(server: &MockServer) -> GoogleProvider {
    GoogleProvider::new(
        "cid.apps.googleusercontent.com",
        SecretString::from("s3cr3t*~".to_owned()),
        CONFIG_REDIRECT,
    )
    .expect("client")
    .with_base_urls(
        format!("{}/token", server.uri()),
        format!("{}/v1/userinfo", server.uri()),
    )
}

#[tokio::test]
async fn exchanges_code_and_reads_userinfo() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        // Sorted keys, Go QueryEscape ('*' escaped, '~' kept, space as '+').
        .and(body_string(
            "client_id=cid.apps.googleusercontent.com&client_secret=s3cr3t%2A~&code=a+b%2Fc\
             &grant_type=authorization_code\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": "ya29.tok", "id_token": "ignored"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/userinfo"))
        .and(header("authorization", "Bearer ya29.tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": "1234567890",
            "email": "user@example.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://lh3.googleusercontent.com/a/x",
            "locale": "th"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let profile = provider(&server)
        .await
        .exchange_authorization_code("a b/c", "https://app.example.com/cb")
        .await
        .expect("profile");
    assert_eq!(profile.name, "google");
    assert_eq!(profile.account_id, "1234567890");
    assert_eq!(profile.email, "user@example.com");
    assert!(profile.email_verified);
    assert_eq!(profile.display_name, "Test User");
    assert_eq!(profile.avatar_url, "https://lh3.googleusercontent.com/a/x");
}

#[tokio::test]
async fn empty_redirect_uri_falls_back_to_config() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string(format!(
            "client_id=cid.apps.googleusercontent.com&client_secret=s3cr3t%2A~&code=c\
             &grant_type=authorization_code&redirect_uri={}",
            "https%3A%2F%2Fauth.example.com%2Fv1%2Fauth%2Flogin%2Fcallback%2Fgoogle"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token": "t"})))
        .expect(1)
        .mount(&server)
        .await;
    // Missing/null fields decode to zero values, as Go's encoding/json does.
    Mock::given(method("GET"))
        .and(path("/v1/userinfo"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"sub": "1", "email_verified": null})),
        )
        .mount(&server)
        .await;

    let profile = provider(&server)
        .await
        .exchange_authorization_code("c", "")
        .await
        .expect("profile");
    assert_eq!(profile.account_id, "1");
    assert_eq!(profile.email, "");
    assert!(!profile.email_verified);
}

#[tokio::test]
async fn token_error_status_is_reported() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .mount(&server)
        .await;

    let error = provider(&server)
        .await
        .exchange_authorization_code("c", "")
        .await
        .expect_err("400");
    assert_eq!(
        error.to_string(),
        "google token exchange failed: 400 Bad Request"
    );
}

#[tokio::test]
async fn userinfo_error_status_is_reported() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token": "t"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/userinfo"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let error = provider(&server)
        .await
        .exchange_authorization_code("c", "")
        .await
        .expect_err("401");
    assert_eq!(
        error.to_string(),
        "google userinfo failed: 401 Unauthorized"
    );
}

#[tokio::test]
async fn non_json_token_body_fails() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let error = provider(&server)
        .await
        .exchange_authorization_code("c", "")
        .await
        .expect_err("empty body");
    assert_eq!(error.to_string(), "EOF");
}

#[tokio::test]
async fn unreachable_server_is_a_transport_error() {
    // A port that was free a moment ago (wiremock pools its servers, so a
    // dropped MockServer keeps listening).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let uri = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let provider = GoogleProvider::new("id", SecretString::from("s".to_owned()), CONFIG_REDIRECT)
        .expect("client")
        .with_base_urls(format!("{uri}/token"), format!("{uri}/userinfo"));

    let error = provider
        .exchange_authorization_code("c", "")
        .await
        .expect_err("connection refused");
    assert!(
        error
            .to_string()
            .starts_with(&format!("Post \"{uri}/token\": ")),
        "{error}"
    );
}
