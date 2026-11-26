use std::{env, time::Duration};

use reqwest::{Client, Response, StatusCode, redirect::Policy};
use serde_json::Value;

pub mod differential;
pub mod dual;
pub mod normalize;

pub fn setting(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.into())
}

pub fn base_url() -> String {
    setting("AUTH_BASE_URL", "http://localhost:8060")
        .trim_end_matches('/')
        .into()
}

pub fn http_client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build HTTP client")
}

pub async fn json_response(response: Response, status: StatusCode) -> Value {
    let actual = response.status();
    let url = response.url().path().to_owned();
    let content_type = response.headers().get("content-type").cloned();
    let body = response.bytes().await.expect("read HTTP response body");
    let parsed = serde_json::from_slice(&body);
    if actual != status {
        let detail = parsed
            .as_ref()
            .map(normalize::json)
            .map_or_else(|_| "<non-JSON body>".into(), |value| value.to_string());
        panic!("{url}: expected {status}, got {actual}: {detail}");
    }
    assert!(
        content_type
            .and_then(|value| value.to_str().ok().map(str::to_owned))
            .is_some_and(|value| value.split(';').next() == Some("application/json")),
        "{url}: expected JSON content type"
    );
    parsed.unwrap_or_else(|err| panic!("{url}: invalid JSON response: {err}"))
}
