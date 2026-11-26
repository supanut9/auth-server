#![allow(dead_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use auth_adapters::config::Config;
use auth_http::{GinRouter, GlobalLayers, middleware::AccessLog};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, Response, StatusCode},
};
use tower::ServiceExt;

pub const UI: &str = "https://auth-ui.example";

pub fn config_with(overrides: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = [
        ("PUBLIC_BASE_URL", "https://auth.example"),
        ("AUTH_UI_BASE_URL", "https://auth-ui.example/"),
        ("DATABASE_URL", "postgres://localhost/unused"),
        ("JWT_ISSUER", "https://auth.example"),
        ("JWT_PRIVATE_KEY_PEM", "unused"),
        ("JWT_PUBLIC_KEY_PEM", "unused"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    for (key, value) in overrides {
        env.insert((*key).to_owned(), (*value).to_owned());
    }
    Config::from_env(|key| env.get(key).cloned()).expect("test config")
}

pub fn config() -> Config {
    config_with(&[])
}

/// Captured access-log lines.
#[derive(Clone, Default)]
pub struct Lines(Arc<Mutex<Vec<String>>>);

impl Lines {
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

pub fn app(routes: GinRouter, config: &Config) -> (Router, Lines) {
    let lines = Lines::default();
    let sink = lines.clone();
    let layers = GlobalLayers::from_config(config).with_access_log(AccessLog::new(move |line| {
        sink.0.lock().unwrap().push(line.to_owned())
    }));
    (routes.into_router(&layers), lines)
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| value.to_str().unwrap())
    }
}

pub async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response: Response<Body> = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

pub fn request(method: Method, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

pub async fn call(router: &Router, method: Method, uri: &str, headers: &[(&str, &str)]) -> Reply {
    send(router, request(method, uri, headers)).await
}
