mod common;

use std::net::SocketAddr;

use auth_http::{
    FullPath, GinRouter, RequestId, build_router, json_response,
    middleware::{LogErrors, SupportAuth, client_ip::VercelEdge, support_auth_middleware},
};
use axum::{
    extract::{ConnectInfo, Path},
    http::{Method, StatusCode},
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::get,
};
use common::{UI, app, call, config, config_with, request, send};
use secrecy::SecretString;
use serde_json::{Value, json};
use uuid::Uuid;

async fn echo(request_id: RequestId, full_path: FullPath) -> Response {
    json_response(
        StatusCode::OK,
        &json!({"full_path": full_path.as_str(), "request_id": request_id.as_str()}),
    )
}

async fn boom() -> Response {
    panic!("handler panic")
}

async fn failing() -> Response {
    let mut response = StatusCode::BAD_GATEWAY.into_response();
    response
        .extensions_mut()
        .insert(LogErrors(vec!["upstream timeout ".into()]));
    response
}

fn routes() -> GinRouter {
    GinRouter::new()
        .get("/healthz", echo)
        .post("/v1/oauth2/token", echo)
        .get(
            "/v1/clients/:clientID/public-info",
            |Path(id): Path<String>| async move {
                json_response(StatusCode::OK, &json!({"client_id": id}))
            },
        )
        .get("/panic", boom)
        .get("/failing", failing)
}

fn assert_v4(id: &str) {
    assert_eq!(
        Uuid::parse_str(id).expect("uuid").get_version_num(),
        4,
        "{id}"
    );
}

fn parse_line(line: &str) -> Value {
    serde_json::from_str(line).expect("log line is JSON")
}

// --- request ID -----------------------------------------------------------

#[tokio::test]
async fn request_id_accepts_valid_and_generates_otherwise() {
    let router = build_router(&config());
    let too_long = "a".repeat(129);
    let max = "b".repeat(128);
    for (incoming, keep) in [
        (None, false),
        (Some("contract.request-01_OK"), true),
        (Some("  padded-id  "), true),
        (Some(max.as_str()), true),
        (Some("bad id"), false),
        (Some("semi;colon"), false),
        (Some(too_long.as_str()), false),
    ] {
        let headers: Vec<(&str, &str)> = incoming
            .map(|id| ("X-Request-Id", id))
            .into_iter()
            .collect();
        let reply = call(&router, Method::GET, "/healthz", &headers).await;
        assert_eq!(reply.status, StatusCode::OK);
        let id = reply.header("x-request-id").unwrap().to_owned();
        if keep {
            assert_eq!(id, incoming.unwrap().trim());
        } else {
            assert_v4(&id);
        }
        assert_eq!(
            reply.header("content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(
            reply.body,
            format!(r#"{{"app_name":"auth-server","request_id":"{id}","status":"ok"}}"#)
        );
    }
}

#[tokio::test]
async fn request_id_is_in_extensions_and_on_every_middleware_response() {
    let (router, _) = app(routes(), &config());
    let reply = call(&router, Method::GET, "/healthz", &[("x-request-id", "abc")]).await;
    assert_eq!(
        serde_json::from_str::<Value>(&reply.body).unwrap(),
        json!({"full_path": "/healthz", "request_id": "abc"})
    );
    for (method, uri) in [
        (Method::GET, "/nope"),
        (Method::OPTIONS, "/nope"),
        (Method::GET, "/panic"),
        (Method::GET, "/failing"),
    ] {
        let reply = call(&router, method.clone(), uri, &[("x-request-id", "keep.me")]).await;
        assert_eq!(
            reply.header("x-request-id"),
            Some("keep.me"),
            "{method} {uri}"
        );
    }
}

// --- access log -----------------------------------------------------------

#[tokio::test]
async fn access_log_writes_one_sorted_line_without_query() {
    let (router, lines) = app(routes(), &config());
    let mut req = request(
        Method::GET,
        "/v1/clients/a%20b/public-info?email=someone%40example.com&code=secret",
        &[
            ("x-request-id", "log-1"),
            ("x-forwarded-for", "203.0.113.9, 10.0.0.1"),
        ],
    );
    req.extensions_mut()
        .insert(ConnectInfo("10.0.0.2:4000".parse::<SocketAddr>().unwrap()));
    req.extensions_mut().insert(VercelEdge);
    let reply = send(&router, req).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, r#"{"client_id":"a b"}"#);

    let logged = lines.take();
    assert_eq!(logged.len(), 1);
    let line = &logged[0];
    assert!(!line.contains("secret") && !line.contains('?'), "{line}");
    let entry = parse_line(line);
    let keys: Vec<&String> = entry.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "client_ip",
            "latency_ms",
            "method",
            "path",
            "request_id",
            "status",
            "time"
        ]
    );
    assert!(
        line.starts_with(r#"{"client_ip":"203.0.113.9","latency_ms":"#),
        "{line}"
    );
    assert_eq!(entry["method"], "GET");
    assert_eq!(entry["path"], "/v1/clients/a b/public-info");
    assert_eq!(entry["request_id"], "log-1");
    assert_eq!(entry["status"], 200);
    assert!(entry["latency_ms"].as_i64().unwrap() >= 0);
    let time = entry["time"].as_str().unwrap();
    assert!(
        time.ends_with('Z') && time.len() >= 20 && !time.contains(".0Z"),
        "{time}"
    );
}

#[tokio::test]
async fn access_log_uses_peer_and_records_errors() {
    let (router, lines) = app(routes(), &config());
    let mut req = request(Method::GET, "/failing", &[]);
    req.extensions_mut().insert(ConnectInfo(
        "[::ffff:192.0.2.7]:1".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(send(&router, req).await.status, StatusCode::BAD_GATEWAY);
    let entry = parse_line(&lines.take()[0]);
    assert_eq!(entry["client_ip"], "192.0.2.7");
    assert_eq!(entry["error"], "Error #01: upstream timeout");
    assert_eq!(entry["status"], 502);

    // No peer and no header: "" (as gin with an unparsable RemoteAddr).
    call(&router, Method::POST, "/healthz", &[]).await;
    let entry = parse_line(&lines.take()[0]);
    assert_eq!(entry["client_ip"], "");
    assert_eq!(entry["status"], 404);
    assert_eq!(entry["method"], "POST");
    assert!(entry.get("error").is_none());
}

// --- recovery -------------------------------------------------------------

#[tokio::test]
async fn panic_becomes_empty_500_with_global_headers() {
    let (router, lines) = app(routes(), &config());
    let reply = call(&router, Method::GET, "/panic", &[("origin", UI)]).await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.body, "");
    assert_eq!(reply.header("content-type"), None);
    assert_eq!(reply.header("vary"), Some("Origin"));
    assert_eq!(reply.header("access-control-allow-origin"), Some(UI));
    assert_v4(reply.header("x-request-id").unwrap());
    assert_eq!(parse_line(&lines.take()[0])["status"], 500);

    // The router keeps serving after a panic.
    assert_eq!(
        call(&router, Method::GET, "/healthz", &[]).await.status,
        StatusCode::OK
    );
}

// --- CORS -----------------------------------------------------------------

#[tokio::test]
async fn cors_allows_only_the_auth_ui_origin() {
    let (router, _) = app(routes(), &config());
    for origin in [UI, "https://auth-ui.example/", "https://auth-ui.example///"] {
        let reply = call(&router, Method::GET, "/healthz", &[("origin", origin)]).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.header("vary"), Some("Origin"));
        assert_eq!(reply.header("access-control-allow-origin"), Some(UI));
        assert_eq!(
            reply.header("access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(
            reply.header("access-control-allow-headers"),
            Some("Authorization, Content-Type")
        );
        assert_eq!(
            reply.header("access-control-allow-methods"),
            Some("GET, POST, OPTIONS")
        );
        assert_eq!(reply.header("access-control-max-age"), None);
    }
    for headers in [
        vec![("origin", "https://evil.example")],
        vec![("origin", "https://AUTH-UI.example")],
        vec![("origin", "http://auth-ui.example")],
        vec![],
    ] {
        let reply = call(&router, Method::GET, "/healthz", &headers).await;
        assert_eq!(reply.header("vary"), Some("Origin"));
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-headers",
            "access-control-allow-methods",
        ] {
            assert_eq!(reply.header(name), None, "{headers:?} {name}");
        }
    }
}

#[tokio::test]
async fn every_options_request_is_204_on_any_path() {
    let (router, lines) = app(routes(), &config());
    for uri in [
        "/contract-unknown-path",
        "/v1/oauth2/token",
        "/v1/oauth2/token/",
        "/healthz",
        "/",
        "/panic",
    ] {
        let reply = call(&router, Method::OPTIONS, uri, &[("origin", UI)]).await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{uri}");
        assert_eq!(reply.body, "");
        assert_eq!(reply.header("vary"), Some("Origin"));
        assert_eq!(reply.header("access-control-allow-origin"), Some(UI));
        assert_eq!(
            reply.header("access-control-allow-methods"),
            Some("GET, POST, OPTIONS")
        );
        assert_eq!(reply.header("access-control-max-age"), None);
        assert_eq!(reply.header("content-type"), None);
        assert!(reply.header("x-request-id").is_some());
    }
    assert_eq!(lines.take().len(), 6);

    let reply = call(
        &router,
        Method::OPTIONS,
        "/x",
        &[("origin", "https://evil.example")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(reply.header("vary"), Some("Origin"));
    assert_eq!(reply.header("access-control-allow-origin"), None);
}

#[tokio::test]
async fn handler_set_cors_headers_win() {
    let routes = GinRouter::new().get("/vary", || async {
        ([("vary", "Accept")], "x").into_response()
    });
    let (router, _) = app(routes, &config());
    let reply = call(&router, Method::GET, "/vary", &[]).await;
    assert_eq!(reply.header("vary"), Some("Accept"));
}

// --- routing quirks -------------------------------------------------------

#[tokio::test]
async fn unknown_path_and_wrong_method_are_gin_404s() {
    let (router, lines) = app(routes(), &config());
    for (method, uri) in [
        (Method::GET, "/contract-unknown-path"),
        (Method::POST, "/healthz"),
        (Method::HEAD, "/healthz"),
        (Method::PUT, "/healthz"),
        (Method::DELETE, "/v1/oauth2/token"),
        (Method::PUT, "/healthz/"),
        (Method::GET, "/v1/clients//public-info"),
        (Method::GET, "/healthz//"),
        (Method::GET, "/HEALTHZ"),
    ] {
        let reply = call(&router, method.clone(), uri, &[("origin", UI)]).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {uri}");
        assert_eq!(reply.header("content-type"), Some("text/plain"));
        // Bodies of HEAD responses are dropped on the wire (Go and hyper).
        let body = if method == Method::HEAD {
            ""
        } else {
            "404 page not found"
        };
        assert_eq!(reply.body, body);
        // The "no route" chain runs the global middleware.
        assert!(reply.header("x-request-id").is_some());
        assert_eq!(reply.header("vary"), Some("Origin"));
        assert_eq!(reply.header("access-control-allow-origin"), Some(UI));
        assert_eq!(parse_line(&lines.take()[0])["status"], 404);
    }
}

#[tokio::test]
async fn trailing_slash_redirects_bypass_middleware() {
    let (router, lines) = app(routes(), &config());

    let reply = call(
        &router,
        Method::GET,
        "/healthz/",
        &[("origin", UI), ("x-request-id", "r1")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(reply.header("location"), Some("/healthz"));
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        reply.body,
        "<a href=\"/healthz\">Moved Permanently</a>.\n\n"
    );
    assert_eq!(reply.header("x-request-id"), None);
    assert_eq!(reply.header("vary"), None);
    assert_eq!(reply.header("access-control-allow-origin"), None);

    let reply = call(&router, Method::POST, "/v1/oauth2/token/", &[]).await;
    assert_eq!(reply.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(reply.header("location"), Some("/v1/oauth2/token"));
    assert_eq!(reply.header("content-type"), None);
    assert_eq!(reply.body, "");

    let reply = call(
        &router,
        Method::GET,
        "/v1/clients/abc/public-info/?x=1&y=a%20b",
        &[],
    )
    .await;
    assert_eq!(reply.status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        reply.header("location"),
        Some("/v1/clients/abc/public-info?x=1&y=a%20b")
    );

    let reply = call(
        &router,
        Method::GET,
        "/healthz/",
        &[("x-forwarded-prefix", "/api/")],
    )
    .await;
    assert_eq!(reply.header("location"), Some("/api/healthz"));
    assert_eq!(
        reply.body,
        "<a href=\"/api/healthz\">Moved Permanently</a>.\n\n"
    );

    let reply = call(
        &router,
        Method::POST,
        "/v1/oauth2/token/",
        &[("x-forwarded-prefix", "/a.b//c")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(reply.header("location"), Some("/ab/c/v1/oauth2/token"));

    // A missing trailing slash redirects the other way when only the
    // slashed route exists.
    let slashed = GinRouter::new().get("/dir/", echo);
    let (slashed, _) = app(slashed, &config());
    let reply = call(&slashed, Method::GET, "/dir", &[]).await;
    assert_eq!(reply.status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(reply.header("location"), Some("/dir/"));

    assert!(lines.take().is_empty(), "redirects are not logged");
}

/// Cases cross-checked against Go 1.26 + gin v1.12 (`httptest`).
#[tokio::test]
async fn decoded_path_matching_like_gin() {
    let (router, lines) = app(routes(), &config());
    let reply = call(&router, Method::GET, "/heal%74hz", &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&reply.body).unwrap()["full_path"],
        "/healthz"
    );
    assert_eq!(parse_line(&lines.take()[0])["path"], "/healthz");

    let reply = call(&router, Method::GET, "/healthz%2F", &[]).await;
    assert_eq!(reply.status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(reply.header("location"), Some("/healthz"));

    let reply = call(&router, Method::GET, "/healthz/?", &[]).await;
    assert_eq!(reply.header("location"), Some("/healthz?"));
    assert_eq!(
        reply.body,
        "<a href=\"/healthz?\">Moved Permanently</a>.\n\n"
    );

    let reply = call(
        &router,
        Method::GET,
        "/v1/clients/abc/public-info/?x=1&y=a%20b",
        &[],
    )
    .await;
    assert_eq!(
        reply.body,
        "<a href=\"/v1/clients/abc/public-info?x=1&amp;y=a%20b\">Moved Permanently</a>.\n\n"
    );

    for (prefix, want) in [
        ("api", "api/api/healthz"),
        ("!!!", "//healthz"),
        ("/../..", "/healthz"),
    ] {
        let reply = call(
            &router,
            Method::GET,
            "/healthz/",
            &[("x-forwarded-prefix", prefix)],
        )
        .await;
        assert_eq!(reply.header("location"), Some(want), "{prefix}");
    }
    let (slashed, _) = app(GinRouter::new().get("/dir/", echo), &config());
    let reply = call(
        &slashed,
        Method::GET,
        "/dir",
        &[("x-forwarded-prefix", "x:y")],
    )
    .await;
    assert_eq!(reply.header("location"), Some("xy/dir/xy/dir/"));

    for (method, uri) in [
        (Method::HEAD, "/healthz/"),
        (Method::GET, "/a%20b/"),
        (Method::GET, "/"),
    ] {
        assert_eq!(
            call(&router, method, uri, &[]).await.status,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
    assert!(
        lines
            .take()
            .iter()
            .all(|line| line.contains("\"status\":404"))
    );
}

#[tokio::test]
async fn full_path_is_the_gin_pattern() {
    let routes = GinRouter::new().get("/v1/clients/:clientID/public-info", echo);
    let (router, _) = app(routes, &config());
    let reply = call(
        &router,
        Method::GET,
        "/v1/clients/c-1/public-info",
        &[("x-request-id", "fp")],
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&reply.body).unwrap(),
        json!({"full_path": "/v1/clients/:clientID/public-info", "request_id": "fp"})
    );
}

// --- support bearer auth --------------------------------------------------

fn support_routes(auth: SupportAuth) -> GinRouter {
    GinRouter::new().route(
        Method::GET,
        "/v1/support/accounts/:accountID",
        get(echo).route_layer(from_fn_with_state(auth, support_auth_middleware)),
    )
}

#[tokio::test]
async fn support_auth_statuses() {
    let mut config = config_with(&[("SUPPORT_API_TOKEN", " s3cret ")]);
    let (router, _) = app(support_routes(SupportAuth::from_config(&config)), &config);
    let path = "/v1/support/accounts/acc-1";

    let ok = call(
        &router,
        Method::GET,
        path,
        &[("authorization", "Bearer s3cret")],
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&ok.body).unwrap()["full_path"],
        "/v1/support/accounts/:accountID"
    );

    for headers in [
        vec![],
        vec![("authorization", "Bearer")],
        vec![("authorization", "Bearer wrong")],
        vec![("authorization", "bearer s3cret")],
    ] {
        let reply = call(&router, Method::GET, path, &headers).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{headers:?}");
        assert_eq!(
            reply.header("content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(reply.body, r#"{"error":"invalid_token"}"#);
    }

    // Unknown support paths never reach the group middleware.
    let reply = call(&router, Method::GET, "/v1/support/other", &[]).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    config.support_api_token = SecretString::from("   ".to_owned());
    let (router, _) = app(support_routes(SupportAuth::from_config(&config)), &config);
    let reply = call(
        &router,
        Method::GET,
        path,
        &[("authorization", "Bearer s3cret")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.body, r#"{"error":"support_unavailable"}"#);
}

#[tokio::test]
async fn development_default_support_token_applies() {
    let config = config_with(&[("APP_ENV", "development")]);
    let (router, _) = app(support_routes(SupportAuth::from_config(&config)), &config);
    let reply = call(
        &router,
        Method::GET,
        "/v1/support/accounts/x",
        &[("authorization", "Bearer dev-support-token")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
}

// --- JSON helper ----------------------------------------------------------

#[tokio::test]
async fn json_helper_matches_gin_render() {
    let routes = GinRouter::new().get("/j", || async {
        json_response(
            StatusCode::CREATED,
            &json!({"z": 1, "a": "<&>", "m": {"y": true, "b": null}}),
        )
    });
    let (router, _) = app(routes, &config());
    let reply = call(&router, Method::GET, "/j", &[]).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(
        reply.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(
        reply.body,
        "{\"a\":\"\\u003c\\u0026\\u003e\",\"m\":{\"b\":null,\"y\":true},\"z\":1}"
    );
}

// --- legacy entrypoint router ---------------------------------------------

#[tokio::test]
async fn config_free_router_still_serves_healthz() {
    let router = auth_http::router();
    let reply = call(&router, Method::GET, "/healthz", &[("origin", UI)]).await;
    assert_eq!(reply.status, StatusCode::OK);
    let id = reply.header("x-request-id").unwrap().to_owned();
    assert_v4(&id);
    assert_eq!(
        reply.body,
        format!(r#"{{"app_name":"auth-server","request_id":"{id}","status":"ok"}}"#)
    );
    assert_eq!(reply.header("access-control-allow-origin"), None);
    assert_eq!(
        call(&router, Method::GET, "/healthz/", &[]).await.status,
        StatusCode::MOVED_PERMANENTLY
    );
}
