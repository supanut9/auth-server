//! Every case of `testdata/golden/cookies.json` (captured from Go).

use auth_http::{
    cookies::{CSRF_COOKIE_NAME, CookiePolicy, SSO_COOKIE_NAME, read_cookie},
    json::to_go_json,
};
use axum::http::{HeaderMap, HeaderValue, header};
use serde_json::{Value, json};

fn golden() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/golden/cookies.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read cookies.json"))
        .expect("parse cookies.json")
}

fn policy(case: &Value) -> CookiePolicy {
    let config = &case["config"];
    CookiePolicy::new(
        config["sso_cookie_secure"].as_bool().unwrap(),
        config["sso_cookie_same_site"].as_str().unwrap(),
        config["sso_cookie_domain"].as_str().unwrap(),
    )
}

fn only_set_cookie(case: &Value, key: &str) -> String {
    let list = case[key].as_array().unwrap();
    assert_eq!(list.len(), 1);
    list[0].as_str().unwrap().to_owned()
}

/// The cookie value a browser would send back for a `Set-Cookie` line.
fn round_trip(set_cookie: &str, name: &str) -> Option<String> {
    let pair = set_cookie.split(';').next().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, HeaderValue::from_str(pair).unwrap());
    read_cookie(&headers, name)
}

#[test]
fn sso_cookie_cases() {
    let golden = golden();
    let cases = golden["sso_cookie"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let policy = policy(case);
        let want = only_set_cookie(case, "set_cookie");
        let got = match case["action"].as_str().unwrap() {
            "set" => {
                let value = case["value"].as_str().unwrap();
                let got = policy.sso_cookie(value, case["max_age"].as_i64().unwrap());
                assert_eq!(
                    round_trip(got.to_str().unwrap(), SSO_COOKIE_NAME).as_deref(),
                    Some(value),
                    "{name}: read back"
                );
                got
            }
            "clear" => {
                assert_eq!(case["max_age"], -1, "{name}");
                policy.clear_sso_cookie()
            }
            other => panic!("unknown action {other}"),
        };
        assert_eq!(got.to_str().unwrap(), want, "{name}");
    }
}

#[test]
fn csrf_cookie_cases() {
    let golden = golden();
    let cases = golden["csrf_cookie"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let token = case["token"].as_str().unwrap();
        let response = &case["response"];
        let got = policy(case).csrf_cookie(token);
        assert_eq!(
            got.to_str().unwrap(),
            only_set_cookie(response, "set_cookie"),
            "{name}"
        );
        assert_eq!(
            round_trip(got.to_str().unwrap(), CSRF_COOKIE_NAME).as_deref(),
            Some(token),
            "{name}: read back"
        );
        // The handler body, rendered through the gin-compatible JSON helper.
        let body = to_go_json(&json!({"csrf_token": token, "expires_in": 1800})).unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            response["body"].as_str().unwrap(),
            "{name}: body"
        );
        assert_eq!(response["content_type"], auth_http::json::JSON_CONTENT_TYPE);
    }
}
