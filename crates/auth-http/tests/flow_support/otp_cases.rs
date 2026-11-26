//! `POST /v1/auth/otp/{start,verify,resend}` and their rate limit.

use axum::http::StatusCode;
use serde_json::{Value, json};
use time::Duration;

use crate::{
    authorize_cases::code_from,
    flow_support::{
        CALLBACK, CLIENT, Harness, OTP_CODE, UI, encode, harness, json_body, oauth_params, with,
    },
};

const SCOPE: &str = "profile openid email";

fn body_with(params: &[(&'static str, String)], extra: &[(&str, &str)]) -> Value {
    let mut body = json_body(params);
    for (key, value) in extra {
        body[*key] = Value::from(*value);
    }
    body
}

async fn start(h: &Harness, email: &str) -> String {
    let reply = h
        .post_json(
            "/v1/auth/otp/start",
            &body_with(&oauth_params(SCOPE), &[("email", email)]),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    reply.json()["otp_challenge_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn verify_body(params: &[(&'static str, String)], email: &str, id: &str, code: &str) -> Value {
    body_with(
        params,
        &[("email", email), ("otp_challenge_id", id), ("code", code)],
    )
}

#[tokio::test]
async fn start_returns_masked_email_and_otp_redirect() {
    let h = harness();
    let params = oauth_params(SCOPE);
    let reply = h
        .post_json(
            "/v1/auth/otp/start",
            &body_with(&params, &[("email", " alice@example.com ")]),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let json = reply.json();
    let id = json["otp_challenge_id"].as_str().unwrap();
    let mut query = params.clone();
    query.push(("otp_challenge_id", id.to_owned()));
    query.push(("email", "alice@example.com".to_owned()));
    assert_eq!(
        json,
        json!({
            "email": "a***e@example.com",
            "expires_at": "2026-04-01T12:10:00Z",
            "otp_challenge_id": id,
            "redirect_to": format!("{UI}otp?{}", encode(&query)),
        })
    );
    assert_eq!(h.db.otp(id).email, "alice@example.com");
}

#[tokio::test]
async fn start_errors() {
    let h = harness();
    let path = "/v1/auth/otp/start";
    h.post_json(path, &json_body(&oauth_params(SCOPE)), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request","error_description":"email is required"}"#,
        );
    // Validation runs before the challenge is created.
    h.post_json(
        path,
        &body_with(
            &with(oauth_params(SCOPE), "nonce", ""),
            &[("email", "a@example.com")],
        ),
        None,
    )
    .await
    .assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"nonce is required for openid"}"#,
    );
    // A whitespace email passes `required` but not the service.
    h.post_json(
        path,
        &body_with(&oauth_params(SCOPE), &[("email", "   ")]),
        None,
    )
    .await
    .assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"otp email required"}"#,
    );
    assert!(h.db.otps.lock().unwrap().is_empty());
}

#[tokio::test]
async fn verify_without_consent_sets_cookie_and_points_to_consent() {
    let h = harness();
    let id = start(&h, "bob@example.com").await;
    let params = oauth_params(SCOPE);
    let reply = h
        .post_json(
            "/v1/auth/otp/verify",
            &verify_body(&params, "BOB@example.com", &id, OTP_CODE),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let session_id = reply.sso_cookie().expect("SSO cookie");
    let session = h.db.session(&session_id);
    assert_eq!(session.login_method, "email_otp");
    let canonical = with(params, "scope", "email openid profile");
    assert_eq!(
        reply.json(),
        json!({
            "account": {
                "id": session.account_id.as_str(),
                "display_name": "bob",
                "email": "bob@example.com",
            },
            "redirect_to": format!("{UI}consent?{}", encode(&canonical)),
        })
    );
    assert!(
        reply
            .body
            .starts_with(r#"{"account":{"display_name":"bob","email":"bob@example.com","id":""#)
    );
    assert!(h.db.codes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn verify_with_consent_issues_code_for_the_verified_account() {
    let h = harness();
    // Signed in as A; verifies the OTP for B, who already consented.
    h.db.add_account("acct-a", "a@example.com");
    h.db.add_session("sess-a", "acct-a", h.clock.now());
    h.db.add_consent("acct-a", CLIENT, "email openid profile");
    h.db.add_account("acct-b", "b@example.com");
    h.db.add_consent("acct-b", CLIENT, "email openid offline_access profile");
    let id = start(&h, "b@example.com").await;
    let params = with(oauth_params(SCOPE), "prompt", "login");
    let reply = h
        .post_json(
            "/v1/auth/otp/verify",
            &verify_body(&params, "b@example.com", &id, OTP_CODE),
            Some("auth_sso_session=sess-a"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let json = reply.json();
    assert_eq!(json["account"]["id"], "acct-b");
    let code = code_from(json["redirect_to"].as_str().unwrap(), CALLBACK, "st 1&x");
    let stored = h.db.code(&code);
    let session_id = reply.sso_cookie().expect("SSO cookie");
    assert_eq!(stored.account_id, "acct-b");
    assert_eq!(
        stored
            .sso_session_id
            .as_ref()
            .map(auth_core::domain::SessionId::as_str),
        Some(session_id.as_str())
    );
    assert_eq!(stored.auth_time, h.db.session(&session_id).authenticated_at);
}

#[tokio::test]
async fn verify_validates_before_checking_the_code() {
    let h = harness();
    let id = start(&h, "c@example.com").await;
    let path = "/v1/auth/otp/verify";
    // Bind: every OTP field is required.
    h.post_json(
        path,
        &body_with(
            &oauth_params(SCOPE),
            &[("email", "c@example.com"), ("otp_challenge_id", &id)],
        ),
        None,
    )
    .await
    .assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"code is required"}"#,
    );
    // Invalid OAuth params win over a wrong code, and no attempt is counted.
    h.post_json(
        path,
        &verify_body(&with(oauth_params(SCOPE), "scope", "admin"), "c@example.com", &id, "wrong"),
        None,
    )
    .await
    .assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_scope","error_description":"requested scopes are not allowed for this client"}"#,
    );
    assert_eq!(h.db.otp(&id).attempt_count, 0);
    let reply = h
        .post_json(
            path,
            &verify_body(&oauth_params(SCOPE), "c@example.com", &id, "wrong"),
            None,
        )
        .await;
    reply.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_grant","error_description":"otp challenge invalid"}"#,
    );
    assert!(reply.set_cookies().is_empty());
    h.post_json(
        path,
        &verify_body(&oauth_params(SCOPE), "c@example.com", "unknown", OTP_CODE),
        None,
    )
    .await
    .assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_grant","error_description":"otp challenge not found"}"#,
    );
}

#[tokio::test]
async fn resend_throttles_then_returns_new_expiry() {
    let h = harness();
    let id = start(&h, "dave@example.com").await;
    let path = "/v1/auth/otp/resend";
    let body = json!({"otp_challenge_id": id});
    h.post_json(path, &body, None).await.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"otp challenge throttled"}"#,
    );
    h.clock
        .advance(Duration::seconds(61) + Duration::milliseconds(250));
    h.post_json(path, &body, None).await.assert_json(
        StatusCode::OK,
        &format!(
            r#"{{"email":"d**e@example.com","expires_at":"2026-04-01T12:11:01.25Z","otp_challenge_id":"{id}"}}"#
        ),
    );
    assert_eq!(h.db.otp(&id).resend_count, 1);
    h.post_json(path, &json!({}), None).await.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"otp_challenge_id is required"}"#,
    );
    h.post_json(path, &json!({"otp_challenge_id": "missing"}), None)
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request","error_description":"otp challenge not found"}"#,
        );
}

#[tokio::test]
async fn otp_routes_are_rate_limited_per_route() {
    let h = harness();
    for _ in 0..20 {
        let reply = h.post("/v1/auth/otp/resend", "{}", None).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }
    let reply = h.post("/v1/auth/otp/resend", "{}", None).await;
    reply.assert_json(
        StatusCode::TOO_MANY_REQUESTS,
        r#"{"error":"rate_limited","error_description":"too many requests; try again in a moment"}"#,
    );
    let retry: u64 = reply.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry), "{retry}");
    // Another OTP route has its own bucket; non-OTP routes are not limited.
    assert_eq!(
        h.post("/v1/auth/otp/verify", "{}", None).await.status,
        StatusCode::BAD_REQUEST
    );
    for _ in 0..25 {
        assert_eq!(
            h.post("/v1/auth/consent/reject", "{}", None).await.status,
            StatusCode::BAD_REQUEST
        );
    }
}
