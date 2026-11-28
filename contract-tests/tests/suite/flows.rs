use std::time::Duration;

use auth_contract_tests::{json_response, setting};
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::{
    protocol::{jwks, verify_jwt},
    support::*,
};

#[tokio::test]
async fn otp_pkce_public_client() {
    let api = Api::new();
    otp_pkce_lifecycle(&api, &api.browser).await;
}

#[tokio::test]
async fn otp_pkce_confidential_client() {
    let api = Api::new();
    otp_pkce_lifecycle(&api, &api.web).await;
}

async fn otp_pkce_lifecycle(api: &Api, client: &OAuthClient) {
    let mut browser = Browser::default();
    let flow = Flow::new(client, "profile openid email");
    let response = send(api.authorize(&flow.params)).await;
    assert_eq!(location(&response), api.ui_route("/login", &flow.params));
    browser.fetch_csrf(api).await;
    let email = unique_email();
    let result = browser.verify_otp(api, &flow, &email).await;
    assert_consent_redirect(api, &flow, &result);
    let sub = string(&result["account"], "id");
    let sid = browser.sso.as_deref().unwrap();

    let response = send(browser.request(api.authorize(&flow.params))).await;
    assert_eq!(location(&response), api.ui_route("/consent", &flow.params));
    let no_prompt = Flow::new(client, FULL_SCOPE).prompt("none");
    let response = send(browser.request(api.authorize(&no_prompt.params))).await;
    no_prompt.assert_error_redirect(location(&response), "consent_required", "consent required");

    let code = browser.accept(api, &flow).await;
    let tokens = response_json(
        flow.exchange(api, client, &code, &flow.verifier),
        StatusCode::OK,
    )
    .await;
    assert_keys(
        &tokens,
        &[
            "access_token",
            "id_token",
            "refresh_token",
            "token_type",
            "expires_in",
            "scope",
        ],
    );
    let refresh = string(&tokens, "refresh_token");
    assert_opaque(refresh);
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 600);
    assert_eq!(tokens["scope"], FULL_SCOPE);

    let keys = jwks(api).await;
    let access_token = string(&tokens, "access_token");
    let access = verify_jwt(&api.issuer, &keys, access_token, &api.audience);
    assert_user_access(&access, client, sub, sid, FULL_SCOPE);
    let discovery =
        response_json(api.get("/.well-known/openid-configuration"), StatusCode::OK).await;
    let id = verify_jwt(
        string(&discovery, "issuer"),
        &keys,
        string(&tokens, "id_token"),
        &client.id,
    );
    assert_keys(
        &id,
        &[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "azp",
            "email",
            "email_verified",
            "name",
            "picture",
            "nonce",
            "sid",
        ],
    );
    assert_eq!(id["sub"], sub);
    assert_eq!(id["azp"], client.id);
    assert_eq!(id["sid"], sid);
    assert_eq!(id["nonce"], flow.params["nonce"].as_str());
    assert_eq!(id["email"], email);
    assert_eq!(id["email_verified"], true);
    assert_eq!(id["name"], result["account"]["display_name"]);
    assert_eq!(id["picture"], "");
    assert!(integer(&id, "auth_time") > 0 && integer(&id, "auth_time") <= integer(&id, "iat"));

    assert_eq!(
        userinfo(api, access_token).await,
        json!({"sub": sub, "email": email, "email_verified": true, "name": id["name"], "picture": ""}),
    );
    let response = send(flow.exchange(api, client, &code, &flow.verifier)).await;
    assert_error(response, StatusCode::BAD_REQUEST, "invalid_grant", None).await;

    let response = send(api.form(
        INTROSPECT,
        &api.browser,
        ClientAuth::Post,
        &[("token", access_token)],
    ))
    .await;
    assert_error(
        response,
        StatusCode::UNAUTHORIZED,
        "unauthorized_client",
        None,
    )
    .await;
    assert_eq!(
        introspect(api, access_token, "access_token").await,
        json!({
            "active": true, "scope": FULL_SCOPE, "client_id": client.id, "sub": sub,
            "token_type": "Bearer", "exp": access["exp"], "iat": access["iat"], "aud": access["aud"],
        }),
    );
    let refresh_info = introspect(api, refresh, "refresh_token").await;
    let issued = integer(&refresh_info, "iat");
    let expires = integer(&refresh_info, "exp");
    assert_eq!(
        refresh_info,
        json!({
            "active": true, "scope": FULL_SCOPE, "client_id": client.id, "sub": sub,
            "token_type": "refresh_token", "iat": issued, "exp": expires,
        })
    );
    assert_eq!(expires - issued, 30 * 24 * 60 * 60);

    let rotated = json_response(api.refresh(client, refresh).await, StatusCode::OK).await;
    assert_keys(
        &rotated,
        &[
            "access_token",
            "refresh_token",
            "token_type",
            "expires_in",
            "scope",
        ],
    );
    assert_eq!(rotated["token_type"], "Bearer");
    assert_eq!(rotated["expires_in"], 600);
    assert_eq!(rotated["scope"], FULL_SCOPE);
    let replacement = string(&rotated, "refresh_token");
    assert_opaque(replacement);
    assert_ne!(replacement, refresh);
    let rotated_access = verify_jwt(
        &api.issuer,
        &keys,
        string(&rotated, "access_token"),
        &api.audience,
    );
    assert_user_access(&rotated_access, client, sub, sid, FULL_SCOPE);
    assert_ne!(rotated_access["jti"], access["jti"]);
    assert_eq!(
        introspect(api, refresh, "refresh_token").await,
        json!({"active": false})
    );
    assert_eq!(
        introspect(api, replacement, "refresh_token").await["active"],
        true
    );
    let grace: u64 = setting("CONTRACT_REFRESH_REUSE_GRACE_SECS", "0")
        .parse()
        .expect("reuse grace in seconds");
    if grace > 0 {
        tokio::time::sleep(Duration::from_secs(grace) + Duration::from_millis(100)).await;
    }
    assert_error(
        api.refresh(client, refresh).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        None,
    )
    .await;
    assert_eq!(
        introspect(api, replacement, "refresh_token").await,
        json!({"active": false})
    );
    assert_error(
        api.refresh(client, replacement).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        None,
    )
    .await;

    let subsequent = Flow::new(client, FULL_SCOPE);
    let response = send(browser.request(api.authorize(&subsequent.params))).await;
    let code = subsequent.code(location(&response));
    let response = send(subsequent.exchange(api, client, &code, "incorrect-verifier")).await;
    assert_error(
        response,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        Some("pkce validation failed"),
    )
    .await;
    response_json(
        subsequent.exchange(api, client, &code, &subsequent.verifier),
        StatusCode::OK,
    )
    .await;
    let response = send(subsequent.exchange(api, client, &code, &subsequent.verifier)).await;
    assert_error(response, StatusCode::BAD_REQUEST, "invalid_grant", None).await;

    let subsequent = Flow::new(client, FULL_SCOPE).prompt("none");
    let response = send(browser.request(api.authorize(&subsequent.params))).await;
    let code = subsequent.code(location(&response));
    let tokens = response_json(
        subsequent.exchange(api, client, &code, &subsequent.verifier),
        StatusCode::OK,
    )
    .await;
    let new_refresh = string(&tokens, "refresh_token");
    let new_access = verify_jwt(
        &api.issuer,
        &keys,
        string(&tokens, "access_token"),
        &api.audience,
    );
    assert_user_access(&new_access, client, sub, sid, FULL_SCOPE);
    for token in ["", "contract-unknown-token", new_refresh, new_refresh] {
        let response = send(api.form(REVOKE, client, ClientAuth::Post, &[("token", token)])).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    assert_eq!(
        introspect(api, new_refresh, "refresh_token").await,
        json!({"active": false})
    );
    assert_error(
        api.refresh(client, new_refresh).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        None,
    )
    .await;
}

fn assert_user_access(claims: &Value, client: &OAuthClient, sub: &str, sid: &str, scope: &str) {
    assert_keys(
        claims,
        &[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "scope",
            "client_id",
            "jti",
            "sid",
        ],
    );
    assert_eq!(claims["sub"], sub);
    assert_eq!(claims["client_id"], client.id);
    assert_eq!(claims["sid"], sid);
    assert_eq!(claims["scope"], scope);
    assert_uuid_v7(string(claims, "jti"));
}

async fn introspect(api: &Api, token: &str, hint: &str) -> Value {
    response_json(
        api.form(
            INTROSPECT,
            &api.worker,
            ClientAuth::Basic,
            &[("token", token), ("token_type_hint", hint)],
        ),
        StatusCode::OK,
    )
    .await
}

async fn userinfo(api: &Api, token: &str) -> Value {
    response_json(api.get(USERINFO).bearer_auth(token), StatusCode::OK).await
}

#[tokio::test]
async fn userinfo_email_and_profile_are_independently_scope_gated() {
    let api = Api::new();
    let mut browser = Browser::default();
    let login = login(&api, &mut browser, &api.browser, FULL_SCOPE).await;
    for (scope, extra) in [
        ("openid", json!({})),
        (
            "openid email",
            json!({"email": login.email, "email_verified": true}),
        ),
        (
            "openid profile",
            json!({"name": login.email.split_once('@').unwrap().0, "picture": ""}),
        ),
    ] {
        let flow = Flow::new(&api.browser, scope);
        let response = send(browser.request(api.authorize(&flow.params))).await;
        let code = flow.code(location(&response));
        let tokens = response_json(
            flow.exchange(&api, &api.browser, &code, &flow.verifier),
            StatusCode::OK,
        )
        .await;
        let mut expected = json!({"sub": login.sub});
        expected
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            userinfo(&api, string(&tokens, "access_token")).await,
            expected
        );
    }
}

#[tokio::test]
async fn consent_csrf_and_reject() {
    let api = Api::new();
    let flow = Flow::new(&api.browser, FULL_SCOPE);
    let mut browser = Browser::default();
    browser.fetch_csrf(&api).await;
    let csrf = browser.csrf.as_deref().unwrap();
    let body = flow.body(&[("csrf_token", csrf)]);
    let response = send(api.post(CONSENT_ACCEPT).json(&body)).await;
    assert_error(
        response,
        StatusCode::FORBIDDEN,
        "csrf",
        Some("missing csrf cookie"),
    )
    .await;

    let body = flow.body(&[("csrf_token", "incorrect-csrf-token")]);
    let response = send(browser.request(api.post(CONSENT_ACCEPT).json(&body))).await;
    assert_error(
        response,
        StatusCode::FORBIDDEN,
        "csrf",
        Some("csrf token mismatch"),
    )
    .await;

    let result = response_json(
        browser.request(api.post(CONSENT_ACCEPT).json(&flow.body(&[]))),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_keys(&result, &["error", "error_description"]);
    assert_eq!(result["error"], "invalid_request");
    assert!(!string(&result, "error_description").is_empty());

    let result = response_json(
        browser.request(
            api.post("/v1/auth/consent/reject")
                .json(&flow.body(&[("csrf_token", csrf)])),
        ),
        StatusCode::OK,
    )
    .await;
    assert_keys(&result, &["redirect_to"]);
    flow.assert_error_redirect(
        string(&result, "redirect_to"),
        "access_denied",
        "user denied consent",
    );
}

#[tokio::test]
async fn otp_wrong_code_attempt_cap_and_resend_cooldown() {
    let api = Api::new();
    let flow = Flow::new(&api.browser, FULL_SCOPE);
    let email = unique_email();
    let challenge = otp_start(&api, &flow, &email).await;
    let response = send(
        api.post("/v1/auth/otp/resend")
            .json(&json!({"otp_challenge_id": challenge})),
    )
    .await;
    assert_error(
        response,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some("otp challenge throttled"),
    )
    .await;

    let fixed = otp_code();
    let wrong = if fixed == "wrongOTP" {
        "bad-code"
    } else {
        "wrongOTP"
    };
    for attempt in 1..=6 {
        let response = send(otp_verify(&api, &flow, &email, &challenge, wrong)).await;
        assert!(!response.headers().contains_key("set-cookie"));
        let description = if attempt == 6 {
            "otp challenge too many attempts"
        } else {
            "otp challenge invalid"
        };
        assert_error(
            response,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some(description),
        )
        .await;
    }
    let response = send(otp_verify(&api, &flow, &email, &challenge, &fixed)).await;
    assert_error(
        response,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        Some("otp challenge too many attempts"),
    )
    .await;
}

#[tokio::test]
async fn support_summary_and_sign_out() {
    let api = Api::new();
    let mut browser = Browser::default();
    let login = login(&api, &mut browser, &api.browser, FULL_SCOPE).await;
    let sid = browser.sso.as_deref().unwrap();
    let path = format!("/v1/support/accounts/{}", login.sub);
    for request in [
        api.get(&path),
        api.get(&path).bearer_auth("invalid-contract-token"),
    ] {
        assert_error(
            send(request).await,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            None,
        )
        .await;
    }

    let summary = api.summary(&login.sub).await;
    assert_keys(
        &summary,
        &["account", "sessions", "consents", "refresh_token_chains"],
    );
    let account = &summary["account"];
    assert_keys(
        account,
        &[
            "id",
            "email",
            "display_name",
            "avatar_url",
            "status",
            "created_at",
            "updated_at",
        ],
    );
    assert_eq!(account["id"], login.sub);
    assert_eq!(account["email"], login.email);
    assert_eq!(
        account["display_name"],
        login.email.split_once('@').unwrap().0
    );
    assert_eq!(account["avatar_url"], "");
    assert_eq!(account["status"], "active");
    for key in ["created_at", "updated_at"] {
        assert_timestamp(account, key);
    }

    let session = one(&summary["sessions"]);
    assert_keys(
        session,
        &[
            "id",
            "status",
            "login_method",
            "authenticated_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
        ],
    );
    assert_eq!(session["id"], sid);
    assert_eq!(session["status"], "active");
    assert_eq!(session["login_method"], "email_otp");
    assert!(session["revoked_at"].is_null());
    for key in ["authenticated_at", "last_seen_at", "expires_at"] {
        assert_timestamp(session, key);
    }

    let consent = one(&summary["consents"]);
    assert_keys(
        consent,
        &[
            "id",
            "client",
            "granted_scopes",
            "granted_at",
            "last_used_at",
            "revoked_at",
        ],
    );
    assert_uuid_v7(string(consent, "id"));
    let client = json!({"client_id": api.browser.id, "display_name": setting("CONTRACT_BROWSER_DISPLAY_NAME", "Development Browser Client")});
    assert_eq!(consent["client"], client);
    assert_eq!(consent["granted_scopes"], FULL_SCOPE);
    assert!(consent["revoked_at"].is_null());
    for key in ["granted_at", "last_used_at"] {
        assert_timestamp(consent, key);
    }

    let chain = one(&summary["refresh_token_chains"]);
    assert_keys(
        chain,
        &[
            "id",
            "client",
            "sso_session_id",
            "scope",
            "status",
            "absolute_expires_at",
            "inactive_expires_at",
            "last_used_at",
            "revoked_at",
        ],
    );
    let chain_id = string(chain, "id");
    assert_uuid_v7(chain_id);
    assert_eq!(chain["client"], client);
    assert_eq!(chain["sso_session_id"], sid);
    assert_eq!(chain["scope"], FULL_SCOPE);
    assert_eq!(chain["status"], "active");
    assert!(chain["revoked_at"].is_null());
    for key in ["absolute_expires_at", "inactive_expires_at", "last_used_at"] {
        assert_timestamp(chain, key);
    }

    assert_eq!(
        response_json(
            api.post(&format!("{path}/sign-out"))
                .bearer_auth(Api::support_token()),
            StatusCode::OK
        )
        .await,
        json!({"account_id": login.sub, "revoked_session_ids": [sid], "revoked_chain_ids": [chain_id], "revoked_refresh_chain_count": 1}),
    );
    let summary = api.summary(&login.sub).await;
    for value in [
        one(&summary["sessions"]),
        one(&summary["refresh_token_chains"]),
    ] {
        assert_eq!(value["status"], "revoked");
        assert_timestamp(value, "revoked_at");
    }
    assert_error(
        api.refresh(&api.browser, login.refresh_token()).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        None,
    )
    .await;
    let response = send(browser.request(api.get("/v1/auth/me"))).await;
    assert_error(response, StatusCode::UNAUTHORIZED, "unauthenticated", None).await;
}

fn one(value: &Value) -> &Value {
    let values = value.as_array().expect("summary list");
    assert_eq!(values.len(), 1);
    &values[0]
}

#[tokio::test]
async fn global_logout_cookie_and_redirect_allowlist() {
    let api = Api::new();
    let mut browser = Browser::default();
    login(&api, &mut browser, &api.browser, FULL_SCOPE).await;
    let target = setting(
        "CONTRACT_LOGOUT_REDIRECT_URI",
        &format!("{}/signed-out?from=contract#return", api.ui),
    );
    let response = send(browser.request(api.get_with_query(
        "/v1/auth/logout/global",
        [("post_logout_redirect_uri", &target)],
    )))
    .await;
    assert_eq!(location(&response), target);
    let (value, attrs) = cookie(&response, SSO);
    assert!(value.is_empty());
    assert_cookie_attributes(attrs, true, Some("0".into()));
    let response = send(browser.request(api.get("/v1/auth/me"))).await;
    assert_error(response, StatusCode::UNAUTHORIZED, "unauthenticated", None).await;

    let response = send(api.get_with_query(
        "/v1/auth/logout/global",
        [(
            "post_logout_redirect_uri",
            "https://unapproved.example.test/signed-out",
        )],
    ))
    .await;
    assert_eq!(location(&response), format!("{}/logout", api.ui));
    assert!(!response.headers().contains_key("set-cookie"));
}
