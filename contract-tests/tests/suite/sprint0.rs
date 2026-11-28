use auth_contract_tests::json_response;
use reqwest::StatusCode;

use super::{
    protocol::{jwks, verify_jwt},
    support::*,
};

#[tokio::test]
async fn sprint0_provider_login_account() {
    let api = Api::new();
    let expected = login(&api, &mut Browser::default(), &api.browser, FULL_SCOPE).await;
    let mut browser = Browser::default();
    let first = login(&api, &mut browser, &api.browser, FULL_SCOPE).await;
    let first_session = browser.sso.clone();
    let flow = Flow::new(&api.browser, FULL_SCOPE).prompt("login");
    let response = send(browser.request(api.authorize(&flow.params))).await;
    assert_eq!(location(&response), api.ui_route("/login", &flow.params));

    let result = browser.verify_otp(&api, &flow, &expected.email).await;
    let second = string(&result["account"], "id");
    assert_eq!(second, expected.sub);
    assert_ne!(second, first.sub);
    assert_ne!(browser.sso, first_session);
    let code = flow.code(string(&result, "redirect_to"));
    let tokens = response_json(
        flow.exchange(&api, &api.browser, &code, &flow.verifier),
        StatusCode::OK,
    )
    .await;
    let keys = jwks(&api).await;
    for (key, issuer, audience) in [
        ("access_token", api.issuer.as_str(), &api.audience),
        (
            "id_token",
            api.issuer.trim_end_matches('/'),
            &api.browser.id,
        ),
    ] {
        let claims = verify_jwt(issuer, &keys, string(&tokens, key), audience);
        assert_eq!(claims["sub"], second);
    }
}

#[tokio::test]
async fn sprint0_local_logout_chain() {
    let api = Api::new();
    let victim = login(&api, &mut Browser::default(), &api.browser, FULL_SCOPE).await;
    let summary = api.summary(&victim.sub).await;
    let chain = string(&summary["refresh_token_chains"][0], "id");
    let response =
        send(api.get_with_query("/v1/auth/logout", [("refresh_token_chain_id", chain)])).await;
    assert_eq!(location(&response), format!("{}/logout", api.ui));
    assert!(!response.headers().contains_key("set-cookie"));
    let result = json_response(
        api.refresh(&api.browser, victim.refresh_token()).await,
        StatusCode::OK,
    )
    .await;
    let rotated = string(&result, "refresh_token");
    assert_opaque(rotated);
    assert_ne!(rotated, victim.refresh_token());
}

#[tokio::test]
async fn sprint0_global_logout_revokes_refresh() {
    let api = Api::new();
    let mut browser = Browser::default();
    let login = login(&api, &mut browser, &api.browser, FULL_SCOPE).await;
    let response = send(browser.request(api.get("/v1/auth/logout/global"))).await;
    assert_eq!(location(&response), format!("{}/logout", api.ui));
    assert_error(
        api.refresh(&api.browser, login.refresh_token()).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        None,
    )
    .await;
}
