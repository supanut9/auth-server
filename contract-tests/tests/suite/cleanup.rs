use auth_contract_tests::json_response;
use reqwest::StatusCode;
use serde_json::json;

use super::support::{Api, assert_keys, send};

#[tokio::test]
async fn scheduled_cleanup_requires_bearer_and_returns_deleted_counts() {
    let api = Api::new();
    let path = "/v1/internal/cleanup";
    let response = send(api.get(path)).await;
    let secret = std::env::var("CONTRACT_CRON_SECRET").unwrap_or_default();
    if secret.is_empty() {
        assert_eq!(
            json_response(response, StatusCode::SERVICE_UNAVAILABLE).await,
            json!({"error": "cleanup_unavailable"})
        );
        return;
    }

    assert_eq!(
        json_response(response, StatusCode::UNAUTHORIZED).await,
        json!({"error": "invalid_token"})
    );
    let response = send(api.get(path).bearer_auth("wrong-cron-secret")).await;
    assert_eq!(
        json_response(response, StatusCode::UNAUTHORIZED).await,
        json!({"error": "invalid_token"})
    );

    let response = send(api.get(path).bearer_auth(secret)).await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = json_response(response, StatusCode::OK).await;
    assert_keys(&body, &["deleted"]);
    let fields = [
        "signed_state_jtis",
        "authorization_codes",
        "otp_challenges",
        "otp_rate_limit_hits",
    ];
    assert_keys(&body["deleted"], &fields);
    for field in fields {
        assert!(body["deleted"][field].as_u64().is_some(), "{field}");
    }
}
