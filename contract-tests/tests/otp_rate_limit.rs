use auth_contract_tests::{base_url, http_client, json_response};
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore = "consumes the OTP rate-limit budget; run separately against an idle or restarted server"]
async fn otp_rate_limit_rejects_the_twenty_first_request() {
    let client = http_client();
    let url = format!("{}/v1/auth/otp/resend", base_url());
    let body = json!({"otp_challenge_id": Uuid::new_v4().to_string()});
    for attempt in 1..=21 {
        let response = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .expect("send OTP resend request");
        if attempt <= 20 {
            assert!(
                !response.headers().contains_key("retry-after"),
                "attempt {attempt}"
            );
            assert_eq!(
                json_response(response, StatusCode::BAD_REQUEST).await,
                json!({"error": "invalid_request", "error_description": "otp challenge not found"}),
            );
        } else {
            let retry_after = response
                .headers()
                .get("retry-after")
                .expect("Retry-After on attempt 21")
                .to_str()
                .unwrap()
                .parse::<u64>()
                .expect("Retry-After seconds");
            assert!((1..=60).contains(&retry_after));
            assert_eq!(
                json_response(response, StatusCode::TOO_MANY_REQUESTS).await,
                json!({"error": "rate_limited", "error_description": "too many requests; try again in a moment"}),
            );
        }
    }
}
