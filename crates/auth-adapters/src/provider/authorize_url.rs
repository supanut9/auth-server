//! Provider authorization URLs (`handlers_provider_stateless.go`
//! `providerAuthorizationURLWithState`).

use super::go_encode_values;

pub const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";

/// Google's authorization URL: `scope=openid email profile`,
/// `access_type=offline`, `prompt=select_account`, keys sorted, spaces as `+`.
#[must_use]
pub fn google_authorization_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let query = go_encode_values(&[
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("state", state),
        ("prompt", "select_account"),
        ("scope", "openid email profile"),
        ("access_type", "offline"),
    ]);
    format!("{GOOGLE_AUTHORIZE_URL}?{query}")
}

/// GitHub's authorization URL: `scope=read:user user:email`,
/// `prompt=select_account`, keys sorted, spaces as `+`.
#[must_use]
pub fn github_authorization_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let query = go_encode_values(&[
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("state", state),
        ("prompt", "select_account"),
        ("scope", "read:user user:email"),
    ]);
    format!("{GITHUB_AUTHORIZE_URL}?{query}")
}

/// Dispatches on the provider name; an unknown provider yields `""`, as in Go.
/// `client_id` and `redirect_uri` come from config (`GOOGLE_*` / `GITHUB_*`).
#[must_use]
pub fn provider_authorization_url(
    provider: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
) -> String {
    match provider {
        "google" => google_authorization_url(client_id, redirect_uri, state),
        "github" => github_authorization_url(client_id, redirect_uri, state),
        _ => String::new(),
    }
}
