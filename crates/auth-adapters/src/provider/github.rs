//! GitHub OAuth adapter (`internal/adapter/out/provider/github.go`).

use async_trait::async_trait;
use auth_core::ports::{IdentityProvider, ProviderError, ProviderProfile};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use secrecy::{ExposeSecret, SecretString};

use super::{
    FORM_CONTENT_TYPE, TokenResponse, check_status, decode_json, first_non_empty, go_encode_values,
    http_client, transport_error,
};
use crate::config::Config;

pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// `GET {base}/user` and `GET {base}/user/emails`.
pub const GITHUB_API_BASE_URL: &str = "https://api.github.com";

const NAME: &str = "github";
const API_ACCEPT: &str = "application/vnd.github+json";
const API_VERSION_HEADER: &str = "X-GitHub-Api-Version";
const API_VERSION: &str = "2022-11-28";

/// Exchanges a GitHub authorization code, then reads `/user` and `/user/emails`.
#[derive(Debug, Clone)]
pub struct GitHubProvider {
    client: reqwest::Client,
    client_id: String,
    client_secret: SecretString,
    redirect_url: String,
    token_url: String,
    api_base_url: String,
}

impl GitHubProvider {
    /// `NewGitHubProvider`: a 10s-timeout client against the real GitHub URLs.
    ///
    /// # Errors
    /// Fails only if the HTTP client (TLS backend) cannot be built.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_url: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            client: http_client()?,
            client_id: client_id.into(),
            client_secret,
            redirect_url: redirect_url.into(),
            token_url: GITHUB_TOKEN_URL.to_owned(),
            api_base_url: GITHUB_API_BASE_URL.to_owned(),
        })
    }

    /// Built only when `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` and
    /// `GITHUB_REDIRECT_URL` are all set (`httpserver/server.go`).
    #[must_use]
    pub fn from_config(config: &Config) -> Option<Result<Self, ProviderError>> {
        let configured = !config.github_client_id.is_empty()
            && !config.github_client_secret.expose_secret().is_empty()
            && !config.github_redirect_url.is_empty();
        configured.then(|| {
            Self::new(
                config.github_client_id.clone(),
                config.github_client_secret.clone(),
                config.github_redirect_url.clone(),
            )
        })
    }

    /// Points the adapter at other endpoints (tests use a wiremock server).
    /// `api_base_url` has no trailing slash; `/user` and `/user/emails` are appended.
    #[must_use]
    pub fn with_base_urls(
        mut self,
        token_url: impl Into<String>,
        api_base_url: impl Into<String>,
    ) -> Self {
        self.token_url = token_url.into();
        self.api_base_url = api_base_url.into();
        self
    }

    async fn api_get(
        &self,
        url: &str,
        access_token: &str,
    ) -> Result<reqwest::Response, ProviderError> {
        self.client
            .get(url)
            .header(ACCEPT, API_ACCEPT)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(API_VERSION_HEADER, API_VERSION)
            .send()
            .await
            .map_err(|error| transport_error("Get", url, error))
    }
}

#[derive(Debug, Default, serde::Deserialize)]
struct GitHubUser {
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
}

/// One `/user/emails` entry. Go also decoded `visibility` but never used it.
#[derive(Debug, Default, Clone, serde::Deserialize)]
struct GitHubEmail {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    primary: Option<bool>,
    #[serde(default)]
    verified: Option<bool>,
}

/// Go's `pickGitHubEmail`: the first primary address with its own verified flag
/// (an unverified primary wins over a verified secondary), else the first
/// verified address, else the first address, else `("", false)`.
fn pick_github_email(emails: &[GitHubEmail]) -> (String, bool) {
    let email_of = |item: &GitHubEmail| item.email.clone().unwrap_or_default();
    if let Some(primary) = emails.iter().find(|item| item.primary.unwrap_or_default()) {
        return (email_of(primary), primary.verified.unwrap_or_default());
    }
    if let Some(verified) = emails.iter().find(|item| item.verified.unwrap_or_default()) {
        return (email_of(verified), true);
    }
    emails.first().map_or_else(
        || (String::new(), false),
        |first| (email_of(first), first.verified.unwrap_or_default()),
    )
}

#[async_trait]
impl IdentityProvider for GitHubProvider {
    fn name(&self) -> &str {
        NAME
    }

    async fn exchange_authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ProviderProfile, ProviderError> {
        let form = go_encode_values(&[
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose_secret()),
            ("code", code),
            (
                "redirect_uri",
                first_non_empty(redirect_uri, &self.redirect_url),
            ),
        ]);
        let response = self
            .client
            .post(&self.token_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, FORM_CONTENT_TYPE)
            .body(form)
            .send()
            .await
            .map_err(|error| transport_error("Post", &self.token_url, error))?;
        check_status(response.status(), "github token exchange failed")?;
        // GitHub reports a bad code as `200 {"error": ...}`; that decodes to an
        // empty token and the `/user` call below fails with 401, as in Go.
        let token: TokenResponse = decode_json(response).await?;
        let access_token = token.access_token.unwrap_or_default();

        let user_url = format!("{}/user", self.api_base_url);
        let response = self.api_get(&user_url, &access_token).await?;
        check_status(response.status(), "github user fetch failed")?;
        let user: GitHubUser = decode_json(response).await?;

        let emails_url = format!("{}/user/emails", self.api_base_url);
        let response = self.api_get(&emails_url, &access_token).await?;
        check_status(response.status(), "github email fetch failed")?;
        let emails: Vec<Option<GitHubEmail>> = decode_json(response).await?;
        let emails: Vec<GitHubEmail> = emails.into_iter().map(Option::unwrap_or_default).collect();

        let (email, email_verified) = pick_github_email(&emails);
        let name = user.name.unwrap_or_default();
        let login = user.login.unwrap_or_default();
        Ok(ProviderProfile {
            name: NAME.to_owned(),
            account_id: user.id.unwrap_or_default().to_string(),
            email,
            email_verified,
            display_name: first_non_empty(&name, &login).to_owned(),
            avatar_url: user.avatar_url.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(address: &str, primary: bool, verified: bool) -> GitHubEmail {
        GitHubEmail {
            email: Some(address.to_owned()),
            primary: Some(primary),
            verified: Some(verified),
        }
    }

    #[test]
    fn primary_wins_with_its_own_verified_flag() {
        let emails = [email("a@x", false, true), email("p@x", true, false)];
        assert_eq!(pick_github_email(&emails), ("p@x".to_owned(), false));
    }

    #[test]
    fn first_verified_when_no_primary() {
        let emails = [
            email("a@x", false, false),
            email("b@x", false, true),
            email("c@x", false, true),
        ];
        assert_eq!(pick_github_email(&emails), ("b@x".to_owned(), true));
    }

    #[test]
    fn first_entry_when_nothing_verified() {
        let emails = [email("a@x", false, false), email("b@x", false, false)];
        assert_eq!(pick_github_email(&emails), ("a@x".to_owned(), false));
        assert_eq!(pick_github_email(&[]), (String::new(), false));
    }
}
