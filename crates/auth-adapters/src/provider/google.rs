//! Google OAuth adapter (`internal/adapter/out/provider/google.go`).

use async_trait::async_trait;
use auth_core::ports::{IdentityProvider, ProviderError, ProviderProfile};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use secrecy::{ExposeSecret, SecretString};

use super::{
    FORM_CONTENT_TYPE, TokenResponse, check_status, decode_json, first_non_empty, go_encode_values,
    http_client, transport_error,
};
use crate::config::Config;

pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

const NAME: &str = "google";

/// Exchanges a Google authorization code and reads the OIDC userinfo endpoint.
/// The ID token is not verified (the profile comes from userinfo), as in Go.
#[derive(Debug, Clone)]
pub struct GoogleProvider {
    client: reqwest::Client,
    client_id: String,
    client_secret: SecretString,
    redirect_url: String,
    token_url: String,
    userinfo_url: String,
}

impl GoogleProvider {
    /// `NewGoogleProvider`: a 10s-timeout client against the real Google URLs.
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
            token_url: GOOGLE_TOKEN_URL.to_owned(),
            userinfo_url: GOOGLE_USERINFO_URL.to_owned(),
        })
    }

    /// Built only when `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and
    /// `GOOGLE_REDIRECT_URL` are all set (`httpserver/server.go`).
    #[must_use]
    pub fn from_config(config: &Config) -> Option<Result<Self, ProviderError>> {
        let configured = !config.google_client_id.is_empty()
            && !config.google_client_secret.expose_secret().is_empty()
            && !config.google_redirect_url.is_empty();
        configured.then(|| {
            Self::new(
                config.google_client_id.clone(),
                config.google_client_secret.clone(),
                config.google_redirect_url.clone(),
            )
        })
    }

    /// Points the adapter at other endpoints (tests use a wiremock server).
    #[must_use]
    pub fn with_base_urls(
        mut self,
        token_url: impl Into<String>,
        userinfo_url: impl Into<String>,
    ) -> Self {
        self.token_url = token_url.into();
        self.userinfo_url = userinfo_url.into();
        self
    }
}

/// The userinfo fields Go reads.
#[derive(Debug, Default, serde::Deserialize)]
struct GoogleUserInfo {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[async_trait]
impl IdentityProvider for GoogleProvider {
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
            ("grant_type", "authorization_code"),
            (
                "redirect_uri",
                first_non_empty(redirect_uri, &self.redirect_url),
            ),
        ]);
        let response = self
            .client
            .post(&self.token_url)
            .header(CONTENT_TYPE, FORM_CONTENT_TYPE)
            .body(form)
            .send()
            .await
            .map_err(|error| transport_error("Post", &self.token_url, error))?;
        check_status(response.status(), "google token exchange failed")?;
        let token: TokenResponse = decode_json(response).await?;
        let access_token = token.access_token.unwrap_or_default();

        let response = self
            .client
            .get(&self.userinfo_url)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|error| transport_error("Get", &self.userinfo_url, error))?;
        check_status(response.status(), "google userinfo failed")?;
        let profile: GoogleUserInfo = decode_json(response).await?;

        Ok(ProviderProfile {
            name: NAME.to_owned(),
            account_id: profile.sub.unwrap_or_default(),
            email: profile.email.unwrap_or_default(),
            email_verified: profile.email_verified.unwrap_or_default(),
            display_name: profile.name.unwrap_or_default(),
            avatar_url: profile.picture.unwrap_or_default(),
        })
    }
}
