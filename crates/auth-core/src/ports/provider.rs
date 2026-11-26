use async_trait::async_trait;

use super::ProviderError;

/// Profile returned by an external identity provider (`port.ProviderProfile`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderProfile {
    /// Provider name, e.g. `google`.
    pub name: String,
    /// The provider's stable account ID.
    pub account_id: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub avatar_url: String,
}

/// `port.IdentityProvider`.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    fn name(&self) -> &str;

    async fn exchange_authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ProviderProfile, ProviderError>;
}
