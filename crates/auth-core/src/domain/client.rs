use secrecy::SecretString;
use time::OffsetDateTime;

use super::{ClientId, ClientRecordId, ClientStatus, ClientType, Scopes, ZERO_TIME};

/// `oauth_clients` row plus its registered redirect URIs.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub id: ClientRecordId,
    pub client_id: ClientId,
    pub client_type: ClientType,
    /// `sha256:<b64url>` hash or, for legacy rows, the plaintext secret.
    pub client_secret_hash: SecretString,
    pub display_name: String,
    pub logo_uri: String,
    /// Exact-match redirect URIs in stored order.
    pub redirect_uris: Vec<String>,
    /// Raw stored scope list; order matters for the public-info endpoint.
    pub allowed_scopes: String,
    pub status: ClientStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl OAuthClient {
    /// The allowed scopes parsed with request-scope rules.
    #[must_use]
    pub fn allowed_scope_set(&self) -> Scopes {
        Scopes::parse(&self.allowed_scopes)
    }

    #[must_use]
    pub fn is_public(&self) -> bool {
        self.client_type == ClientType::Public
    }

    #[must_use]
    pub fn has_redirect_uri(&self, candidate: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri == candidate)
    }
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self {
            id: ClientRecordId::default(),
            client_id: ClientId::default(),
            client_type: ClientType::default(),
            client_secret_hash: SecretString::default(),
            display_name: String::new(),
            logo_uri: String::new(),
            redirect_uris: Vec::new(),
            allowed_scopes: String::new(),
            status: ClientStatus::default(),
            created_at: ZERO_TIME,
            updated_at: ZERO_TIME,
        }
    }
}
