use time::OffsetDateTime;

use super::{
    AccountId, AuthorizationCodeId, ClientId, ConsentGrantId, SessionId, SsoSessionStatus,
    ZERO_TIME,
};

/// `sso_sessions` row: the browser-level login behind the SSO cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoSession {
    pub id: SessionId,
    pub account_id: AccountId,
    pub status: SsoSessionStatus,
    /// `email_otp`, `google`, `github`, ...
    pub login_method: String,
    pub authenticated_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Default for SsoSession {
    fn default() -> Self {
        Self {
            id: SessionId::default(),
            account_id: AccountId::default(),
            status: SsoSessionStatus::default(),
            login_method: String::new(),
            authenticated_at: ZERO_TIME,
            last_seen_at: ZERO_TIME,
            expires_at: ZERO_TIME,
            revoked_at: None,
            created_at: ZERO_TIME,
            updated_at: ZERO_TIME,
        }
    }
}

/// `authorization_codes` row. Only the hash of the code value is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub id: AuthorizationCodeId,
    pub code_hash: String,
    pub authorization_request_id: Option<String>,
    pub account_id: AccountId,
    pub client_id: ClientId,
    pub sso_session_id: Option<SessionId>,
    pub redirect_uri: String,
    /// Space-joined sorted scopes as stored.
    pub granted_scopes: String,
    pub pkce_code_challenge: String,
    pub pkce_code_challenge_method: String,
    /// OIDC `nonce` from the authorization request, echoed in the ID token;
    /// empty when none was sent.
    pub nonce: String,
    pub auth_time: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl Default for AuthorizationCode {
    fn default() -> Self {
        Self {
            id: AuthorizationCodeId::default(),
            code_hash: String::new(),
            authorization_request_id: None,
            account_id: AccountId::default(),
            client_id: ClientId::default(),
            sso_session_id: None,
            redirect_uri: String::new(),
            granted_scopes: String::new(),
            pkce_code_challenge: String::new(),
            pkce_code_challenge_method: String::new(),
            nonce: String::new(),
            auth_time: ZERO_TIME,
            expires_at: ZERO_TIME,
            consumed_at: None,
            created_at: ZERO_TIME,
        }
    }
}

/// `consent_grants` row: scopes an account has granted a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrant {
    pub id: ConsentGrantId,
    pub account_id: AccountId,
    pub client_id: ClientId,
    /// Space-joined sorted scopes as stored.
    pub granted_scopes: String,
    pub granted_at: OffsetDateTime,
    pub last_used_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Default for ConsentGrant {
    fn default() -> Self {
        Self {
            id: ConsentGrantId::default(),
            account_id: AccountId::default(),
            client_id: ClientId::default(),
            granted_scopes: String::new(),
            granted_at: ZERO_TIME,
            last_used_at: ZERO_TIME,
            revoked_at: None,
        }
    }
}
