use time::OffsetDateTime;

use super::{
    AccessTokenRecordId, AccessTokenStatus, AccountId, ChainId, ClientId, RefreshTokenChainStatus,
    RefreshTokenId, SessionId, ZERO_TIME,
};

/// `access_tokens` audit row. Not consulted when validating tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    pub id: AccessTokenRecordId,
    pub jti: String,
    pub sid: String,
    /// `None` for client_credentials tokens.
    pub account_id: Option<AccountId>,
    pub client_id: ClientId,
    pub sso_session_id: Option<SessionId>,
    pub audience: String,
    pub scope: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub status: AccessTokenStatus,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl Default for AccessTokenRecord {
    fn default() -> Self {
        Self {
            id: AccessTokenRecordId::default(),
            jti: String::new(),
            sid: String::new(),
            account_id: None,
            client_id: ClientId::default(),
            sso_session_id: None,
            audience: String::new(),
            scope: String::new(),
            issued_at: ZERO_TIME,
            expires_at: ZERO_TIME,
            status: AccessTokenStatus::default(),
            revoked_at: None,
            created_at: ZERO_TIME,
        }
    }
}

/// `refresh_token_chains` row: one rotation lineage of refresh tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenChain {
    pub id: ChainId,
    pub account_id: AccountId,
    pub client_id: ClientId,
    pub sso_session_id: SessionId,
    pub scope: String,
    pub device_session_id: String,
    pub status: RefreshTokenChainStatus,
    pub absolute_expires_at: OffsetDateTime,
    pub inactive_expires_at: OffsetDateTime,
    pub last_used_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Default for RefreshTokenChain {
    fn default() -> Self {
        Self {
            id: ChainId::default(),
            account_id: AccountId::default(),
            client_id: ClientId::default(),
            sso_session_id: SessionId::default(),
            scope: String::new(),
            device_session_id: String::new(),
            status: RefreshTokenChainStatus::default(),
            absolute_expires_at: ZERO_TIME,
            inactive_expires_at: ZERO_TIME,
            last_used_at: ZERO_TIME,
            revoked_at: None,
            created_at: ZERO_TIME,
            updated_at: ZERO_TIME,
        }
    }
}

/// `refresh_tokens` row. Only the hash of the opaque token is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub refresh_token_chain_id: ChainId,
    pub token_hash: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub replaced_by_token_id: Option<RefreshTokenId>,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Default for RefreshToken {
    fn default() -> Self {
        Self {
            id: RefreshTokenId::default(),
            refresh_token_chain_id: ChainId::default(),
            token_hash: String::new(),
            issued_at: ZERO_TIME,
            expires_at: ZERO_TIME,
            used_at: None,
            replaced_by_token_id: None,
            revoked_at: None,
        }
    }
}

/// `signed_state_jtis` row: a consumed provider-state envelope JTI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStateJti {
    pub jti: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}
