//! Repository ports (`internal/port/*_repositories.go`).
//!
//! `create` follows the Go adapters: an empty ID is assigned a UUIDv7, zero
//! timestamps ([`crate::domain::ZERO_TIME`]) default to the adapter clock, and
//! an empty status defaults to `active` where Go did so. Missing rows return
//! [`RepoError::NotFound`].

use async_trait::async_trait;
use time::OffsetDateTime;

#[cfg(doc)]
use super::RepoError;
use super::RepoResult;
use crate::domain::{
    AccessTokenRecord, Account, AccountId, AccountProvider, AuthorizationCode, ChainId, ClientId,
    ConsentGrant, OAuthClient, OtpChallenge, OtpChallengeId, RefreshToken, RefreshTokenChain,
    SessionId, SsoSession,
};

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn create(&self, account: Account) -> RepoResult<Account>;
    async fn find_by_id(&self, id: &AccountId) -> RepoResult<Account>;
    async fn find_by_primary_verified_email(&self, email: &str) -> RepoResult<Account>;
    async fn update(&self, account: Account) -> RepoResult<Account>;
}

#[async_trait]
pub trait AccountProviderRepository: Send + Sync {
    async fn create(&self, provider: AccountProvider) -> RepoResult<AccountProvider>;
    async fn find_by_provider_account_id(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> RepoResult<AccountProvider>;
    async fn find_by_account_id_and_provider(
        &self,
        account_id: &AccountId,
        provider: &str,
    ) -> RepoResult<AccountProvider>;
}

#[async_trait]
pub trait OAuthClientRepository: Send + Sync {
    async fn create(&self, client: OAuthClient) -> RepoResult<OAuthClient>;
    /// Loads the client with its redirect URIs.
    async fn find_by_client_id(&self, client_id: &ClientId) -> RepoResult<OAuthClient>;
}

#[async_trait]
pub trait AuthorizationCodeRepository: Send + Sync {
    async fn create(&self, code: AuthorizationCode) -> RepoResult<AuthorizationCode>;
    async fn find_by_code_hash(&self, code_hash: &str) -> RepoResult<AuthorizationCode>;
    async fn update(&self, code: AuthorizationCode) -> RepoResult<AuthorizationCode>;
}

/// Consumed provider-state envelope JTIs (replay protection).
#[async_trait]
pub trait SignedStateJtiRepository: Send + Sync {
    /// Records `jti`. Returns [`RepoError::Conflict`] when it was already
    /// recorded (Go: `oauth.ErrJTIExists`).
    async fn insert(&self, jti: &str, expires_at: OffsetDateTime) -> RepoResult<()>;
    /// Deletes rows with `expires_at < now`.
    async fn prune_expired(&self, now: OffsetDateTime) -> RepoResult<()>;
}

#[async_trait]
pub trait ConsentGrantRepository: Send + Sync {
    async fn find_by_account_and_client(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant>;
    async fn upsert(&self, grant: ConsentGrant) -> RepoResult<ConsentGrant>;
}

#[async_trait]
pub trait SsoSessionRepository: Send + Sync {
    async fn create(&self, session: SsoSession) -> RepoResult<SsoSession>;
    async fn find_by_id(&self, id: &SessionId) -> RepoResult<SsoSession>;
    async fn update(&self, session: SsoSession) -> RepoResult<SsoSession>;
    async fn revoke_by_id(&self, id: &SessionId) -> RepoResult<()>;
}

#[async_trait]
pub trait OtpChallengeRepository: Send + Sync {
    async fn create(&self, challenge: OtpChallenge) -> RepoResult<OtpChallenge>;
    async fn find_active_by_request_and_email(
        &self,
        request_id: &str,
        email: &str,
    ) -> RepoResult<OtpChallenge>;
    async fn find_by_id(&self, id: &OtpChallengeId) -> RepoResult<OtpChallenge>;
    async fn update(&self, challenge: OtpChallenge) -> RepoResult<OtpChallenge>;
    /// Newest unverified, unexpired challenge for `email`. Only used by the
    /// non-production OTP test-hint endpoint.
    async fn find_latest_active_by_email(&self, email: &str) -> RepoResult<OtpChallenge>;
}

#[async_trait]
pub trait AccessTokenRepository: Send + Sync {
    async fn create(&self, record: AccessTokenRecord) -> RepoResult<AccessTokenRecord>;
}

#[async_trait]
pub trait RefreshTokenChainRepository: Send + Sync {
    async fn create(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain>;
    /// Returns [`RepoError::NotFound`] when the chain does not exist
    /// (Go: `port.ErrRefreshTokenChainNotFound`).
    async fn find_by_id(&self, id: &ChainId) -> RepoResult<RefreshTokenChain>;
    /// IDs of chains bound to `sso_session_id` that are still `active`.
    async fn list_active_ids_by_sso_session_id(
        &self,
        sso_session_id: &SessionId,
    ) -> RepoResult<Vec<ChainId>>;
    async fn update(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain>;
    async fn revoke_by_id(&self, id: &ChainId) -> RepoResult<()>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn create(&self, token: RefreshToken) -> RepoResult<RefreshToken>;
    async fn find_by_token_hash(&self, token_hash: &str) -> RepoResult<RefreshToken>;
    async fn update(&self, token: RefreshToken) -> RepoResult<RefreshToken>;
    async fn revoke_by_chain_id(&self, chain_id: &ChainId) -> RepoResult<()>;
}
