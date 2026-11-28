use std::collections::BTreeMap;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::RepoResult;
use crate::domain::{
    Account, AccountId, ChainId, ClientId, ConsentGrant, RefreshTokenChain, SessionId, SsoSession,
};

/// Everything the support API shows for one account.
///
/// Rust-only port: Go's support handler queried GORM directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportAccountSummary {
    pub account: Account,
    /// Ordered by `last_seen_at DESC`.
    pub sessions: Vec<SsoSession>,
    /// Ordered by `last_used_at DESC`.
    pub consents: Vec<ConsentGrant>,
    /// Ordered by `last_used_at DESC`.
    pub refresh_token_chains: Vec<RefreshTokenChain>,
    /// Display names of clients referenced by consents or chains. Missing
    /// clients are absent (Go rendered an empty display name).
    pub client_display_names: BTreeMap<ClientId, String>,
}

#[async_trait]
pub trait SupportRepository: Send + Sync {
    async fn load_account_summary(
        &self,
        account_id: &AccountId,
    ) -> RepoResult<SupportAccountSummary>;

    /// In one transaction: marks the sessions and chains `revoked` with
    /// `revoked_at = updated_at = now`, and sets `revoked_at = now` on every
    /// refresh token in those chains.
    async fn sign_out(
        &self,
        session_ids: &[SessionId],
        chain_ids: &[ChainId],
        now: OffsetDateTime,
    ) -> RepoResult<()>;
}

/// Database readiness probe behind `/readyz`.
#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    async fn ping(&self) -> RepoResult<()>;
}

/// Deleted row counts from one cleanup run.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct CleanupCounts {
    pub signed_state_jtis: i64,
    pub authorization_codes: i64,
    pub otp_challenges: i64,
    pub otp_rate_limit_hits: i64,
}

#[async_trait]
pub trait CleanupRepository: Send + Sync {
    /// Deletes expired state JTIs, codes and challenges expired for more
    /// than 24 hours, and rate-limit hits older than one hour, atomically.
    async fn delete_expired(&self, now: OffsetDateTime) -> RepoResult<CleanupCounts>;
}
