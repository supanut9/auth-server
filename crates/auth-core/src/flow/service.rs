//! Flow application service (`internal/application/flow/service.go`).
//!
//! Authorization codes, consent grants and the SSO session lifecycle. Every
//! method mirrors its Go counterpart, including the order of checks and
//! repository calls.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use time::{Duration, OffsetDateTime, UtcOffset};

use super::FlowError;
use crate::crypto::{hash_opaque, new_opaque_secret};
use crate::domain::{
    AccountId, AuthorizationCode, ChainId, ClientId, ConsentGrant, Scopes, SessionId, SsoSession,
    SsoSessionStatus,
};
use crate::ports::{
    AuthorizationCodeRepository, Clock, ConsentGrantRepository, IdGenerator, RandomSource,
    RefreshTokenChainRepository, RefreshTokenRepository, SsoSessionRepository,
};

/// Go `flow.Config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowConfig {
    /// Lifetime of an issued authorization code (`AUTH_CODE_TTL`).
    pub authorization_code_ttl: Duration,
    /// Lifetime of a new SSO session (`SSO_SESSION_TTL`).
    pub sso_session_ttl: Duration,
}

/// The ports Go `flow.NewService` takes, plus the [`RandomSource`] that Go
/// read from the global `crypto/rand`.
#[derive(Clone)]
pub struct FlowPorts {
    pub clock: Arc<dyn Clock>,
    /// Held for parity with Go `NewService`; no flow method uses it (new rows
    /// get their UUIDv7 from the repository).
    pub id_generator: Arc<dyn IdGenerator>,
    pub random: Arc<dyn RandomSource>,
    pub authorization_codes: Arc<dyn AuthorizationCodeRepository>,
    pub consent_grants: Arc<dyn ConsentGrantRepository>,
    pub sso_sessions: Arc<dyn SsoSessionRepository>,
    pub refresh_token_chains: Arc<dyn RefreshTokenChainRepository>,
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,
}

impl fmt::Debug for FlowPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowPorts").finish_non_exhaustive()
    }
}

/// Go `flow.IssueDirectCodeRequest`.
///
/// The caller has already validated the OAuth parameters (see
/// [`crate::oauth::validate()`]) and resolved the subject from the SSO session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueDirectCodeRequest {
    pub account_id: AccountId,
    pub client_id: ClientId,
    pub sso_session_id: Option<SessionId>,
    pub redirect_uri: String,
    /// Normalized (trimmed, deduplicated, sorted) before it is stored.
    pub scopes: Vec<String>,
    pub pkce_code_challenge: String,
    pub pkce_code_challenge_method: String,
    pub auth_time: OffsetDateTime,
}

/// Go `flow.ConsumeAuthorizationCodeRequest`.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsumeAuthorizationCodeRequest {
    /// The opaque code value presented at the token endpoint.
    pub code: String,
    pub client_id: ClientId,
    pub redirect_uri: String,
}

impl fmt::Debug for ConsumeAuthorizationCodeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeAuthorizationCodeRequest")
            .field("code", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Go `flow.UpsertConsentRequest`. Scopes were already checked against the
/// client registration by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertConsentRequest {
    pub account_id: AccountId,
    pub client_id: ClientId,
    pub scopes: Vec<String>,
}

/// An authorization code that [`FlowService::consume_authorization_code`]
/// has marked consumed. Only that method builds one, so a token can only be
/// issued from a code that passed every consume check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedCode(AuthorizationCode);

impl ConsumedCode {
    /// The stored record, with `consumed_at` set.
    #[must_use]
    pub fn code(&self) -> &AuthorizationCode {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> AuthorizationCode {
        self.0
    }
}

impl Deref for ConsumedCode {
    type Target = AuthorizationCode;

    fn deref(&self) -> &AuthorizationCode {
        &self.0
    }
}

/// Go `flow.Service`.
#[derive(Clone)]
pub struct FlowService {
    config: FlowConfig,
    ports: FlowPorts,
}

impl fmt::Debug for FlowService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl FlowService {
    /// Go `flow.NewService`.
    #[must_use]
    pub fn new(config: FlowConfig, ports: FlowPorts) -> Self {
        Self { config, ports }
    }

    #[must_use]
    pub fn config(&self) -> FlowConfig {
        self.config
    }

    fn now(&self) -> OffsetDateTime {
        self.ports.clock.now().to_offset(UtcOffset::UTC)
    }

    /// Go `IssueDirectCode`: issues an authorization code without an
    /// authorization-request record. All security gates (parameter
    /// validation, consent) belong to the caller; this only persists the code.
    ///
    /// Returns the code value (handed to the client once) and the stored
    /// record, which holds only its hash.
    ///
    /// # Errors
    /// [`FlowError::AuthorizationRequestInvalidStage`] when the account,
    /// client or redirect URI is empty; otherwise random-source or repository
    /// failures.
    pub async fn issue_direct_code(
        &self,
        req: IssueDirectCodeRequest,
    ) -> Result<(String, AuthorizationCode), FlowError> {
        if req.account_id.is_empty() || req.client_id.is_empty() || req.redirect_uri.is_empty() {
            return Err(FlowError::AuthorizationRequestInvalidStage);
        }
        let secret = new_opaque_secret(self.ports.random.as_ref())?;
        let now = self.now();
        let scopes = Scopes::normalize(&req.scopes);
        let code = AuthorizationCode {
            code_hash: secret.hash,
            authorization_request_id: None,
            account_id: req.account_id,
            client_id: req.client_id,
            sso_session_id: req.sso_session_id,
            redirect_uri: req.redirect_uri,
            granted_scopes: scopes.to_string(),
            pkce_code_challenge: req.pkce_code_challenge,
            pkce_code_challenge_method: req.pkce_code_challenge_method,
            auth_time: req.auth_time.to_offset(UtcOffset::UTC),
            expires_at: now.saturating_add(self.config.authorization_code_ttl),
            created_at: now,
            ..AuthorizationCode::default()
        };
        let code = self.ports.authorization_codes.create(code).await?;
        Ok((secret.value, code))
    }

    /// Go `ConsumeAuthorizationCode`. Checks, in order: hash lookup, client
    /// ID, exact redirect URI, not yet consumed, not expired; then stores
    /// `consumed_at = now`.
    ///
    /// Like Go this is a read-then-update, not an atomic compare-and-set.
    ///
    /// # Errors
    /// [`FlowError::AuthorizationCodeExpired`] for an empty code or an expired
    /// one, [`FlowError::AuthorizationCodeClientMismatch`],
    /// [`FlowError::AuthorizationCodeRedirectMismatch`],
    /// [`FlowError::AuthorizationCodeAlreadyConsumed`], or the repository
    /// error (including `NotFound` for an unknown code).
    pub async fn consume_authorization_code(
        &self,
        req: ConsumeAuthorizationCodeRequest,
    ) -> Result<ConsumedCode, FlowError> {
        let hash = hash_opaque(&req.code).ok_or(FlowError::AuthorizationCodeExpired)?;
        let mut code = self
            .ports
            .authorization_codes
            .find_by_code_hash(&hash)
            .await?;

        let now = self.now();
        if code.client_id != req.client_id {
            return Err(FlowError::AuthorizationCodeClientMismatch);
        }
        if code.redirect_uri != req.redirect_uri {
            return Err(FlowError::AuthorizationCodeRedirectMismatch);
        }
        if code.consumed_at.is_some() {
            return Err(FlowError::AuthorizationCodeAlreadyConsumed);
        }
        if now > code.expires_at {
            return Err(FlowError::AuthorizationCodeExpired);
        }

        code.consumed_at = Some(now);
        let code = self.ports.authorization_codes.update(code).await?;
        Ok(ConsumedCode(code))
    }

    /// Go `UpsertConsent`: records or refreshes the grant for account +
    /// client. New scopes are unioned with the existing grant's scopes
    /// (revocation is a separate operation), `granted_at` is kept,
    /// `last_used_at` becomes now and `revoked_at` is cleared.
    ///
    /// Like Go, any lookup error (not only `NotFound`) is treated as "no
    /// existing grant".
    ///
    /// # Errors
    /// The repository's upsert error.
    pub async fn upsert_consent(
        &self,
        req: UpsertConsentRequest,
    ) -> Result<ConsentGrant, FlowError> {
        let now = self.now();
        let found = self
            .ports
            .consent_grants
            .find_by_account_and_client(&req.account_id, &req.client_id)
            .await;
        let mut grant_scopes = Scopes::normalize(&req.scopes);
        let existing = match found {
            Ok(existing) => {
                grant_scopes =
                    grant_scopes.union(&Scopes::parse_whitespace(&existing.granted_scopes));
                existing
            }
            Err(_) => ConsentGrant::default(),
        };
        let grant = self
            .ports
            .consent_grants
            .upsert(ConsentGrant {
                id: existing.id,
                account_id: req.account_id,
                client_id: req.client_id,
                granted_scopes: grant_scopes.to_string(),
                granted_at: existing.granted_at,
                last_used_at: now,
                revoked_at: None,
            })
            .await?;
        Ok(grant)
    }

    /// Go `HasConsentForScopes`: true when the account has an unrevoked grant
    /// for the client covering every requested scope (a superset suffices).
    /// Any lookup error yields `false`. Does not touch `last_used_at`.
    pub async fn has_consent_for_scopes<S: AsRef<str>>(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
        scopes: &[S],
    ) -> bool {
        let Ok(grant) = self
            .ports
            .consent_grants
            .find_by_account_and_client(account_id, client_id)
            .await
        else {
            return false;
        };
        if grant.revoked_at.is_some() {
            return false;
        }
        Scopes::normalize(scopes).is_subset_of(&Scopes::parse_whitespace(&grant.granted_scopes))
    }

    /// Go `StartSSOSession`: creates an active session expiring after the
    /// configured TTL. The repository assigns the ID (UUIDv7).
    ///
    /// # Errors
    /// The repository's create error.
    pub async fn start_sso_session(
        &self,
        account_id: &AccountId,
        login_method: &str,
    ) -> Result<SsoSession, FlowError> {
        let now = self.now();
        let session = self
            .ports
            .sso_sessions
            .create(SsoSession {
                account_id: account_id.clone(),
                status: SsoSessionStatus::Active,
                login_method: login_method.to_owned(),
                authenticated_at: now,
                last_seen_at: now,
                expires_at: now.saturating_add(self.config.sso_session_ttl),
                created_at: now,
                updated_at: now,
                ..SsoSession::default()
            })
            .await?;
        Ok(session)
    }

    /// Go `LogoutLocal`: revokes one refresh-token chain (tokens first, then
    /// the chain), but only when it belongs to `sso_session_id`.
    ///
    /// Empty IDs, an unknown chain and a chain owned by another session are
    /// silent no-ops.
    ///
    /// # Errors
    /// Repository failures other than the chain lookup's `NotFound`.
    pub async fn logout_local(
        &self,
        sso_session_id: &SessionId,
        refresh_token_chain_id: &ChainId,
    ) -> Result<(), FlowError> {
        if sso_session_id.is_empty() || refresh_token_chain_id.is_empty() {
            return Ok(());
        }
        let chain = match self
            .ports
            .refresh_token_chains
            .find_by_id(refresh_token_chain_id)
            .await
        {
            Ok(chain) => chain,
            Err(error) if error.is_not_found() => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if chain.sso_session_id != *sso_session_id {
            return Ok(());
        }
        self.ports
            .refresh_tokens
            .revoke_by_chain_id(refresh_token_chain_id)
            .await?;
        self.ports
            .refresh_token_chains
            .revoke_by_id(refresh_token_chain_id)
            .await?;
        Ok(())
    }

    /// Go `LogoutGlobal`: revokes the SSO session, then each of its active
    /// refresh-token chains (tokens first, then the chain). Other sessions of
    /// the same account are untouched. An empty ID is a no-op.
    ///
    /// # Errors
    /// The first repository failure; later steps are not attempted.
    pub async fn logout_global(&self, sso_session_id: &SessionId) -> Result<(), FlowError> {
        if sso_session_id.is_empty() {
            return Ok(());
        }
        self.ports.sso_sessions.revoke_by_id(sso_session_id).await?;
        let chain_ids = self
            .ports
            .refresh_token_chains
            .list_active_ids_by_sso_session_id(sso_session_id)
            .await?;
        for chain_id in &chain_ids {
            self.ports
                .refresh_tokens
                .revoke_by_chain_id(chain_id)
                .await?;
            self.ports
                .refresh_token_chains
                .revoke_by_id(chain_id)
                .await?;
        }
        Ok(())
    }
}
