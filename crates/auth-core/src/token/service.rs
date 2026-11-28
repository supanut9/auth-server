//! Token issuance and refresh rotation (`internal/application/token/service.go`).
//!
//! Claims are built as [`JwtClaims`] (a sorted map), so the signer serializes
//! them with the same key order as Go's `map[string]any`.

use std::fmt;
use std::sync::Arc;

use serde_json::Value;
use time::{Duration, OffsetDateTime, UtcOffset};

use super::TokenError;
use crate::crypto::{hash_opaque, new_opaque_secret};
use crate::domain::{
    AccessTokenRecord, AccessTokenStatus, AccountId, ChainId, ClientId, RefreshToken,
    RefreshTokenChain, RefreshTokenChainStatus, Scopes, SessionId, SsoSessionStatus,
};
use crate::ports::{
    AccessTokenRepository, Clock, IdGenerator, JwtClaims, JwtSigner, RandomSource,
    RefreshTokenChainRepository, RefreshTokenRepository, SsoSessionRepository,
};

/// `token_type` of every issued token set.
pub const TOKEN_TYPE_BEARER: &str = "Bearer";

/// Go `token.Config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenConfig {
    /// Configured issuer, used verbatim in access tokens.
    pub issuer: String,
    /// `aud` of access tokens (the platform audience).
    pub audience: String,
    pub access_token_ttl: Duration,
    pub id_token_ttl: Duration,
    pub refresh_token_absolute_ttl: Duration,
    pub refresh_token_inactive_ttl: Duration,
    /// A rotated refresh token presented again within this window mints a
    /// sibling token set instead of revoking the chain. Zero or negative
    /// disables the grace window.
    pub refresh_reuse_grace: Duration,
}

impl TokenConfig {
    /// Issuer shared by discovery metadata and ID tokens.
    #[must_use]
    pub fn oidc_issuer(&self) -> &str {
        self.issuer.trim_end_matches('/')
    }
}

/// Go `token.UserTokenRequest` (authorization_code grant).
#[derive(Clone, PartialEq, Eq)]
pub struct UserTokenRequest {
    pub account_id: AccountId,
    pub client_id: ClientId,
    /// Granted scopes; trimmed, deduplicated and sorted before use.
    pub scope: Vec<String>,
    pub sso_session_id: SessionId,
    /// The authorization code row ID in production.
    pub device_session_id: String,
    pub auth_time: OffsetDateTime,
    /// The authorization request's OIDC `nonce`, from the consumed code.
    /// Echoed in the ID token only when non-empty; never in the access token.
    pub nonce: String,
    pub email: String,
    /// Copied into the ID token. The HTTP handler always passes `true`.
    pub email_verified: bool,
    pub name: String,
    pub picture: String,
}

impl fmt::Debug for UserTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserTokenRequest")
            .field("account_id", &self.account_id)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("sso_session_id", &self.sso_session_id)
            .field("device_session_id", &self.device_session_id)
            .field("auth_time", &self.auth_time)
            .field("nonce", &self.nonce)
            .field("email", &"[redacted]")
            .field("email_verified", &self.email_verified)
            .field("name", &"[redacted]")
            .field("picture", &"[redacted]")
            .finish()
    }
}

/// Go `token.ClientCredentialsTokenRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialsTokenRequest {
    pub client_id: ClientId,
    pub scope: Vec<String>,
}

/// Go `token.RefreshTokenRequest`.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshTokenRequest {
    /// The authenticated client.
    pub client_id: ClientId,
    /// The opaque refresh token as presented.
    pub refresh_token: String,
}

impl fmt::Debug for RefreshTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshTokenRequest")
            .field("client_id", &self.client_id)
            .field("refresh_token", &"[redacted]")
            .finish()
    }
}

/// Go `token.IssuedTokens`. Fields Go leaves as zero values are `None`.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedTokens {
    pub access_token: String,
    /// Only the authorization_code grant issues an ID token.
    pub id_token: Option<String>,
    /// `None` for client_credentials.
    pub refresh_token: Option<String>,
    /// Always [`TOKEN_TYPE_BEARER`].
    pub token_type: String,
    /// Access token TTL in whole seconds (truncated, like Go).
    pub expires_in: i64,
    /// Space-joined sorted scopes.
    pub scope: String,
    pub access_token_expires_at: OffsetDateTime,
    pub id_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

impl fmt::Debug for IssuedTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |value: &Option<String>| value.as_ref().map(|_| "[redacted]");
        f.debug_struct("IssuedTokens")
            .field("access_token", &"[redacted]")
            .field("id_token", &redact(&self.id_token))
            .field("refresh_token", &redact(&self.refresh_token))
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("id_token_expires_at", &self.id_token_expires_at)
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .finish()
    }
}

/// Go `token.Service`.
#[derive(Clone)]
pub struct TokenService {
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    random: Arc<dyn RandomSource>,
    signer: Arc<dyn JwtSigner>,
    access_tokens: Arc<dyn AccessTokenRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    refresh_token_chains: Arc<dyn RefreshTokenChainRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    config: TokenConfig,
}

impl fmt::Debug for TokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Port dependencies of [`TokenService`] (Go `NewService` arguments, plus
/// the random source Go read from `crypto/rand` directly).
#[derive(Clone)]
pub struct TokenServiceDeps {
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdGenerator>,
    pub random: Arc<dyn RandomSource>,
    pub signer: Arc<dyn JwtSigner>,
    pub access_tokens: Arc<dyn AccessTokenRepository>,
    pub sso_sessions: Arc<dyn SsoSessionRepository>,
    pub refresh_token_chains: Arc<dyn RefreshTokenChainRepository>,
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,
}

impl fmt::Debug for TokenServiceDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenServiceDeps").finish_non_exhaustive()
    }
}

impl TokenService {
    /// Go `token.NewService`.
    #[must_use]
    pub fn new(config: TokenConfig, deps: TokenServiceDeps) -> Self {
        Self {
            clock: deps.clock,
            ids: deps.ids,
            random: deps.random,
            signer: deps.signer,
            access_tokens: deps.access_tokens,
            sso_sessions: deps.sso_sessions,
            refresh_token_chains: deps.refresh_token_chains,
            refresh_tokens: deps.refresh_tokens,
            config,
        }
    }

    #[must_use]
    pub fn config(&self) -> &TokenConfig {
        &self.config
    }

    /// Checks whether verified JWT claims identify a platform access token.
    #[must_use]
    pub fn is_access_token(&self, claims: &JwtClaims) -> bool {
        claims.get("aud").and_then(Value::as_str) == Some(self.config.audience.as_str())
            && claims.contains_key("scope")
    }

    fn now(&self) -> OffsetDateTime {
        self.clock.now().to_offset(UtcOffset::UTC)
    }

    fn access_expiry(&self, now: OffsetDateTime) -> OffsetDateTime {
        now.saturating_add(self.config.access_token_ttl)
    }

    fn expires_in(&self) -> i64 {
        self.config.access_token_ttl.whole_seconds()
    }

    /// Access token claims shared by user and refresh grants. `sid` is
    /// omitted for client_credentials.
    fn access_claims(
        &self,
        now: OffsetDateTime,
        sub: &str,
        client_id: &ClientId,
        scope: &str,
        jti: &str,
        sid: Option<&SessionId>,
    ) -> JwtClaims {
        let mut claims = JwtClaims::new();
        claims.insert("iss".into(), Value::from(self.config.issuer.as_str()));
        claims.insert("sub".into(), Value::from(sub));
        claims.insert("aud".into(), Value::from(self.config.audience.as_str()));
        claims.insert(
            "exp".into(),
            Value::from(self.access_expiry(now).unix_timestamp()),
        );
        claims.insert("iat".into(), Value::from(now.unix_timestamp()));
        claims.insert("scope".into(), Value::from(scope));
        claims.insert("client_id".into(), Value::from(client_id.as_str()));
        claims.insert("jti".into(), Value::from(jti));
        if let Some(sid) = sid {
            claims.insert("sid".into(), Value::from(sid.as_str()));
        }
        claims
    }

    /// Go `IssueUserTokens`: access token, ID token and a refresh token on a
    /// new chain, whatever the scopes.
    ///
    /// Generated IDs are consumed in order: access `jti`, then chain ID.
    ///
    /// # Errors
    /// Signing, random-source and repository failures.
    pub async fn issue_user_tokens(
        &self,
        req: UserTokenRequest,
    ) -> Result<IssuedTokens, TokenError> {
        let now = self.now();
        let scope = Scopes::normalize(&req.scope).to_string();
        let access_jti = self.ids.new_id();

        let access_exp = self.access_expiry(now);
        let access_claims = self.access_claims(
            now,
            req.account_id.as_str(),
            &req.client_id,
            &scope,
            &access_jti,
            Some(&req.sso_session_id),
        );
        let access_token = self.signer.sign(&access_claims)?;

        let id_exp = now.saturating_add(self.config.id_token_ttl);
        let mut id_claims = JwtClaims::new();
        id_claims.insert("iss".into(), Value::from(self.config.oidc_issuer()));
        id_claims.insert("sub".into(), Value::from(req.account_id.as_str()));
        id_claims.insert("aud".into(), Value::from(req.client_id.as_str()));
        id_claims.insert("azp".into(), Value::from(req.client_id.as_str()));
        if !req.sso_session_id.is_empty() {
            id_claims.insert("sid".into(), Value::from(req.sso_session_id.as_str()));
        }
        id_claims.insert("exp".into(), Value::from(id_exp.unix_timestamp()));
        id_claims.insert("iat".into(), Value::from(now.unix_timestamp()));
        id_claims.insert(
            "auth_time".into(),
            Value::from(req.auth_time.unix_timestamp()),
        );
        id_claims.insert("email".into(), Value::from(req.email.as_str()));
        id_claims.insert("email_verified".into(), Value::from(req.email_verified));
        id_claims.insert("name".into(), Value::from(req.name.as_str()));
        id_claims.insert("picture".into(), Value::from(req.picture.as_str()));
        // OIDC Core 3.1.3.6: echo the authorization request's nonce; omit the
        // claim when none was sent.
        if !req.nonce.is_empty() {
            id_claims.insert("nonce".into(), Value::from(req.nonce.as_str()));
        }
        let id_token = self.signer.sign(&id_claims)?;

        let chain_id = ChainId::new(self.ids.new_id());
        let refresh =
            new_opaque_secret(self.random.as_ref()).map_err(TokenError::GenerateOpaqueToken)?;

        let refresh_exp = now.saturating_add(self.config.refresh_token_absolute_ttl);
        let chain = RefreshTokenChain {
            id: chain_id.clone(),
            account_id: req.account_id.clone(),
            client_id: req.client_id.clone(),
            sso_session_id: req.sso_session_id.clone(),
            scope: scope.clone(),
            device_session_id: req.device_session_id,
            status: RefreshTokenChainStatus::Active,
            absolute_expires_at: refresh_exp,
            inactive_expires_at: now.saturating_add(self.config.refresh_token_inactive_ttl),
            last_used_at: now,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.refresh_token_chains.create(chain).await?;

        self.refresh_tokens
            .create(RefreshToken {
                refresh_token_chain_id: chain_id,
                token_hash: refresh.hash,
                issued_at: now,
                expires_at: refresh_exp,
                ..RefreshToken::default()
            })
            .await?;

        self.access_tokens
            .create(AccessTokenRecord {
                jti: access_jti,
                sid: req.sso_session_id.as_str().to_owned(),
                account_id: Some(req.account_id),
                client_id: req.client_id,
                sso_session_id: Some(req.sso_session_id),
                audience: self.config.audience.clone(),
                scope: scope.clone(),
                issued_at: now,
                expires_at: access_exp,
                status: AccessTokenStatus::Active,
                created_at: now,
                ..AccessTokenRecord::default()
            })
            .await?;

        Ok(IssuedTokens {
            access_token: access_token.token,
            id_token: Some(id_token.token),
            refresh_token: Some(refresh.value),
            token_type: TOKEN_TYPE_BEARER.to_owned(),
            expires_in: self.expires_in(),
            scope,
            access_token_expires_at: access_exp,
            id_token_expires_at: Some(id_exp),
            refresh_token_expires_at: Some(refresh_exp),
        })
    }

    /// Go `IssueClientCredentialsToken`: `sub` = `client_id`, no `sid`, no ID
    /// or refresh token.
    ///
    /// # Errors
    /// Signing and repository failures.
    pub async fn issue_client_credentials_token(
        &self,
        req: ClientCredentialsTokenRequest,
    ) -> Result<IssuedTokens, TokenError> {
        let now = self.now();
        let scope = Scopes::normalize(&req.scope).to_string();
        let access_jti = self.ids.new_id();

        let access_exp = self.access_expiry(now);
        let claims = self.access_claims(
            now,
            req.client_id.as_str(),
            &req.client_id,
            &scope,
            &access_jti,
            None,
        );
        let access_token = self.signer.sign(&claims)?;

        self.access_tokens
            .create(AccessTokenRecord {
                jti: access_jti,
                sid: String::new(),
                account_id: None,
                client_id: req.client_id,
                sso_session_id: None,
                audience: self.config.audience.clone(),
                scope: scope.clone(),
                issued_at: now,
                expires_at: access_exp,
                status: AccessTokenStatus::Active,
                created_at: now,
                ..AccessTokenRecord::default()
            })
            .await?;

        Ok(IssuedTokens {
            access_token: access_token.token,
            id_token: None,
            refresh_token: None,
            token_type: TOKEN_TYPE_BEARER.to_owned(),
            expires_in: self.expires_in(),
            scope,
            access_token_expires_at: access_exp,
            id_token_expires_at: None,
            refresh_token_expires_at: None,
        })
    }

    /// Go `RefreshUserTokens`: rotates a refresh token.
    ///
    /// Check order (each step decides the error when several apply):
    /// 1. hash lookup; 2. token revoked; 3. token already used outside the
    ///    reuse grace window: revoke every token of the chain and the chain,
    ///    then [`TokenError::RefreshTokenReuseDetected`] (before the client
    ///    check); 4. token expired; 5. chain load; 6. client mismatch;
    ///    7. chain inactive or revoked; 8. chain absolute or inactive expiry;
    ///    9. SSO session load, then inactive, revoked or `now >= expires_at`.
    ///
    /// A used token presented within the grace window mints an extra valid
    /// sibling and leaves its own `used_at`/`replaced_by_token_id` untouched.
    ///
    /// # Errors
    /// The [`TokenError`] for the first failed check, or a signing,
    /// random-source or repository failure (a missing token, chain or SSO
    /// session is [`TokenError::Repo`] with `NotFound`).
    pub async fn refresh_user_tokens(
        &self,
        req: RefreshTokenRequest,
    ) -> Result<IssuedTokens, TokenError> {
        let now = self.now();
        let refresh_hash = hash_opaque(&req.refresh_token).ok_or(TokenError::EmptyToken)?;

        let mut current = self
            .refresh_tokens
            .find_by_token_hash(&refresh_hash)
            .await?;

        if current.revoked_at.is_some() {
            return Err(TokenError::RefreshTokenRevoked);
        }
        let already_used = current.used_at.is_some();
        if let Some(used_at) = current.used_at {
            // A just-rotated token presented again within the grace window is
            // a benign concurrent refresh; outside it, reuse means theft.
            let grace = self.config.refresh_reuse_grace;
            if grace <= Duration::ZERO || now - used_at > grace {
                // Go ignores these errors.
                let _ = self
                    .refresh_tokens
                    .revoke_by_chain_id(&current.refresh_token_chain_id)
                    .await;
                let _ = self
                    .refresh_token_chains
                    .revoke_by_id(&current.refresh_token_chain_id)
                    .await;
                return Err(TokenError::RefreshTokenReuseDetected);
            }
        }
        if now > current.expires_at {
            return Err(TokenError::RefreshTokenExpired);
        }

        let mut chain = self
            .refresh_token_chains
            .find_by_id(&current.refresh_token_chain_id)
            .await?;
        if chain.client_id != req.client_id {
            return Err(TokenError::RefreshTokenClientMismatch);
        }
        if chain.status != RefreshTokenChainStatus::Active || chain.revoked_at.is_some() {
            return Err(TokenError::RefreshTokenChainInactive);
        }
        if now > chain.absolute_expires_at || now > chain.inactive_expires_at {
            return Err(TokenError::RefreshTokenExpired);
        }

        let session = self.sso_sessions.find_by_id(&chain.sso_session_id).await?;
        if session.status != SsoSessionStatus::Active
            || session.revoked_at.is_some()
            || now >= session.expires_at
        {
            return Err(TokenError::RefreshTokenSessionInactive);
        }

        let scope = Scopes::parse_whitespace(&chain.scope).to_string();
        let access_jti = self.ids.new_id();
        let access_exp = self.access_expiry(now);
        let claims = self.access_claims(
            now,
            chain.account_id.as_str(),
            &chain.client_id,
            &scope,
            &access_jti,
            Some(&chain.sso_session_id),
        );
        let access_token = self.signer.sign(&claims)?;

        let next =
            new_opaque_secret(self.random.as_ref()).map_err(TokenError::GenerateOpaqueToken)?;

        let replacement = self
            .refresh_tokens
            .create(RefreshToken {
                refresh_token_chain_id: chain.id.clone(),
                token_hash: next.hash,
                issued_at: now,
                expires_at: chain.absolute_expires_at,
                ..RefreshToken::default()
            })
            .await?;

        // Only the first rotation marks the presented token; within the grace
        // window it already points at the first replacement.
        if !already_used {
            current.used_at = Some(now);
            current.replaced_by_token_id = Some(replacement.id);
            self.refresh_tokens.update(current).await?;
        }

        chain.last_used_at = now;
        chain.inactive_expires_at = now.saturating_add(self.config.refresh_token_inactive_ttl);
        self.refresh_token_chains.update(chain.clone()).await?;

        self.access_tokens
            .create(AccessTokenRecord {
                jti: access_jti,
                sid: chain.sso_session_id.as_str().to_owned(),
                account_id: Some(chain.account_id.clone()),
                client_id: chain.client_id.clone(),
                sso_session_id: Some(chain.sso_session_id.clone()),
                audience: self.config.audience.clone(),
                // Go records an empty scope on refresh.
                scope: String::new(),
                issued_at: now,
                expires_at: access_exp,
                status: AccessTokenStatus::Active,
                created_at: now,
                ..AccessTokenRecord::default()
            })
            .await?;

        Ok(IssuedTokens {
            access_token: access_token.token,
            id_token: None,
            refresh_token: Some(next.value),
            token_type: TOKEN_TYPE_BEARER.to_owned(),
            expires_in: self.expires_in(),
            scope,
            access_token_expires_at: access_exp,
            id_token_expires_at: None,
            refresh_token_expires_at: Some(chain.absolute_expires_at),
        })
    }
}

/// Go `hashOpaqueToken`: the stored refresh `token_hash`.
///
/// # Errors
/// [`TokenError::EmptyToken`] for an empty value.
pub fn hash_refresh_token(value: &str) -> Result<String, TokenError> {
    hash_opaque(value).ok_or(TokenError::EmptyToken)
}

/// Scopes a user-identity token would need; never granted to
/// client_credentials.
const USER_ONLY_SCOPES: [&str; 3] = ["openid", "email", "profile"];

/// client_credentials scope rule from Go `handleClientCredentials`
/// (`router.go`): the request may not contain `openid`, `email` or
/// `profile`, and must be a subset of the client's allowed scopes. Both
/// sides are parsed like Go `splitProtocolList` ([`Scopes::parse`]). An empty
/// request is permitted.
#[must_use]
pub fn client_credentials_scope_permitted(requested: &Scopes, allowed: &Scopes) -> bool {
    !USER_ONLY_SCOPES
        .iter()
        .any(|scope| requested.contains(scope))
        && requested.is_subset_of(allowed)
}
