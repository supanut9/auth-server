//! Authorization domain types (`internal/domain`).
//!
//! Timestamps are `OffsetDateTime` in UTC. Stored scope fields stay raw strings;
//! use [`Scopes`] to compute with them.

mod account;
mod client;
mod ids;
mod otp;
mod scopes;
mod session;
mod status;
mod timestamp;
mod token;

pub use account::{Account, AccountProvider, PendingProviderProfile};
pub use client::OAuthClient;
pub use ids::{
    AccessTokenRecordId, AccountId, AccountProviderId, AuthorizationCodeId, ChainId, ClientId,
    ClientRecordId, ConsentGrantId, OtpChallengeId, RefreshTokenId, SessionId,
};
pub use otp::OtpChallenge;
pub use scopes::Scopes;
pub use session::{AuthorizationCode, ConsentGrant, SsoSession};
pub use status::{
    AccessTokenStatus, AccountStatus, AuthorizationStage, ClientStatus, ClientType,
    RefreshTokenChainStatus, SsoSessionStatus,
};
pub use timestamp::{ZERO_TIME, is_zero_time};
pub use token::{AccessTokenRecord, RefreshToken, RefreshTokenChain, SignedStateJti};
