use time::OffsetDateTime;

use super::{AccountId, AccountProviderId, AccountStatus, ZERO_TIME};

/// `accounts` row (`internal/domain/account.go`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub primary_verified_email: String,
    pub display_name: String,
    pub avatar_url: String,
    pub status: AccountStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            id: AccountId::default(),
            primary_verified_email: String::new(),
            display_name: String::new(),
            avatar_url: String::new(),
            status: AccountStatus::default(),
            created_at: ZERO_TIME,
            updated_at: ZERO_TIME,
        }
    }
}

/// `account_providers` row: an external identity linked to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProvider {
    pub id: AccountProviderId,
    pub account_id: AccountId,
    /// Provider name, e.g. `google` or `github`.
    pub provider: String,
    pub provider_account_id: String,
    pub provider_email: String,
    pub provider_email_verified: bool,
    pub profile_name: String,
    pub profile_avatar_url: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Default for AccountProvider {
    fn default() -> Self {
        Self {
            id: AccountProviderId::default(),
            account_id: AccountId::default(),
            provider: String::new(),
            provider_account_id: String::new(),
            provider_email: String::new(),
            provider_email_verified: false,
            profile_name: String::new(),
            profile_avatar_url: String::new(),
            created_at: ZERO_TIME,
            updated_at: ZERO_TIME,
        }
    }
}

/// Provider profile awaiting an account link (`internal/domain/provider_auth.go`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingProviderProfile {
    pub name: String,
    pub account_id: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub avatar_url: String,
}
