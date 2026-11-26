//! Status and type columns stored as free-form text.
//!
//! Each enum names the values the Go service writes (`internal/domain/shared.go`)
//! and keeps anything else in `Other` so rows round-trip unchanged. `Default`
//! is `Other("")`, the Go zero value; repositories that defaulted an empty
//! status in Go (accounts, SSO sessions, chains, access tokens) must do the same.

macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
            /// Any other stored value, including the empty string.
            Other(String),
        }

        impl $name {
            /// The exact database string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Other(value) => value,
                }
            }

            /// Parses a stored value; unknown strings become `Other`.
            #[must_use]
            pub fn parse(value: &str) -> Self {
                match value {
                    $($text => Self::$variant,)+
                    other => Self::Other(other.to_owned()),
                }
            }

            /// True for the empty Go zero value.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.as_str().is_empty()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::Other(String::new())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::parse(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                match Self::parse(&value) {
                    Self::Other(_) => Self::Other(value),
                    known => known,
                }
            }
        }
    };
}

string_enum!(
    /// `accounts.status`.
    AccountStatus { Active => "active" }
);

string_enum!(
    /// `oauth_clients.status`.
    ClientStatus { Active => "active" }
);

impl ClientStatus {
    /// Go's authorize gate: an empty status counts as usable, as does `active`.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active) || self.is_empty()
    }
}

string_enum!(
    /// `oauth_clients.client_type`.
    ClientType {
        Public => "public",
        Confidential => "confidential",
    }
);

string_enum!(
    /// `sso_sessions.status`.
    SsoSessionStatus {
        Active => "active",
        Revoked => "revoked",
    }
);

string_enum!(
    /// `refresh_token_chains.status`.
    RefreshTokenChainStatus {
        Active => "active",
        Revoked => "revoked",
    }
);

string_enum!(
    /// `access_tokens.status`.
    AccessTokenStatus {
        Active => "active",
        Revoked => "revoked",
    }
);

string_enum!(
    /// Legacy stateful authorize-request stage. The stateless flow no longer
    /// persists it, but the strings are part of the Go domain vocabulary.
    AuthorizationStage {
        LoginRequired => "login_required",
        ProviderRedirect => "provider_redirect",
        OtpRequired => "otp_required",
        ConsentRequired => "consent_required",
        AuthorizationReady => "authorization_ready",
        Completed => "completed",
        Failed => "failed",
        Expired => "expired",
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values_round_trip() {
        for (status, text) in [
            (SsoSessionStatus::Active, "active"),
            (SsoSessionStatus::Revoked, "revoked"),
        ] {
            assert_eq!(status.as_str(), text);
            assert_eq!(SsoSessionStatus::parse(text), status);
        }
        assert_eq!(ClientType::parse("public"), ClientType::Public);
        assert_eq!(ClientType::parse("confidential"), ClientType::Confidential);
        assert_eq!(
            AuthorizationStage::parse("authorization_ready"),
            AuthorizationStage::AuthorizationReady
        );
    }

    #[test]
    fn unknown_values_are_preserved() {
        let status = AccountStatus::from(String::from("suspended"));
        assert_eq!(status, AccountStatus::Other("suspended".into()));
        assert_eq!(status.to_string(), "suspended");
        assert!(AccountStatus::default().is_empty());
        // Matching is exact, like Go's string comparison.
        assert_eq!(
            ClientType::parse("Public"),
            ClientType::Other("Public".into())
        );
    }

    #[test]
    fn client_status_usable_matches_go() {
        assert!(ClientStatus::Active.is_usable());
        assert!(ClientStatus::default().is_usable());
        assert!(!ClientStatus::parse("disabled").is_usable());
    }
}
