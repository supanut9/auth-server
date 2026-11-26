//! String-backed identifier newtypes.
//!
//! IDs stay strings (not `Uuid`) because the Go service treats them as opaque
//! text: an empty ID on `create` means "repository assigns a UUIDv7", and IDs
//! read from cookies or query strings reach repositories unparsed.

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }

            /// True for the unset (Go zero-value) ID.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }
    };
}

id_newtype!(
    /// `accounts.id`; also the token `sub`.
    AccountId
);
id_newtype!(
    /// `account_providers.id`.
    AccountProviderId
);
id_newtype!(
    /// `oauth_clients.id` (internal primary key, not the public `client_id`).
    ClientRecordId
);
id_newtype!(
    /// Public OAuth `client_id` string (`oauth_clients.client_id`).
    ClientId
);
id_newtype!(
    /// `sso_sessions.id`; also the `auth_sso_session` cookie value and token `sid`.
    SessionId
);
id_newtype!(
    /// `authorization_codes.id`.
    AuthorizationCodeId
);
id_newtype!(
    /// `consent_grants.id`.
    ConsentGrantId
);
id_newtype!(
    /// `otp_challenges.id`; the `otp_challenge_id` URL parameter.
    OtpChallengeId
);
id_newtype!(
    /// `access_tokens.id` (audit row, not the JWT `jti`).
    AccessTokenRecordId
);
id_newtype!(
    /// `refresh_token_chains.id`.
    ChainId
);
id_newtype!(
    /// `refresh_tokens.id`.
    RefreshTokenId
);
