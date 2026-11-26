use std::error::Error as StdError;

/// Boxed adapter error.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Repository failure shared by every repository port.
///
/// Adapters map driver errors here so `auth-core` never sees sqlx.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// No matching row. Display matches GORM's `ErrRecordNotFound`.
    #[error("record not found")]
    NotFound,
    /// A uniqueness constraint rejected the write (e.g. a replayed JTI).
    #[error("record already exists")]
    Conflict,
    #[error(transparent)]
    Other(BoxError),
}

impl RepoError {
    pub fn other(error: impl Into<BoxError>) -> Self {
        Self::Other(error.into())
    }

    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }

    #[must_use]
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict)
    }
}

pub type RepoResult<T> = Result<T, RepoError>;

macro_rules! adapter_error {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        pub struct $name(BoxError);

        impl $name {
            /// Wraps an error or message; its text is shown verbatim, as Go's `err.Error()` was.
            pub fn new(error: impl Into<BoxError>) -> Self {
                Self(error.into())
            }
        }
    };
}

adapter_error!(
    /// JWT signing, verification or JWKS rendering failure.
    JwtError
);
adapter_error!(
    /// Mail delivery failure.
    MailError
);
adapter_error!(
    /// External identity provider failure (token exchange or profile fetch).
    ProviderError
);
adapter_error!(
    /// The operating system random source failed.
    RandomError
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_go() {
        assert_eq!(RepoError::NotFound.to_string(), "record not found");
        assert_eq!(RepoError::other("db down").to_string(), "db down");
        assert_eq!(
            ProviderError::new("google token exchange failed: 400 Bad Request").to_string(),
            "google token exchange failed: 400 Bad Request"
        );
    }
}
