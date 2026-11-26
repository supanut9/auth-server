use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::{BoxError, RepoError, SignedStateJtiRepository};

/// Why a JTI could not be recorded.
#[derive(Debug, thiserror::Error)]
pub enum JtiStoreError {
    /// The JTI was already consumed. Text matches Go `oauth.ErrJTIExists`.
    #[error("oauth: jti replay")]
    Replay,
    #[error(transparent)]
    Other(BoxError),
}

/// Single-use JTI store used by the envelope signer (`oauth.JTIStore`).
#[async_trait]
pub trait JtiStore: Send + Sync {
    async fn insert(&self, jti: &str, expires_at: OffsetDateTime) -> Result<(), JtiStoreError>;
}

/// Backs a [`JtiStore`] with a [`SignedStateJtiRepository`] (Go `JTIStoreAdapter`).
pub struct RepositoryJtiStore<R: ?Sized> {
    repo: Arc<R>,
}

impl<R: ?Sized> RepositoryJtiStore<R> {
    #[must_use]
    pub fn new(repo: Arc<R>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl<R: SignedStateJtiRepository + ?Sized> JtiStore for RepositoryJtiStore<R> {
    async fn insert(&self, jti: &str, expires_at: OffsetDateTime) -> Result<(), JtiStoreError> {
        match self.repo.insert(jti, expires_at).await {
            Ok(()) => Ok(()),
            Err(RepoError::Conflict) => Err(JtiStoreError::Replay),
            Err(error) => Err(JtiStoreError::Other(Box::new(error))),
        }
    }
}
