use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use time::OffsetDateTime;

use super::*;

/// Drives a future that never awaits real I/O.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

#[derive(Default)]
struct MemoryJtis(Mutex<BTreeSet<String>>);

#[async_trait]
impl SignedStateJtiRepository for MemoryJtis {
    async fn insert(&self, jti: &str, _expires_at: OffsetDateTime) -> RepoResult<()> {
        if jti == "boom" {
            return Err(RepoError::other("connection reset"));
        }
        let mut seen = self.0.lock().expect("lock");
        if seen.insert(jti.to_owned()) {
            Ok(())
        } else {
            Err(RepoError::Conflict)
        }
    }

    async fn prune_expired(&self, _now: OffsetDateTime) -> RepoResult<()> {
        Ok(())
    }
}

#[test]
fn repository_jti_store_maps_conflict_to_replay() {
    let repo: Arc<dyn SignedStateJtiRepository> = Arc::new(MemoryJtis::default());
    let store: Arc<dyn JtiStore> = Arc::new(RepositoryJtiStore::new(repo));
    let exp = OffsetDateTime::UNIX_EPOCH;

    block_on(store.insert("abc", exp)).expect("first insert");
    let replay = block_on(store.insert("abc", exp)).expect_err("replay");
    assert!(matches!(replay, JtiStoreError::Replay));
    assert_eq!(replay.to_string(), "oauth: jti replay");

    let other = block_on(store.insert("boom", exp)).expect_err("db error");
    assert_eq!(other.to_string(), "connection reset");
}

#[test]
fn ports_are_object_safe() {
    fn assert_dyn<T: ?Sized + Send + Sync>() {}
    assert_dyn::<dyn AccountRepository>();
    assert_dyn::<dyn AccountProviderRepository>();
    assert_dyn::<dyn OAuthClientRepository>();
    assert_dyn::<dyn AuthorizationCodeRepository>();
    assert_dyn::<dyn SignedStateJtiRepository>();
    assert_dyn::<dyn ConsentGrantRepository>();
    assert_dyn::<dyn SsoSessionRepository>();
    assert_dyn::<dyn OtpChallengeRepository>();
    assert_dyn::<dyn AccessTokenRepository>();
    assert_dyn::<dyn RefreshTokenChainRepository>();
    assert_dyn::<dyn RefreshTokenRepository>();
    assert_dyn::<dyn SupportRepository>();
    assert_dyn::<dyn ReadinessProbe>();
    assert_dyn::<dyn JtiStore>();
    assert_dyn::<dyn Clock>();
    assert_dyn::<dyn IdGenerator>();
    assert_dyn::<dyn RandomSource>();
    assert_dyn::<dyn OtpCodeGenerator>();
    assert_dyn::<dyn JwtSigner>();
    assert_dyn::<dyn JwksProvider>();
    assert_dyn::<dyn JwtVerifier>();
    assert_dyn::<dyn MailSender>();
    assert_dyn::<dyn IdentityProvider>();
}
