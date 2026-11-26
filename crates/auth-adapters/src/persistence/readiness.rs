//! Database readiness probe behind `/readyz` (Go: `router.go` `readyz`,
//! which called `sql.DB.PingContext` under a 2 second context timeout).

use std::time::Duration;

use async_trait::async_trait;
use auth_core::ports::{ReadinessProbe, RepoError, RepoResult};
use sqlx::{Connection, PgPool};

/// Go's `context.WithTimeout(ctx, 2*time.Second)` around the ping.
pub const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Postgres [`ReadinessProbe`].
#[derive(Clone)]
pub struct PgReadinessProbe {
    pool: PgPool,
    timeout: Duration,
}

impl PgReadinessProbe {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            timeout: PING_TIMEOUT,
        }
    }
}

#[async_trait]
impl ReadinessProbe for PgReadinessProbe {
    /// Like `sql.DB.PingContext`: take a pooled connection (opening one if
    /// needed) and ping it. The timeout covers both steps.
    async fn ping(&self) -> RepoResult<()> {
        let ping = async {
            let mut conn = self.pool.acquire().await?;
            conn.ping().await
        };
        match tokio::time::timeout(self.timeout, ping).await {
            Ok(result) => result.map_err(RepoError::other),
            // Go's ctx.Err() text.
            Err(_) => Err(RepoError::other("context deadline exceeded")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use auth_core::ports::{ReadinessProbe, RepoError};
    use sqlx::PgPool;
    use sqlx::postgres::PgPoolOptions;

    use super::{PING_TIMEOUT, PgReadinessProbe};

    #[sqlx::test(migrations = false)]
    async fn ping_succeeds_against_live_database(pool: PgPool) {
        PgReadinessProbe::new(pool).ping().await.unwrap();
    }

    #[test]
    fn default_timeout_matches_go() {
        assert_eq!(PING_TIMEOUT, Duration::from_secs(2));
    }

    #[tokio::test]
    async fn ping_fails_when_database_refuses_connections() {
        // Bind then drop a listener so the port is very likely closed.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(&format!(
                "postgres://u:p@127.0.0.1:{port}/db?sslmode=disable"
            ))
            .unwrap();
        let err = PgReadinessProbe::new(pool).ping().await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }

    #[tokio::test]
    async fn ping_times_out_when_server_never_answers() {
        // Accepts TCP connections but never speaks the Postgres protocol.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let holder = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(&format!(
                "postgres://u:p@127.0.0.1:{port}/db?sslmode=disable"
            ))
            .unwrap();
        let probe = PgReadinessProbe {
            pool,
            timeout: Duration::from_millis(200),
        };

        let started = Instant::now();
        let err = probe.ping().await.unwrap_err();
        assert_eq!(err.to_string(), "context deadline exceeded");
        assert!(started.elapsed() < Duration::from_secs(5));
        holder.abort();
    }
}
