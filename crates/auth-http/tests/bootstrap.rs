mod common;

use std::time::{Duration, Instant};

use auth_http::bootstrap::build_state;
use tokio::{net::TcpListener, time::timeout};

#[tokio::test]
async fn startup_warms_the_pool_without_waiting_for_postgres() {
    // The listener accepts TCP connections but never replies to PostgreSQL startup.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let database_url = format!(
        "postgres://postgres@{}/unused?sslmode=disable",
        listener.local_addr().unwrap()
    );
    let config = common::config_with(&[
        ("DATABASE_URL", &database_url),
        (
            "JWT_PRIVATE_KEY_PEM",
            include_str!("../../../testdata/golden/keys/test-only-rsa-2048-private-pkcs8.pem"),
        ),
        (
            "JWT_PUBLIC_KEY_PEM",
            include_str!("../../../testdata/golden/keys/test-only-rsa-2048-public-pkix.pem"),
        ),
    ]);

    let started = Instant::now();
    let _state =
        build_state(config).expect("startup must succeed while PostgreSQL is unresponsive");
    assert!(started.elapsed() < Duration::from_secs(2));

    timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("warm-up must start a connection in the background")
        .unwrap();
}
