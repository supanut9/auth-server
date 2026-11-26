//! Local/container entry (Go `cmd/server`): loads `.env` without overriding
//! the environment, fails fast on bad config and listens on `HTTP_ADDR`.

use std::{net::SocketAddr, process::ExitCode};

use auth_adapters::config::Config;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let _ = dotenvy::dotenv();
    let config = match Config::from_process_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("load config: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Go accepts ":8050" (all interfaces); TcpListener needs a host.
    let addr = if config.http_addr.starts_with(':') {
        format!("0.0.0.0{}", config.http_addr)
    } else {
        config.http_addr.clone()
    };
    let router = match auth_http::bootstrap::build_router(config) {
        Ok(router) => router,
        Err(error) => {
            eprintln!("build router: {error}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("listen on {addr}: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("auth-server listening on {addr}");
    // ConnectInfo gives the client-IP middleware the peer address (gin ClientIP).
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    match axum::serve(listener, service).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("serve: {error}");
            ExitCode::FAILURE
        }
    }
}
