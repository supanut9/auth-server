use std::{env, io};

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr = match env::var("HTTP_ADDR") {
        Ok(addr) => addr,
        Err(env::VarError::NotPresent) => "127.0.0.1:8051".to_owned(),
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    };
    let listener = TcpListener::bind(addr).await?;
    eprintln!("Listening on {}", listener.local_addr()?);

    axum::serve(listener, auth_http::router()).await
}
