//! Vercel function entry. `vercel.json` rewrites every path here; the
//! router is built once per instance and a boot error is served as a 500.

use auth_http::middleware::client_ip::VercelEdge;
use axum::Extension;
use tower::ServiceBuilder;
use vercel_runtime::axum::VercelLayer;

#[tokio::main]
async fn main() -> Result<(), vercel_runtime::Error> {
    let router = auth_http::bootstrap::serving_router(auth_http::bootstrap::router_from_env())
        .layer(Extension(VercelEdge));
    let service = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(router);
    vercel_runtime::run(service).await
}
