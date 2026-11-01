use axum::routing::get;
use std::env;
use tokio::net::TcpListener;

const DEFAULT_BIND: &str = "127.0.0.1:7116";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("VAPOR_ARTIFACT_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    let app = vapor_artifact_server::app_router_from_env()
        .await?
        .route("/healthz", get(|| async { "ok\n" }));
    let listener = TcpListener::bind(&bind).await?;
    eprintln!("vapor-artifact-server listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
