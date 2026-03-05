use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tracing::warn;

use tee_core::SimulatedCvm;
use tee_relay::echo::{self, EchoState};
use tee_relay::session::SessionStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Phase 1 only supports echo mode with SimulatedCvm.
    // Production TEE mode (SevSnpCvm) will be added in a later phase.
    let signing_pubkey_hex = std::env::var("AV_SIGNING_KEY_HEX").unwrap_or_else(|_| "0".repeat(64));

    let cvm = Arc::new(SimulatedCvm::new(signing_pubkey_hex));

    warn!("ECHO MODE — NOT FOR PRODUCTION. Binds to 127.0.0.1 only.");
    warn!("This relay uses SimulatedCvm with assurance_level: SelfAsserted.");

    let state = Arc::new(EchoState {
        cvm,
        sessions: SessionStore::new(),
    });

    let app = Router::new()
        .route("/tee/info", get(echo::tee_info))
        .route("/sessions", post(echo::create_session))
        .route("/sessions/{id}/input", post(echo::submit_input))
        .with_state(state);

    let bind = "127.0.0.1:3100";
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    tracing::info!("tee-relay echo listening on {bind}");
    axum::serve(listener, app).await.unwrap();
}
