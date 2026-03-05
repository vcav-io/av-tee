use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use tracing::warn;

use tee_core::SimulatedCvm;
use tee_relay::handlers::{self, RelayState};
use tee_relay::relay::AppState;
use tee_relay::session::{SessionStore, start_session_reaper};

#[tokio::main]
async fn main() {
    // Install panic hook that suppresses payload values (plaintext defense-in-depth).
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        eprintln!("panic occurred at {location}");
    }));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let echo_mode = std::env::var("AV_TEE_ECHO_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let signing_pubkey_hex = std::env::var("AV_SIGNING_KEY_HEX").unwrap_or_else(|_| "0".repeat(64));
    let cvm = Arc::new(SimulatedCvm::new(signing_pubkey_hex.clone()));

    if echo_mode {
        run_echo_mode(cvm).await;
    } else {
        run_relay_mode(cvm, signing_pubkey_hex).await;
    }
}

async fn run_echo_mode(cvm: Arc<SimulatedCvm>) {
    use tee_relay::echo::{self, EchoState};

    warn!("ECHO MODE — NOT FOR PRODUCTION. Binds to 127.0.0.1 only.");
    warn!("This relay uses SimulatedCvm with assurance_level: SelfAsserted.");

    let state = Arc::new(EchoState {
        cvm,
        sessions: SessionStore::new(Duration::from_secs(600)),
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

async fn run_relay_mode(cvm: Arc<SimulatedCvm>, signing_pubkey_hex: String) {
    warn!("TEE RELAY MODE — SimulatedCvm (not production-secure).");
    warn!("Phase 1: attestable receipts but no client-side verification tooling yet.");

    // Derive signing key from the hex seed
    let seed_bytes: [u8; 32] = {
        let decoded = hex::decode(&signing_pubkey_hex).unwrap_or_else(|_| vec![0u8; 32]);
        let mut buf = [0u8; 32];
        let len = decoded.len().min(32);
        buf[..len].copy_from_slice(&decoded[..len]);
        buf
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);

    let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok();
    let anthropic_model_id =
        std::env::var("AV_MODEL_ID").unwrap_or_else(|_| "claude-sonnet-4-5-20250929".to_string());
    let anthropic_base_url = std::env::var("ANTHROPIC_BASE_URL").ok();
    let max_completion_tokens: u32 = std::env::var("AV_MAX_COMPLETION_TOKENS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);
    let operator_id =
        std::env::var("AV_OPERATOR_ID").unwrap_or_else(|_| "av-tee-relay-dev".to_string());
    let session_ttl: u64 = std::env::var("AV_SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);

    let sessions = Arc::new(SessionStore::new(Duration::from_secs(session_ttl)));
    start_session_reaper(sessions.clone());

    let app_state = AppState {
        cvm,
        signing_key,
        anthropic_api_key,
        anthropic_model_id,
        anthropic_base_url,
        max_completion_tokens,
        operator_id,
    };

    let state = Arc::new(RelayState {
        app: app_state,
        sessions: SessionStore::new(Duration::from_secs(session_ttl)),
    });

    let port: u16 = std::env::var("AV_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3100);
    let bind = format!("127.0.0.1:{port}");

    let app = Router::new()
        .route("/tee/info", get(handlers::tee_info))
        .route("/sessions", post(handlers::create_session))
        .route("/sessions/{id}/input", post(handlers::submit_input))
        .route("/sessions/{id}/status", get(handlers::session_status))
        .route("/sessions/{id}/output", get(handlers::session_output))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    tracing::info!("tee-relay listening on {bind}");
    axum::serve(listener, app).await.unwrap();
}
