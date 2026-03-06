use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use tracing::warn;

use tee_core::SimulatedCvm;
use tee_core::attestation::CvmRuntime;
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
        eprintln!("panic occurred at {location}"); // SAFETY: no plaintext
    }));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let echo_mode = std::env::var("AV_TEE_ECHO_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // CVM no longer depends on signing key — construct it once
    let cvm = Arc::new(SimulatedCvm::new());

    // Resolve signing key: env var override (dev only, blocked in real TEE) or seal/unseal lifecycle
    let signing_key = if cvm.is_real_tee() {
        if std::env::var("AV_SIGNING_KEY_HEX").is_ok() {
            panic!(
                "AV_SIGNING_KEY_HEX must not be set in real TEE mode — use seal/unseal lifecycle"
            );
        }
        let data_dir =
            std::env::var("AV_TEE_DATA_DIR").unwrap_or_else(|_| "/tmp/av-tee".to_string()); // SAFETY: no plaintext
        let sealed_path = std::path::PathBuf::from(data_dir).join("sealed_signing_key");
        tracing::info!("Using seal/unseal key lifecycle (real TEE)"); // SAFETY: no plaintext
        tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
            .await
            .expect("failed to load/generate sealed signing key")
    } else {
        match std::env::var("AV_SIGNING_KEY_HEX") {
            Ok(hex_str) if hex_str != "0".repeat(64) => {
                warn!("Using AV_SIGNING_KEY_HEX override (dev only)"); // SAFETY: no plaintext
                let decoded = hex::decode(&hex_str).expect("AV_SIGNING_KEY_HEX is not valid hex");
                let seed: [u8; 32] = decoded
                    .try_into()
                    .expect("AV_SIGNING_KEY_HEX must be exactly 32 bytes (64 hex chars)");
                ed25519_dalek::SigningKey::from_bytes(&seed)
            }
            _ => {
                let data_dir =
                    std::env::var("AV_TEE_DATA_DIR").unwrap_or_else(|_| "/tmp/av-tee".to_string()); // SAFETY: no plaintext
                let sealed_path = std::path::PathBuf::from(data_dir).join("sealed_signing_key");
                tracing::info!("Using seal/unseal key lifecycle"); // SAFETY: no plaintext
                tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
                    .await
                    .expect("failed to load/generate sealed signing key")
            }
        }
    };
    let signing_pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

    if echo_mode {
        run_echo_mode(cvm, &signing_pubkey_hex).await;
    } else {
        run_relay_mode(cvm, signing_key).await;
    }
}

async fn run_echo_mode(cvm: Arc<SimulatedCvm>, signing_pubkey_hex: &str) {
    use tee_relay::echo::{self, EchoState};

    warn!("ECHO MODE — NOT FOR PRODUCTION. Binds to 127.0.0.1 only."); // SAFETY: no plaintext
    warn!("This relay uses SimulatedCvm with assurance_level: SelfAsserted."); // SAFETY: no plaintext

    let state = Arc::new(EchoState {
        cvm,
        sessions: SessionStore::new(Duration::from_secs(600)),
        receipt_signing_pubkey_hex: signing_pubkey_hex.to_string(),
    });

    let app = Router::new()
        .route("/tee/info", get(echo::tee_info))
        .route("/sessions", post(echo::create_session))
        .route("/sessions/{id}/input", post(echo::submit_input))
        .with_state(state);

    let bind = "127.0.0.1:3100";
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    tracing::info!("tee-relay echo listening on {bind}"); // SAFETY: no plaintext
    axum::serve(listener, app).await.unwrap();
}

async fn run_relay_mode(cvm: Arc<SimulatedCvm>, signing_key: ed25519_dalek::SigningKey) {
    warn!("TEE RELAY MODE — SimulatedCvm (not production-secure)."); // SAFETY: no plaintext
    warn!("Phase 1: attestable receipts but no client-side verification tooling yet."); // SAFETY: no plaintext

    let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok();
    let anthropic_model_id =
        std::env::var("AV_MODEL_ID").unwrap_or_else(|_| "claude-sonnet-4-5-20250929".to_string());
    let anthropic_base_url = std::env::var("ANTHROPIC_BASE_URL").ok();
    let max_completion_tokens: u32 = match std::env::var("AV_MAX_COMPLETION_TOKENS") {
        Ok(v) => v.parse().unwrap_or_else(|e| {
            tracing::warn!("AV_MAX_COMPLETION_TOKENS invalid ({v}: {e}), using default 4096");
            4096
        }),
        Err(_) => 4096,
    };
    let operator_id =
        std::env::var("AV_OPERATOR_ID").unwrap_or_else(|_| "av-tee-relay-dev".to_string());
    let session_ttl: u64 = match std::env::var("AV_SESSION_TTL_SECS") {
        Ok(v) => v.parse().unwrap_or_else(|e| {
            tracing::warn!("AV_SESSION_TTL_SECS invalid ({v}: {e}), using default 600");
            600
        }),
        Err(_) => 600,
    };

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
        sessions,
    });

    let port: u16 = match std::env::var("AV_PORT") {
        Ok(v) => v.parse().unwrap_or_else(|e| {
            tracing::warn!("AV_PORT invalid ({v}: {e}), using default 3100");
            3100
        }),
        Err(_) => 3100,
    };
    let bind = format!("127.0.0.1:{port}");

    let app = Router::new()
        .route("/tee/info", get(handlers::tee_info))
        .route("/sessions", post(handlers::create_session))
        .route("/sessions/{id}/input", post(handlers::submit_input))
        .route("/sessions/{id}/status", get(handlers::session_status))
        .route("/sessions/{id}/output", get(handlers::session_output))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    tracing::info!("tee-relay listening on {bind}"); // SAFETY: no plaintext
    axum::serve(listener, app).await.unwrap();
}
