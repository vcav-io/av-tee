use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use tracing::warn;

use tee_core::attestation::CvmRuntime;
use tee_relay::handlers::{self, RelayState};
use tee_relay::relay::AppState;
use tee_relay::session::{SessionStore, start_session_reaper};

/// Exit with a startup error. The message never contains secrets.
fn exit_startup(message: &str) -> ! {
    tracing::error!("{message}"); // SAFETY: no plaintext
    std::process::exit(1);
}

/// Open the CVM runtime: SEV-SNP when built with `snp` and the device works;
/// the simulated runtime only with `SELKEY_ALLOW_SIMULATED=1`.
fn build_cvm_runtime() -> Result<Arc<dyn CvmRuntime>, String> {
    use tee_relay::startup::{HardwareRuntime, RuntimeChoice, choose_runtime};

    #[cfg(feature = "snp")]
    let (hardware, snp_cvm) = match tee_snp::SevSnpCvm::new() {
        Ok(cvm) => (HardwareRuntime::Available, Some(cvm)),
        Err(e) => (HardwareRuntime::Failed(e.to_string()), None),
    };
    #[cfg(not(feature = "snp"))]
    let hardware = HardwareRuntime::NotBuilt;

    if let HardwareRuntime::Failed(reason) = &hardware {
        tracing::error!("SEV-SNP initialisation failed: {reason}"); // SAFETY: no plaintext
    }
    let allow_simulated = tee_relay::startup::allow_simulated(
        std::env::var(tee_relay::startup::ALLOW_SIMULATED_ENV)
            .ok()
            .as_deref(),
    );
    match choose_runtime(hardware, allow_simulated)? {
        #[cfg(feature = "snp")]
        RuntimeChoice::SevSnp => {
            tracing::info!("SEV-SNP CVM runtime initialized"); // SAFETY: no plaintext
            let cvm = snp_cvm.ok_or("SEV-SNP runtime missing after initialisation")?;
            Ok(Arc::new(cvm))
        }
        #[cfg(not(feature = "snp"))]
        RuntimeChoice::SevSnp => Err("SEV-SNP runtime selected in a build without it".into()),
        RuntimeChoice::Simulated => {
            warn!(
                "Using the SIMULATED CVM runtime ({}=1): no hardware isolation, receipts are SELF_ASSERTED", // SAFETY: no plaintext
                tee_relay::startup::ALLOW_SIMULATED_ENV
            );
            Ok(Arc::new(tee_core::SimulatedCvm::new()))
        }
    }
}

/// Resolve the listen socket address from SELKEY_BIND_ADDR and SELKEY_PORT.
fn bind_socket_addr() -> std::net::SocketAddr {
    let ip =
        tee_relay::startup::resolve_bind_addr(std::env::var("SELKEY_BIND_ADDR").ok().as_deref())
            .unwrap_or_else(|e| exit_startup(&format!("{e}; refusing to start")));
    let port: u16 = match std::env::var("SELKEY_PORT") {
        Ok(v) => v.parse().unwrap_or_else(|e| {
            tracing::warn!("SELKEY_PORT invalid ({v}: {e}), using default 3100");
            3100
        }),
        Err(_) => 3100,
    };
    std::net::SocketAddr::new(ip, port)
}

/// Load or generate the sealed receipt signing key.
async fn load_sealed_signing_key(cvm: &dyn CvmRuntime) -> ed25519_dalek::SigningKey {
    use tee_relay::key_lifecycle::{KeySource, UnsealFailurePolicy, load_signing_key};

    let data_dir =
        std::env::var("SELKEY_TEE_DATA_DIR").unwrap_or_else(|_| "/tmp/selkey-tee".to_string()); // SAFETY: no plaintext
    let sealed_path = std::path::PathBuf::from(data_dir).join("sealed_signing_key");
    let policy =
        UnsealFailurePolicy::from_env_value(std::env::var("SELKEY_SEAL_STRICT").ok().as_deref());
    let loaded = load_signing_key(cvm, &sealed_path, policy)
        .await
        .unwrap_or_else(|e| exit_startup(&format!("failed to load the sealed signing key: {e}")));
    let pubkey_hex = hex::encode(loaded.signing_key.verifying_key().as_bytes());
    match &loaded.source {
        KeySource::Generated => {
            tracing::info!(receipt_signing_pubkey_hex = %pubkey_hex, "generated and sealed a new receipt signing key"); // SAFETY: no plaintext
        }
        KeySource::Unsealed => {
            tracing::info!(receipt_signing_pubkey_hex = %pubkey_hex, "unsealed the receipt signing key"); // SAFETY: no plaintext
        }
        KeySource::Regenerated { rejected_blob } => {
            tracing::error!(
                rejected_blob = %rejected_blob.display(),
                receipt_signing_pubkey_hex = %pubkey_hex,
                "the sealed signing key could not be unsealed by this CVM; it was moved aside and a NEW receipt signing key was generated. Clients pinning the previous key must re-pin" // SAFETY: no plaintext
            );
        }
    }
    loaded.signing_key
}

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

    let echo_mode = std::env::var("SELKEY_TEE_ECHO_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // CVM no longer depends on signing key — construct it once
    let cvm = build_cvm_runtime().unwrap_or_else(|e| exit_startup(&e));

    // Resolve signing key: env var override (dev only, blocked in real TEE) or seal/unseal lifecycle
    let signing_key = if cvm.is_real_tee() {
        if std::env::var("SELKEY_SIGNING_KEY_HEX").is_ok() {
            exit_startup(
                "SELKEY_SIGNING_KEY_HEX must not be set in real TEE mode — use seal/unseal lifecycle",
            );
        }
        tracing::info!("Using seal/unseal key lifecycle (real TEE)"); // SAFETY: no plaintext
        load_sealed_signing_key(cvm.as_ref()).await
    } else {
        match std::env::var("SELKEY_SIGNING_KEY_HEX") {
            Ok(hex_str) if hex_str != "0".repeat(64) => {
                warn!("Using SELKEY_SIGNING_KEY_HEX override (dev only)"); // SAFETY: no plaintext
                let decoded =
                    hex::decode(&hex_str).expect("SELKEY_SIGNING_KEY_HEX is not valid hex");
                let seed: [u8; 32] = decoded
                    .try_into()
                    .expect("SELKEY_SIGNING_KEY_HEX must be exactly 32 bytes (64 hex chars)");
                ed25519_dalek::SigningKey::from_bytes(&seed)
            }
            _ => {
                tracing::info!("Using seal/unseal key lifecycle"); // SAFETY: no plaintext
                load_sealed_signing_key(cvm.as_ref()).await
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

async fn run_echo_mode(cvm: Arc<dyn CvmRuntime>, signing_pubkey_hex: &str) {
    use tee_relay::echo::{self, EchoState};

    warn!("ECHO MODE — NOT FOR PRODUCTION."); // SAFETY: no plaintext

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

    let bind = bind_socket_addr();
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .unwrap_or_else(|e| exit_startup(&format!("failed to bind {bind}: {e}")));
    tracing::info!("tee-relay echo listening on {bind}"); // SAFETY: no plaintext
    axum::serve(listener, app).await.unwrap();
}

async fn run_relay_mode(cvm: Arc<dyn CvmRuntime>, signing_key: ed25519_dalek::SigningKey) {
    if !cvm.is_real_tee() {
        warn!("TEE RELAY MODE — SimulatedCvm (not production-secure)."); // SAFETY: no plaintext
    }
    warn!(
        "Prototype: attestable receipts; clients must verify attestation before relying on them."
    ); // SAFETY: no plaintext

    let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok();
    if anthropic_api_key.is_none() {
        tracing::error!("ANTHROPIC_API_KEY is required in relay mode");
        std::process::exit(1);
    }
    let anthropic_model_id = std::env::var("SELKEY_MODEL_ID")
        .unwrap_or_else(|_| "claude-sonnet-4-5-20250929".to_string());
    let anthropic_base_url = std::env::var("ANTHROPIC_BASE_URL").ok();
    if let Some(url) = anthropic_base_url.as_deref()
        && let Err(e) = tee_relay::provider::anthropic::validate_base_url(url)
    {
        // The message names the problem, never the URL.
        tracing::error!("{e}; refusing to start"); // SAFETY: no plaintext
        std::process::exit(1);
    }
    let max_completion_tokens: u32 = match std::env::var("SELKEY_MAX_COMPLETION_TOKENS") {
        Ok(v) => v.parse().unwrap_or_else(|e| {
            tracing::warn!("SELKEY_MAX_COMPLETION_TOKENS invalid ({v}: {e}), using default 4096");
            4096
        }),
        Err(_) => 4096,
    };
    let operator_id =
        std::env::var("SELKEY_OPERATOR_ID").unwrap_or_else(|_| "selkey-tee-relay-dev".to_string());
    let session_ttl: u64 = match std::env::var("SELKEY_SESSION_TTL_SECS") {
        Ok(v) => v.parse().unwrap_or_else(|e| {
            tracing::warn!("SELKEY_SESSION_TTL_SECS invalid ({v}: {e}), using default 600");
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
        env: std::env::var("SELKEY_ENV").unwrap_or_default(),
    };

    let state = Arc::new(RelayState {
        app: app_state,
        sessions,
    });

    let bind = bind_socket_addr();

    let app = Router::new()
        .route("/tee/info", get(handlers::tee_info))
        .route("/sessions", post(handlers::create_session))
        .route("/sessions/{id}/input", post(handlers::submit_input))
        .route("/sessions/{id}/status", get(handlers::session_status))
        .route("/sessions/{id}/output", get(handlers::session_output))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .unwrap_or_else(|e| exit_startup(&format!("failed to bind {bind}: {e}")));
    tracing::info!("tee-relay listening on {bind}"); // SAFETY: no plaintext
    axum::serve(listener, app).await.unwrap();
}
