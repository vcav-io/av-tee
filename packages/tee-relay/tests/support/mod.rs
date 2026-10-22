//! Shared helpers for the receipt v3 integration tests.
//!
//! Requests and responses are handled as raw JSON so the tests describe the
//! wire format rather than the relay's Rust types.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use base64::Engine;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use tee_core::SimulatedCvm;
use tee_core::crypto::{build_aad, encrypt_payload};
use tee_core::types::ParticipantRole;
use tee_relay::handlers::{self, RelayState};
use tee_relay::relay::AppState;
use tee_relay::session::SessionStore;

pub const SIGNING_SEED: [u8; 32] = [0xBB; 32];

pub fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED)
}

pub const ALICE_NONCE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
pub const BOB_NONCE: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

/// A minimal contract as a client sends it (absent optionals omitted).
pub fn contract_json() -> serde_json::Value {
    serde_json::json!({
        "purpose_code": "MEDIATION",
        "output_schema_id": "test_output",
        "output_schema": {
            "type": "object",
            "properties": {
                "decision": {"type": "string", "enum": ["PROCEED", "HALT"]}
            },
            "required": ["decision"],
            "additionalProperties": false
        },
        "participants": ["alice", "bob"],
        "prompt_template_hash": tee_relay::relay::INLINE_PROMPT_TEMPLATE_HASH,
    })
}

/// Start a mock Anthropic API server that returns a fixed JSON response.
pub async fn start_mock_provider(output_json: &str) -> String {
    let output = output_json.to_string();
    let app = Router::new().route(
        "/v1/messages",
        post(move || {
            let output = output.clone();
            async move {
                axum::Json(serde_json::json!({
                    "content": [{"type": "text", "text": output}],
                    "model": "claude-sonnet-4-5-20250929",
                    "stop_reason": "end_turn"
                }))
            }
        }),
    );
    serve(app).await
}

/// Start a mock Anthropic API server that returns an HTTP 500.
pub async fn start_failing_mock_provider() -> String {
    let app = Router::new().route(
        "/v1/messages",
        post(|| async {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": "mock error"})),
            )
        }),
    );
    serve(app).await
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

pub async fn start_relay_server(mock_url: &str) -> String {
    let state = Arc::new(RelayState {
        app: AppState {
            cvm: Arc::new(SimulatedCvm::new()),
            signing_key: signing_key(),
            anthropic_api_key: Some("test-key".to_string()),
            anthropic_model_id: "claude-sonnet-4-5-20250929".to_string(),
            anthropic_base_url: Some(mock_url.to_string()),
            max_completion_tokens: 4096,
            operator_id: "test-operator".to_string(),
        },
        sessions: Arc::new(SessionStore::new(Duration::from_secs(600))),
    });
    let app = Router::new()
        .route("/tee/info", get(handlers::tee_info))
        .route("/sessions", post(handlers::create_session))
        .route("/sessions/{id}/input", post(handlers::submit_input))
        .route("/sessions/{id}/status", get(handlers::session_status))
        .route("/sessions/{id}/output", get(handlers::session_output))
        .with_state(state);
    serve(app).await
}

/// POST /sessions with a raw contract. Returns (status, body).
pub async fn create_session_raw(
    client: &reqwest::Client,
    base: &str,
    contract: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = client
        .post(format!("{base}/sessions"))
        .json(&serde_json::json!({ "contract": contract }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

pub async fn create_session(
    client: &reqwest::Client,
    base: &str,
    contract: serde_json::Value,
) -> serde_json::Value {
    let (status, body) = create_session_raw(client, base, contract).await;
    assert_eq!(status, 200, "session creation failed");
    body
}

/// Encrypt `plaintext` for `role` and POST it. Returns (status, body text).
pub async fn submit_plaintext(
    client: &reqwest::Client,
    base: &str,
    session: &serde_json::Value,
    role: ParticipantRole,
    plaintext: &[u8],
) -> (u16, String) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let session_id = session["session_id"].as_str().unwrap();
    let tee_pub: [u8; 32] = b64
        .decode(session["tee_session_pubkey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let session_id_bytes: [u8; 16] = *uuid::Uuid::parse_str(session_id).unwrap().as_bytes();
    let contract_hash_bytes = hex::decode(session["contract_hash"].as_str().unwrap()).unwrap();
    let aad = build_aad(&session_id_bytes, &contract_hash_bytes, role);
    let aead_nonce = [0u8; 12];
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let (ciphertext, client_pub) = encrypt_payload(
        &client_secret,
        &PublicKey::from(tee_pub),
        plaintext,
        &session_id_bytes,
        &aad,
        &aead_nonce,
    )
    .unwrap();

    let (role_label, token_field) = match role {
        ParticipantRole::Initiator => ("initiator", "initiator_submit_token"),
        ParticipantRole::Responder => ("responder", "responder_submit_token"),
    };
    let resp = client
        .post(format!("{base}/sessions/{session_id}/input"))
        .bearer_auth(session[token_field].as_str().unwrap())
        .json(&serde_json::json!({
            "role": role_label,
            "client_ephemeral_pubkey": b64.encode(client_pub),
            "nonce": b64.encode(aead_nonce),
            "ciphertext": b64.encode(&ciphertext),
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

/// Submit a participant input (`role`, `context`, `commitment_nonce`).
pub async fn submit_input(
    client: &reqwest::Client,
    base: &str,
    session: &serde_json::Value,
    role: ParticipantRole,
    label: &str,
    context: &serde_json::Value,
    commitment_nonce: &str,
) -> (u16, String) {
    let plaintext = serde_json::json!({
        "role": label,
        "context": context,
        "commitment_nonce": commitment_nonce,
    });
    submit_plaintext(
        client,
        base,
        session,
        role,
        &serde_json::to_vec(&plaintext).unwrap(),
    )
    .await
}

/// Poll until the session is terminal and return the raw output body.
pub async fn poll_output(
    client: &reqwest::Client,
    base: &str,
    session: &serde_json::Value,
) -> String {
    let session_id = session["session_id"].as_str().unwrap();
    let read_token = session["read_token"].as_str().unwrap();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status: serde_json::Value = client
            .get(format!("{base}/sessions/{session_id}/status"))
            .bearer_auth(read_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if status["state"] == "COMPLETED" || status["state"] == "ABORTED" {
            return client
                .get(format!("{base}/sessions/{session_id}/output"))
                .bearer_auth(read_token)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
        }
    }
    panic!("timed out waiting for session to finish");
}

/// Run a full two-party session and return the raw output body.
pub async fn run_session(
    client: &reqwest::Client,
    base: &str,
    session: &serde_json::Value,
    alice_context: &serde_json::Value,
    bob_context: &serde_json::Value,
) -> String {
    let (status, _) = submit_input(
        client,
        base,
        session,
        ParticipantRole::Initiator,
        "alice",
        alice_context,
        ALICE_NONCE,
    )
    .await;
    assert_eq!(status, 202);
    let (status, _) = submit_input(
        client,
        base,
        session,
        ParticipantRole::Responder,
        "bob",
        bob_context,
        BOB_NONCE,
    )
    .await;
    assert_eq!(status, 202);
    poll_output(client, base, session).await
}

/// The unsalted v1-style input hash: SHA-256 of the legacy canonical JSON.
pub fn unsalted_input_hash(context: &serde_json::Value) -> String {
    let canonical = receipt_core::canonicalize_serializable(context).unwrap();
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

pub fn nonce_bytes(hex_nonce: &str) -> [u8; 32] {
    hex::decode(hex_nonce).unwrap().try_into().unwrap()
}
