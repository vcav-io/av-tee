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
use tee_relay::echo::{self, EchoCreateSessionResponse, EchoState};
use tee_relay::session::SessionStore;
use tee_relay::types::*;

fn test_app() -> Router {
    let cvm = Arc::new(SimulatedCvm::new("aa".repeat(32)));
    let state = Arc::new(EchoState {
        cvm,
        sessions: SessionStore::new(Duration::from_secs(600)),
    });
    Router::new()
        .route("/tee/info", get(echo::tee_info))
        .route("/sessions", post(echo::create_session))
        .route("/sessions/{id}/input", post(echo::submit_input))
        .with_state(state)
}

async fn start_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = test_app();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn submit_encrypted_input(
    tee_pubkey_bytes: &[u8; 32],
    session_id: &str,
    role: ParticipantRole,
    plaintext: &[u8],
) -> SubmitInputRequest {
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let tee_pub = PublicKey::from(*tee_pubkey_bytes);

    let session_uuid = uuid::Uuid::parse_str(session_id).unwrap();
    let session_id_bytes: [u8; 16] = *session_uuid.as_bytes();

    // Echo mode uses dummy contract hash
    let contract_hash_bytes = vec![0u8; 32];
    let aad = build_aad(&session_id_bytes, &contract_hash_bytes, role);
    let nonce = [0u8; 12];

    let (ciphertext, client_pub_bytes) = encrypt_payload(
        &client_secret,
        &tee_pub,
        plaintext,
        &session_id_bytes,
        &aad,
        &nonce,
    )
    .unwrap();

    let b64 = base64::engine::general_purpose::STANDARD;
    SubmitInputRequest {
        role: match role {
            ParticipantRole::Initiator => "initiator".to_string(),
            ParticipantRole::Responder => "responder".to_string(),
        },
        client_ephemeral_pubkey: b64.encode(client_pub_bytes),
        nonce: b64.encode(nonce),
        ciphertext: b64.encode(&ciphertext),
    }
}

#[tokio::test]
async fn full_echo_roundtrip() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    // 1. GET /tee/info
    let info: TeeInfoResponse = client
        .get(format!("{base}/tee/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.tee_type, "Simulated");
    assert!(!info.measurement.is_empty());

    // 2. POST /sessions
    let session: EchoCreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let tee_pubkey_bytes: [u8; 32] = b64
        .decode(&session.tee_session_pubkey)
        .unwrap()
        .try_into()
        .unwrap();

    // 3. Submit initiator input (encrypted)
    let init_plaintext = b"initiator secret data";
    let init_req = submit_encrypted_input(
        &tee_pubkey_bytes,
        &session.session_id,
        ParticipantRole::Initiator,
        init_plaintext,
    );

    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&init_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    // 4. Submit responder input (encrypted)
    let resp_plaintext = b"responder secret data";
    let resp_req = submit_encrypted_input(
        &tee_pubkey_bytes,
        &session.session_id,
        ParticipantRole::Responder,
        resp_plaintext,
    );

    let echo_resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&resp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(echo_resp.status(), 200);

    let echo: EchoResponse = echo_resp.json().await.unwrap();

    // 5. Verify echo response contains hashes, not plaintext
    let expected_init_hash = hex::encode(Sha256::digest(init_plaintext));
    let expected_resp_hash = hex::encode(Sha256::digest(resp_plaintext));
    assert_eq!(echo.initiator_decrypted_sha256_hex, expected_init_hash);
    assert_eq!(echo.responder_decrypted_sha256_hex, expected_resp_hash);

    // 6. Verify TEE attestation fields
    assert_eq!(echo.tee_attestation.tee_type, "Simulated");
    assert_eq!(echo.tee_attestation.measurement, info.measurement);
    assert!(!echo.tee_attestation.attestation_hash.is_empty());
    assert!(!echo.tee_attestation.transcript_hash_hex.is_empty());
    assert_eq!(echo.tee_attestation.transcript_hash_hex.len(), 128);
}

#[tokio::test]
async fn duplicate_submission_returns_422() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    let session: EchoCreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let tee_pubkey_bytes: [u8; 32] = b64
        .decode(&session.tee_session_pubkey)
        .unwrap()
        .try_into()
        .unwrap();

    let req = submit_encrypted_input(
        &tee_pubkey_bytes,
        &session.session_id,
        ParticipantRole::Initiator,
        b"first",
    );

    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    let req2 = submit_encrypted_input(
        &tee_pubkey_bytes,
        &session.session_id,
        ParticipantRole::Initiator,
        b"second attempt",
    );
    let resp2 = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&req2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 422);
}

#[tokio::test]
async fn each_session_gets_unique_keypair() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    let s1: EchoCreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let s2: EchoCreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_ne!(s1.tee_session_pubkey, s2.tee_session_pubkey);
    assert_ne!(s1.session_id, s2.session_id);
}
