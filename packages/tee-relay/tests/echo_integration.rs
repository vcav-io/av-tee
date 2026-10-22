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
    let cvm = Arc::new(SimulatedCvm::new());
    let state = Arc::new(EchoState {
        cvm,
        sessions: SessionStore::new(Duration::from_secs(600)),
        receipt_signing_pubkey_hex: "aa".repeat(32),
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
    let init_plaintext = &echo_plaintext(
        "initiator",
        serde_json::json!({"data": "initiator secret data"}),
        Some(INIT_NONCE),
    );
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
    let resp_plaintext = &echo_plaintext(
        "responder",
        serde_json::json!({"data": "responder secret data"}),
        Some(RESP_NONCE),
    );
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

    // 5. Verify echo response contains salted commitments, not plaintext
    let nonce = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
    assert_eq!(
        echo.initiator_input_commitment,
        receipt_core::compute_input_commitment_v3(
            &nonce(INIT_NONCE),
            &serde_json::json!({"data": "initiator secret data"})
        )
        .unwrap()
    );
    assert_eq!(
        echo.responder_input_commitment,
        receipt_core::compute_input_commitment_v3(
            &nonce(RESP_NONCE),
            &serde_json::json!({"data": "responder secret data"})
        )
        .unwrap()
    );

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
        &echo_plaintext("initiator", serde_json::json!({}), Some(INIT_NONCE)),
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
        &echo_plaintext("initiator", serde_json::json!({"n": 2}), Some(INIT_NONCE)),
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

const INIT_NONCE: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
const RESP_NONCE: &str = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e";

fn echo_plaintext(role: &str, context: serde_json::Value, nonce: Option<&str>) -> Vec<u8> {
    let mut v = serde_json::json!({"role": role, "context": context});
    if let Some(n) = nonce {
        v["commitment_nonce"] = serde_json::json!(n);
    }
    serde_json::to_vec(&v).unwrap()
}

async fn echo_session(
    client: &reqwest::Client,
    base: &str,
) -> (EchoCreateSessionResponse, [u8; 32]) {
    let session: EchoCreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tee_pubkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&session.tee_session_pubkey)
        .unwrap()
        .try_into()
        .unwrap();
    (session, tee_pubkey_bytes)
}

#[tokio::test]
async fn echo_returns_salted_input_commitments_only() {
    let base = start_server().await;
    let client = reqwest::Client::new();
    let (session, tee_pub) = echo_session(&client, &base).await;

    let init_ctx = serde_json::json!({"offer": 10});
    let resp_ctx = serde_json::json!({"offer": 12});
    let init_pt = echo_plaintext("initiator", init_ctx.clone(), Some(INIT_NONCE));
    let resp_pt = echo_plaintext("responder", resp_ctx.clone(), Some(RESP_NONCE));

    let req = submit_encrypted_input(
        &tee_pub,
        &session.session_id,
        ParticipantRole::Initiator,
        &init_pt,
    );
    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let req = submit_encrypted_input(
        &tee_pub,
        &session.session_id,
        ParticipantRole::Responder,
        &resp_pt,
    );
    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let echo: serde_json::Value = serde_json::from_str(&body).unwrap();

    let nonce = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
    assert_eq!(
        echo["initiator_input_commitment"],
        receipt_core::compute_input_commitment_v3(&nonce(INIT_NONCE), &init_ctx).unwrap()
    );
    assert_eq!(
        echo["responder_input_commitment"],
        receipt_core::compute_input_commitment_v3(&nonce(RESP_NONCE), &resp_ctx).unwrap()
    );

    // No unsalted hash of either plaintext (or its context) is returned.
    for unsalted in [
        hex::encode(Sha256::digest(&init_pt)),
        hex::encode(Sha256::digest(&resp_pt)),
        hex::encode(Sha256::digest(
            receipt_core::canonicalize_v3(&init_ctx).unwrap(),
        )),
        hex::encode(Sha256::digest(
            receipt_core::canonicalize_v3(&resp_ctx).unwrap(),
        )),
    ] {
        assert!(
            !body.contains(&unsalted),
            "unsalted input hash in echo response"
        );
    }
    assert!(echo.get("initiator_decrypted_sha256_hex").is_none());
    assert!(echo.get("responder_decrypted_sha256_hex").is_none());
    assert!(!body.contains(INIT_NONCE) && !body.contains(RESP_NONCE));
}

#[tokio::test]
async fn echo_submission_without_commitment_nonce_is_rejected() {
    let base = start_server().await;
    let client = reqwest::Client::new();
    let (session, tee_pub) = echo_session(&client, &base).await;

    for plaintext in [
        echo_plaintext("initiator", serde_json::json!({}), None),
        echo_plaintext("initiator", serde_json::json!({}), Some("ABCD")),
        b"not json".to_vec(),
    ] {
        let req = submit_encrypted_input(
            &tee_pub,
            &session.session_id,
            ParticipantRole::Initiator,
            &plaintext,
        );
        let resp = client
            .post(format!("{base}/sessions/{}/input", session.session_id))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }
}
