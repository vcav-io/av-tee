use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

use tee_core::SimulatedCvm;
use tee_core::crypto::{build_aad, encrypt_payload};
use tee_core::types::ParticipantRole;
use tee_relay::handlers::{self, RelayState};
use tee_relay::relay::AppState;
use tee_relay::session::SessionStore;
use tee_relay::types::*;

/// Start a mock Anthropic API server that returns a fixed JSON response.
async fn start_mock_provider(output_json: &str) -> String {
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn test_contract() -> vault_family_types::Contract {
    vault_family_types::Contract {
        purpose_code: vault_family_types::Purpose::Mediation,
        output_schema_id: "test_output".to_string(),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["PROCEED", "HALT"]
                }
            },
            "required": ["decision"],
            "additionalProperties": false
        }),
        participants: vec!["alice".to_string(), "bob".to_string()],
        prompt_template_hash: "a".repeat(64),
        entropy_budget_bits: None,
        timing_class: None,
        metadata: serde_json::Value::Null,
        model_profile_id: None,
        enforcement_policy_hash: None,
        output_schema_hash: None,
        model_constraints: None,
        max_completion_tokens: None,
        session_ttl_secs: None,
        invite_ttl_secs: None,
        entropy_enforcement: None,
        relay_verifying_key_hex: None,
    }
}

fn test_relay_state(mock_url: &str) -> Arc<RelayState> {
    let cvm = Arc::new(SimulatedCvm::new("bb".repeat(32)));
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32]);

    Arc::new(RelayState {
        app: AppState {
            cvm,
            signing_key,
            anthropic_api_key: Some("test-key".to_string()),
            anthropic_model_id: "claude-sonnet-4-5-20250929".to_string(),
            anthropic_base_url: Some(mock_url.to_string()),
            max_completion_tokens: 4096,
            operator_id: "test-operator".to_string(),
        },
        sessions: SessionStore::new(Duration::from_secs(600)),
    })
}

fn test_router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/tee/info", get(handlers::tee_info))
        .route("/sessions", post(handlers::create_session))
        .route("/sessions/{id}/input", post(handlers::submit_input))
        .route("/sessions/{id}/status", get(handlers::session_status))
        .route("/sessions/{id}/output", get(handlers::session_output))
        .with_state(state)
}

async fn start_relay_server(mock_url: &str) -> String {
    let state = test_relay_state(mock_url);
    let app = test_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn encrypt_input(
    tee_pubkey_bytes: &[u8; 32],
    session_id: &str,
    contract_hash_hex: &str,
    role: ParticipantRole,
    plaintext: &[u8],
) -> SubmitInputRequest {
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let tee_pub = PublicKey::from(*tee_pubkey_bytes);

    let session_uuid = uuid::Uuid::parse_str(session_id).unwrap();
    let session_id_bytes: [u8; 16] = *session_uuid.as_bytes();

    let contract_hash_bytes = hex::decode(contract_hash_hex).unwrap();
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
async fn full_relay_roundtrip_with_receipt() {
    let mock_output = r#"{"decision":"PROCEED"}"#;
    let mock_url = start_mock_provider(mock_output).await;
    let base = start_relay_server(&mock_url).await;
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

    // 2. POST /sessions with contract
    let session: CreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .json(&CreateSessionRequest {
            contract: test_contract(),
        })
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

    // 3. Submit initiator input
    let init_input = serde_json::json!({
        "role": "alice",
        "context": {"preference": "morning"}
    });
    let init_req = encrypt_input(
        &tee_pubkey_bytes,
        &session.session_id,
        &session.contract_hash,
        ParticipantRole::Initiator,
        serde_json::to_vec(&init_input).unwrap().as_slice(),
    );

    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&init_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    // 4. Submit responder input
    let resp_input = serde_json::json!({
        "role": "bob",
        "context": {"preference": "evening"}
    });
    let resp_req = encrypt_input(
        &tee_pubkey_bytes,
        &session.session_id,
        &session.contract_hash,
        ParticipantRole::Responder,
        serde_json::to_vec(&resp_input).unwrap().as_slice(),
    );

    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&resp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202); // processing (async)

    // 5. Poll for completion
    let mut attempts = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status: SessionStatusResponse = client
            .get(format!("{base}/sessions/{}/status", session.session_id))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        if status.state == tee_relay::session::SessionState::Completed {
            break;
        }
        if status.state == tee_relay::session::SessionState::Aborted {
            panic!("session aborted: {:?}", status.abort_signal);
        }
        attempts += 1;
        assert!(attempts < 50, "timed out waiting for completion");
    }

    // 6. GET /sessions/:id/output
    let output: SessionOutputResponse = client
        .get(format!("{base}/sessions/{}/output", session.session_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(output.state, tee_relay::session::SessionState::Completed);
    assert!(output.output.is_some());
    let output_value = output.output.unwrap();
    assert_eq!(output_value["decision"], "PROCEED");

    // 7. Verify receipt
    let receipt = output.receipt_v2.expect("receipt_v2 should be present");

    // execution_lane should be "tee"
    assert_eq!(
        receipt.claims.execution_lane,
        Some(receipt_core::ExecutionLaneV2::Tee)
    );

    // tee_attestation should be populated
    let tee_att = receipt.tee_attestation.as_ref().expect("tee_attestation");
    assert!(tee_att.measurement.is_some());
    assert!(tee_att.attestation_hash.is_some());
    assert!(tee_att.receipt_signing_pubkey_hex.is_some());
    assert!(tee_att.transcript_hash_hex.is_some());
    assert_eq!(tee_att.transcript_hash_hex.as_ref().unwrap().len(), 128);

    // receipt_signing_pubkey_hex should match /tee/info
    assert_eq!(
        tee_att.receipt_signing_pubkey_hex.as_ref().unwrap(),
        &info.receipt_signing_pubkey_hex
    );

    // submission hashes should be present (TEE ingress commitments)
    assert!(receipt.commitments.initiator_submission_hash.is_some());
    assert!(receipt.commitments.responder_submission_hash.is_some());

    // status should be success
    assert_eq!(
        receipt.claims.status,
        Some(receipt_core::SessionStatus::Success)
    );

    // assurance_level should be SelfAsserted (SimulatedCvm)
    assert_eq!(
        receipt.assurance_level,
        receipt_core::AssuranceLevel::SelfAsserted
    );
}

#[tokio::test]
async fn relay_session_status_not_found() {
    let mock_url = start_mock_provider("{}").await;
    let base = start_relay_server(&mock_url).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sessions/nonexistent/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn relay_duplicate_submission_rejected() {
    let mock_url = start_mock_provider("{}").await;
    let base = start_relay_server(&mock_url).await;
    let client = reqwest::Client::new();

    let session: CreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .json(&CreateSessionRequest {
            contract: test_contract(),
        })
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

    let input = serde_json::json!({"role": "alice", "context": {}});
    let req1 = encrypt_input(
        &tee_pubkey_bytes,
        &session.session_id,
        &session.contract_hash,
        ParticipantRole::Initiator,
        serde_json::to_vec(&input).unwrap().as_slice(),
    );

    // First submission
    let resp = client
        .post(format!("{base}/sessions/{}/input", session.session_id))
        .json(&req1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    // Duplicate
    let req2 = encrypt_input(
        &tee_pubkey_bytes,
        &session.session_id,
        &session.contract_hash,
        ParticipantRole::Initiator,
        serde_json::to_vec(&input).unwrap().as_slice(),
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
async fn relay_contract_hash_bound_into_session() {
    let mock_url = start_mock_provider("{}").await;
    let base = start_relay_server(&mock_url).await;
    let client = reqwest::Client::new();

    let session: CreateSessionResponse = client
        .post(format!("{base}/sessions"))
        .json(&CreateSessionRequest {
            contract: test_contract(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // contract_hash should be a 64-char hex string
    assert_eq!(session.contract_hash.len(), 64);
    assert!(session.contract_hash.chars().all(|c| c.is_ascii_hexdigit()));
}
