use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tee_core::attestation::CvmRuntime;
use tee_core::crypto::{build_aad, decrypt_payload};
use tee_core::types::ParticipantRole;
use tee_transcript::{TranscriptInputs, compute_transcript_hash};

use crate::session::{Session, SessionStore};
use crate::types::*;

/// Shared application state for echo mode.
pub struct EchoState {
    pub cvm: Arc<dyn CvmRuntime>,
    pub sessions: SessionStore,
    /// Receipt signing pubkey hex — passed from main, not from CVM identity.
    pub receipt_signing_pubkey_hex: String,
}

/// Echo-mode CreateSessionResponse (no contract_hash).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EchoCreateSessionResponse {
    pub session_id: String,
    pub tee_session_pubkey: String,
}

/// GET /tee/info — return enclave identity + signing pubkey.
pub async fn tee_info(State(state): State<Arc<EchoState>>) -> Json<TeeInfoResponse> {
    Json(TeeInfoResponse::from_identity_and_pubkey(
        state.cvm.identity(),
        &state.receipt_signing_pubkey_hex,
    ))
}

/// POST /sessions — create a new echo session with per-session ECDH keypair.
pub async fn create_session(
    State(state): State<Arc<EchoState>>,
) -> Result<Json<EchoCreateSessionResponse>, StatusCode> {
    let (pubkey, secret) = state
        .cvm
        .derive_session_keypair()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session_uuid = Uuid::new_v4();
    let session_id = session_uuid.to_string();
    let session_id_bytes: [u8; 16] = *session_uuid.as_bytes();

    // Echo mode uses a dummy contract hash and contract
    let contract_hash_bytes = vec![0u8; 32];
    let dummy_contract = vault_family_types::Contract {
        purpose_code: vault_family_types::Purpose::Mediation,
        output_schema_id: "echo".to_string(),
        output_schema: serde_json::json!({}),
        participants: vec!["initiator".to_string(), "responder".to_string()],
        prompt_template_hash: "0".repeat(64),
        entropy_budget_bits: None,
        timing_class: None,
        metadata: serde_json::Value::Null,
        model_profile_id: None,
        model_profile_hash: None,
        enforcement_policy_hash: None,
        output_schema_hash: None,
        model_constraints: None,
        max_completion_tokens: None,
        session_ttl_secs: None,
        invite_ttl_secs: None,
        entropy_enforcement: None,
        relay_verifying_key_hex: None,
    };

    let session = Session::new(
        session_id_bytes,
        contract_hash_bytes,
        "0".repeat(64),
        dummy_contract,
        secret,
        pubkey,
        "echo-init-token".to_string(),
        "echo-resp-token".to_string(),
        "echo-read-token".to_string(),
    );

    state
        .sessions
        .insert(session_id.clone(), session)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(EchoCreateSessionResponse {
        session_id,
        tee_session_pubkey: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pubkey.as_bytes(),
        ),
    }))
}

/// POST /sessions/:id/input — submit encrypted input for a role.
///
/// All failure modes return the same 422 status + constant-shape body
/// to prevent side-channel leaks.
pub async fn submit_input(
    State(state): State<Arc<EchoState>>,
    Path(session_id): Path<String>,
    Json(req): Json<SubmitInputRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<InputErrorResponse>)> {
    let reject = || {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(InputErrorResponse::rejected()),
        )
    };

    let role = match req.role.as_str() {
        "initiator" => ParticipantRole::Initiator,
        "responder" => ParticipantRole::Responder,
        _ => return Err(reject()),
    };

    let client_pubkey_bytes: [u8; 32] = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.client_ephemeral_pubkey,
    )
    .ok()
    .and_then(|v| v.try_into().ok())
    .ok_or_else(reject)?;

    let nonce_bytes: [u8; 12] =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.nonce)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(reject)?;

    let ciphertext =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.ciphertext)
            .map_err(|_| reject())?;

    let ciphertext_hash = {
        let mut h = Sha256::new();
        h.update(&ciphertext);
        hex::encode(h.finalize())
    };

    let both_ready = state
        .sessions
        .with_session(&session_id, |session| {
            if session.has_submitted(role) {
                return Err(());
            }

            let tee_secret = session.tee_session_secret.as_ref().ok_or(())?;
            let expected_aad = build_aad(
                &session.session_id_bytes,
                &session.contract_hash_bytes,
                role,
            );

            let plaintext = decrypt_payload(
                tee_secret,
                &session.tee_session_pubkey,
                &client_pubkey_bytes,
                &nonce_bytes,
                &ciphertext,
                &session.session_id_bytes,
                &expected_aad,
            )
            .map_err(|_| ())?;

            session.mark_submitted(role);
            match role {
                ParticipantRole::Initiator => {
                    session.initiator_ciphertext_hash = Some(ciphertext_hash);
                    session.initiator_input = Some(plaintext);
                }
                ParticipantRole::Responder => {
                    session.responder_ciphertext_hash = Some(ciphertext_hash);
                    session.responder_input = Some(plaintext);
                }
            }

            let both = session.both_inputs_received();
            if both {
                session.zeroize_session_key();
            }
            Ok(both)
        })
        .map_err(|_| reject())?
        .ok_or_else(reject)?
        .map_err(|_| reject())?;

    if !both_ready {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "waiting_for_other_input"
            })),
        )
            .into_response());
    }

    let echo = build_echo_response(&state, &session_id)
        .await
        .map_err(|e| {
            tracing::warn!(session_id = %session_id, error = ?e, "echo response failed");
            reject()
        })?;
    Ok((StatusCode::OK, Json(echo)).into_response())
}

#[derive(Debug)]
#[allow(dead_code)] // Fields are read via Debug formatting in tracing output
enum EchoError {
    SessionStorePoisoned,
    SessionNotFound,
    MissingInput(&'static str),
    MissingSubmissionHash(&'static str),
    AttestationFailed(String),
}

async fn build_echo_response(
    state: &EchoState,
    session_id: &str,
) -> Result<EchoResponse, EchoError> {
    let session = state
        .sessions
        .remove(session_id)
        .map_err(|_| EchoError::SessionStorePoisoned)?
        .ok_or(EchoError::SessionNotFound)?;

    let initiator_input = session
        .initiator_input
        .as_ref()
        .ok_or(EchoError::MissingInput("initiator"))?;
    let responder_input = session
        .responder_input
        .as_ref()
        .ok_or(EchoError::MissingInput("responder"))?;

    let initiator_hash = {
        let mut h = Sha256::new();
        h.update(initiator_input.as_slice());
        hex::encode(h.finalize())
    };
    let responder_hash = {
        let mut h = Sha256::new();
        h.update(responder_input.as_slice());
        hex::encode(h.finalize())
    };

    let initiator_sub_hash = session
        .initiator_ciphertext_hash
        .as_ref()
        .ok_or(EchoError::MissingSubmissionHash("initiator"))?;
    let responder_sub_hash = session
        .responder_ciphertext_hash
        .as_ref()
        .ok_or(EchoError::MissingSubmissionHash("responder"))?;

    let output_hash = {
        let mut h = Sha256::new();
        h.update(initiator_hash.as_bytes());
        h.update(responder_hash.as_bytes());
        hex::encode(h.finalize())
    };

    // Echo mode stays on v1 transcript hash: there is no model invocation,
    // and EchoTeeAttestation has no transcript version field, so switching
    // to v2 would silently break consumers.
    let transcript_inputs = TranscriptInputs {
        contract_hash: &hex::encode(vec![0u8; 32]),
        prompt_template_hash: "echo-mode-no-template",
        initiator_submission_hash: initiator_sub_hash,
        responder_submission_hash: responder_sub_hash,
        output_hash: &output_hash,
        receipt_signing_pubkey_hex: &state.receipt_signing_pubkey_hex,
    };

    let transcript_hash = compute_transcript_hash(&transcript_inputs);
    let transcript_hash_hex = hex::encode(transcript_hash);

    let report = state
        .cvm
        .get_attestation(&transcript_hash)
        .await
        .map_err(|e| EchoError::AttestationFailed(format!("{e}")))?;

    let attestation_hash = {
        let mut h = Sha256::new();
        h.update(&report.quote);
        hex::encode(h.finalize())
    };

    Ok(EchoResponse {
        session_id: session_id.to_string(),
        initiator_decrypted_sha256_hex: initiator_hash,
        responder_decrypted_sha256_hex: responder_hash,
        tee_attestation: EchoTeeAttestation {
            tee_type: serde_json::to_value(report.tee_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", report.tee_type)),
            measurement: report.measurement,
            attestation_hash,
            receipt_signing_pubkey_hex: state.receipt_signing_pubkey_hex.clone(),
            transcript_hash_hex,
        },
    })
}
