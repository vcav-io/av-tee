use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tee_core::crypto::{build_aad, decrypt_payload};
use tee_core::types::ParticipantRole;

use crate::relay::{self, AppState};
use crate::session::{Session, SessionState, SessionStore};
use crate::types::*;

/// Shared state for the relay, wrapping AppState + SessionStore.
pub struct RelayState {
    pub app: AppState,
    pub sessions: SessionStore,
}

/// GET /tee/info — return enclave identity.
pub async fn tee_info(State(state): State<Arc<RelayState>>) -> Json<TeeInfoResponse> {
    Json(TeeInfoResponse::from(state.app.cvm.identity()))
}

/// POST /sessions — create a new relay session with per-session ECDH keypair.
pub async fn create_session(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    let (pubkey, secret) = state
        .app
        .cvm
        .derive_session_keypair()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session_uuid = Uuid::new_v4();
    let session_id = session_uuid.to_string();
    let session_id_bytes: [u8; 16] = *session_uuid.as_bytes();

    // Compute contract hash for binding
    let contract_hash_hex = {
        let canonical = receipt_core::canonicalize_serializable(&req.contract)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    };

    let contract_hash_bytes =
        hex::decode(&contract_hash_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session = Session::new(
        session_id_bytes,
        contract_hash_bytes,
        contract_hash_hex.clone(),
        req.contract,
        secret,
        pubkey,
    );

    state.sessions.insert(session_id.clone(), session);

    Ok(Json(CreateSessionResponse {
        session_id,
        tee_session_pubkey: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pubkey.as_bytes(),
        ),
        contract_hash: contract_hash_hex,
    }))
}

/// POST /sessions/:id/input — submit encrypted input for a role.
///
/// All failure modes return the same 422 status + constant-shape body
/// to prevent side-channel leaks.
pub async fn submit_input(
    State(state): State<Arc<RelayState>>,
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

    // Decode base64 fields
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

    // Compute ciphertext hash for receipt commitments
    let ciphertext_hash = {
        let mut h = Sha256::new();
        h.update(&ciphertext);
        hex::encode(h.finalize())
    };

    // Decrypt and store — all errors map to the same rejection
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
                session.state = SessionState::Processing;
            } else {
                session.state = SessionState::Partial;
            }
            Ok(both)
        })
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

    // Both inputs received — spawn inference in background
    let state_clone = state.clone();
    let session_id_clone = session_id.clone();
    tokio::spawn(async move {
        run_inference(state_clone, session_id_clone).await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "processing"
        })),
    )
        .into_response())
}

/// Run inference in the background. Updates session state on completion.
async fn run_inference(state: Arc<RelayState>, session_id: String) {
    // Extract inputs from session (take ownership)
    let session_data = state.sessions.with_session(&session_id, |session| {
        let initiator = session.initiator_input.take();
        let responder = session.responder_input.take();
        let contract = session.contract.take();
        let contract_hash_hex = session.contract_hash_hex.clone();
        let init_ct_hash = session.initiator_ciphertext_hash.clone();
        let resp_ct_hash = session.responder_ciphertext_hash.clone();
        (
            initiator,
            responder,
            contract,
            contract_hash_hex,
            init_ct_hash,
            resp_ct_hash,
        )
    });

    let Some((
        Some(initiator_input),
        Some(responder_input),
        Some(contract),
        contract_hash_hex,
        Some(init_ct_hash),
        Some(resp_ct_hash),
    )) = session_data
    else {
        // Missing data — abort
        state.sessions.with_session(&session_id, |session| {
            session.state = SessionState::Aborted;
            session.abort_signal = Some("missing_session_data".to_string());
            session.clear_inputs();
        });
        return;
    };

    // Compute schema hash for failure receipt
    let schema_hash = {
        let canonical = receipt_core::canonicalize_serializable(&contract.output_schema);
        match canonical {
            Ok(c) => {
                let mut h = Sha256::new();
                h.update(c.as_bytes());
                hex::encode(h.finalize())
            }
            Err(_) => hex::encode(Sha256::digest(b"")),
        }
    };

    let result = relay::relay_core(
        &contract,
        &initiator_input,
        &responder_input,
        &init_ct_hash,
        &resp_ct_hash,
        &contract_hash_hex,
        &state.app,
    )
    .await;

    match result {
        Ok(relay_result) => {
            state.sessions.with_session(&session_id, |session| {
                session.state = SessionState::Completed;
                session.output = Some(relay_result.output);
                session.receipt_v2 = Some(relay_result.receipt_v2);
                session.clear_inputs();
            });
        }
        Err(e) => {
            tracing::warn!(session_id = %session_id, "inference failed: {e}");
            // Build failure receipt
            let failure_receipt = relay::build_failure_receipt_v2(
                &contract_hash_hex,
                &schema_hash,
                Some(&init_ct_hash),
                Some(&resp_ct_hash),
                "inference_error",
                &state.app,
            )
            .await;

            state.sessions.with_session(&session_id, |session| {
                session.state = SessionState::Aborted;
                session.abort_signal = Some(e.to_string());
                session.receipt_v2 = failure_receipt.ok();
                session.clear_inputs();
            });
        }
    }
}

/// GET /sessions/:id/status — poll session state.
pub async fn session_status(
    State(state): State<Arc<RelayState>>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, StatusCode> {
    state
        .sessions
        .with_session(&session_id, |session| {
            Json(SessionStatusResponse {
                state: session.state,
                abort_signal: session.abort_signal.clone(),
            })
        })
        .ok_or(StatusCode::NOT_FOUND)
}

/// GET /sessions/:id/output — retrieve result + receipt.
pub async fn session_output(
    State(state): State<Arc<RelayState>>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionOutputResponse>, StatusCode> {
    state
        .sessions
        .with_session(&session_id, |session| {
            Json(SessionOutputResponse {
                state: session.state,
                output: session.output.clone(),
                receipt_v2: session.receipt_v2.clone(),
            })
        })
        .ok_or(StatusCode::NOT_FOUND)
}
