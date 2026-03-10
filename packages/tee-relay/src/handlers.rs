use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::response::IntoResponse;
use rand::RngCore;
use rand::rngs::OsRng;
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
    pub sessions: std::sync::Arc<SessionStore>,
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// GET /tee/info — return enclave identity + signing pubkey.
pub async fn tee_info(State(state): State<Arc<RelayState>>) -> Json<TeeInfoResponse> {
    let pubkey_hex = hex::encode(state.app.signing_key.verifying_key().as_bytes());
    Json(TeeInfoResponse::from_identity_and_pubkey(
        state.app.cvm.identity(),
        &pubkey_hex,
    ))
}

/// POST /sessions — create a new relay session with per-session ECDH keypair.
pub async fn create_session(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    let (pubkey, secret) = state.app.cvm.derive_session_keypair().map_err(|e| {
        tracing::error!("session keypair derivation failed: {e}"); // SAFETY: no plaintext
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let session_uuid = Uuid::new_v4();
    let session_id = session_uuid.to_string();
    let session_id_bytes: [u8; 16] = *session_uuid.as_bytes();

    // Compute contract hash for binding
    let contract_hash_hex = {
        let canonical = receipt_core::canonicalize_serializable(&req.contract).map_err(|e| {
            tracing::error!("contract canonicalization failed: {e}"); // SAFETY: no plaintext
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    };

    let contract_hash_bytes = hex::decode(&contract_hash_hex).map_err(|e| {
        tracing::error!("contract hash hex decode failed: {e}"); // SAFETY: no plaintext
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let initiator_submit_token = random_token();
    let responder_submit_token = random_token();
    let read_token = random_token();

    let session = Session::new(
        session_id_bytes,
        contract_hash_bytes,
        contract_hash_hex.clone(),
        req.contract,
        secret,
        pubkey,
        initiator_submit_token.clone(),
        responder_submit_token.clone(),
        read_token.clone(),
    );

    state
        .sessions
        .insert(session_id.clone(), session)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateSessionResponse {
        session_id,
        tee_session_pubkey: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pubkey.as_bytes(),
        ),
        contract_hash: contract_hash_hex,
        initiator_submit_token,
        responder_submit_token,
        read_token,
    }))
}

/// POST /sessions/:id/input — submit encrypted input for a role.
///
/// All failure modes return the same 422 status + constant-shape body
/// to prevent side-channel leaks.
pub async fn submit_input(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(req): Json<SubmitInputRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<InputErrorResponse>)> {
    let reject = || {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(InputErrorResponse::rejected()),
        )
    };

    let presented_token = bearer_token(&headers).ok_or_else(reject)?;

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
            let role = session.submit_role_for_token(presented_token).ok_or(())?;
            let expected_role = match role {
                ParticipantRole::Initiator => "initiator",
                ParticipantRole::Responder => "responder",
            };
            if req.role != expected_role {
                return Err(());
            }
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

    // Both inputs received — spawn inference in background
    let state_clone = state.clone();
    let session_id_clone = session_id.clone();
    let handle = tokio::spawn(async move {
        run_inference(state_clone, session_id_clone).await;
    });
    // Watch for panics in the inference task
    let state_watch = state.clone();
    let session_id_watch = session_id.clone();
    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!(session_id = %session_id_watch, "inference task panicked: {e}"); // SAFETY: no plaintext
            let _ = state_watch
                .sessions
                .with_session(&session_id_watch, |session| {
                    session.state = SessionState::Aborted;
                    session.abort_signal = Some("internal_panic".to_string());
                    session.clear_inputs();
                });
        }
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
    let session_data = match state.sessions.with_session(&session_id, |session| {
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
    }) {
        Ok(data) => data,
        Err(_) => {
            tracing::error!(session_id = %session_id, "session store poisoned during inference"); // SAFETY: no plaintext
            return;
        }
    };

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
        let _ = state.sessions.with_session(&session_id, |session| {
            session.state = SessionState::Aborted;
            session.abort_signal = Some("missing_session_data".to_string());
            session.clear_inputs();
        });
        return;
    };

    // Compute schema hash for failure receipt
    let schema_hash = match receipt_core::canonicalize_serializable(&contract.output_schema) {
        Ok(c) => {
            let mut h = Sha256::new();
            h.update(c.as_bytes());
            hex::encode(h.finalize())
        }
        Err(e) => {
            tracing::error!(session_id = %session_id, "schema canonicalization failed: {e}"); // SAFETY: no plaintext
            let _ = state.sessions.with_session(&session_id, |session| {
                session.state = SessionState::Aborted;
                session.abort_signal = Some("schema_canonicalization_failed".to_string());
                session.clear_inputs();
            });
            return;
        }
    };

    let result = relay::relay_core(
        &session_id,
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
            let _ = state.sessions.with_session(&session_id, |session| {
                session.state = SessionState::Completed;
                session.output = Some(relay_result.output);
                session.receipt_v2 = Some(relay_result.receipt_v2);
                session.clear_inputs();
            });
        }
        Err(e) => {
            // Log only the error variant, not the full message (may contain plaintext fragments)
            tracing::warn!(session_id = %session_id, error_kind = %e.kind(), "inference failed"); // SAFETY: no plaintext
            // Build failure receipt
            let failure_receipt = relay::build_failure_receipt_v2(
                &session_id,
                &contract_hash_hex,
                &schema_hash,
                Some(&init_ct_hash),
                Some(&resp_ct_hash),
                "inference_error",
                &state.app,
            )
            .await;

            let _ = state.sessions.with_session(&session_id, |session| {
                session.state = SessionState::Aborted;
                session.abort_signal = Some(e.kind().to_string());
                session.receipt_v2 = match failure_receipt {
                    Ok(r) => Some(r),
                    Err(re) => {
                        tracing::error!(session_id = %session_id, "failed to build failure receipt: {re}"); // SAFETY: no plaintext
                        None
                    }
                };
                session.clear_inputs();
            });
        }
    }
}

/// GET /sessions/:id/status — poll session state.
pub async fn session_status(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, StatusCode> {
    let presented_token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .sessions
        .with_session(&session_id, |session| {
            if !session.read_token_matches(presented_token) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Json(SessionStatusResponse {
                state: session.state,
                abort_signal: session.abort_signal.clone(),
            }))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?
}

/// GET /sessions/:id/output — retrieve result + receipt.
pub async fn session_output(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionOutputResponse>, StatusCode> {
    let presented_token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .sessions
        .with_session(&session_id, |session| {
            if !session.read_token_matches(presented_token) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Json(SessionOutputResponse {
                state: session.state,
                output: session.output.clone(),
                receipt_v2: session.receipt_v2.clone(),
            }))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?
}
