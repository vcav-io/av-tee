use serde::{Deserialize, Serialize};
use tee_core::EnclaveIdentity;

use crate::session::SessionState;

/// Response from GET /tee/info.
#[derive(Debug, Serialize, Deserialize)]
pub struct TeeInfoResponse {
    pub tee_type: String,
    pub measurement: String,
    pub platform_version: String,
    pub receipt_signing_pubkey_hex: String,
}

impl TeeInfoResponse {
    pub fn from_identity_and_pubkey(id: &EnclaveIdentity, pubkey_hex: &str) -> Self {
        Self {
            tee_type: serde_json::to_value(id.tee_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", id.tee_type)),
            measurement: id.measurement.clone(),
            platform_version: id.platform_version.clone(),
            receipt_signing_pubkey_hex: pubkey_hex.to_string(),
        }
    }
}

// ============================================================================
// Session creation
// ============================================================================

/// Request body for POST /sessions.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub contract: vault_family_types::Contract,
}

/// Response from POST /sessions.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    /// Per-session X25519 public key (base64). Clients use this for ECDH.
    pub tee_session_pubkey: String,
    pub contract_hash: String,
}

/// Request body for POST /sessions/:id/input.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitInputRequest {
    pub role: String,
    pub client_ephemeral_pubkey: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Constant-shape error response. All input-submission failures return the
/// same status code and body shape to prevent side-channel leaks.
#[derive(Debug, Serialize)]
pub struct InputErrorResponse {
    pub error: String,
}

impl InputErrorResponse {
    pub fn rejected() -> Self {
        Self {
            error: "input_rejected".to_string(),
        }
    }
}

// ============================================================================
// Session status and output
// ============================================================================

/// Response from GET /sessions/:id/status.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStatusResponse {
    pub state: SessionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_signal: Option<String>,
}

/// Response from GET /sessions/:id/output.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionOutputResponse {
    pub state: SessionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_v2: Option<receipt_core::ReceiptV2>,
}

// ============================================================================
// Echo mode types (backward compatibility)
// ============================================================================

/// Echo-mode response from POST /sessions/:id/input (after both inputs received).
#[derive(Debug, Serialize, Deserialize)]
pub struct EchoResponse {
    pub session_id: String,
    pub initiator_decrypted_sha256_hex: String,
    pub responder_decrypted_sha256_hex: String,
    pub tee_attestation: EchoTeeAttestation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoTeeAttestation {
    pub tee_type: String,
    pub measurement: String,
    pub attestation_hash: String,
    pub receipt_signing_pubkey_hex: String,
    pub transcript_hash_hex: String,
}
