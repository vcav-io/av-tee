use receipt_core::TeeType;
use serde::{Deserialize, Serialize};

/// Enclave identity — the CVM's static hardware/software identity.
///
/// Does NOT contain session keys or application keys. The receipt signing
/// pubkey is an application concern (lives in `AppState`), not a CVM concern.
/// Per-session ECDH pubkeys are returned only from `POST /sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveIdentity {
    pub tee_type: TeeType,
    pub measurement: String,
    pub platform_version: String,
}

/// Encrypted input payload from a client.
///
/// The client performs ECDH with the per-session TEE pubkey, derives an
/// AES-256-GCM key via HKDF, and encrypts their `RelayInput` JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Client's ephemeral X25519 public key (32 bytes, base64).
    pub client_ephemeral_pubkey: String,
    /// AES-256-GCM nonce (12 bytes, base64).
    pub nonce: String,
    /// Encrypted input (base64).
    pub ciphertext: String,
}

/// Attestation report produced by the CVM.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    pub tee_type: TeeType,
    pub measurement: String,
    /// Raw attestation quote bytes.
    pub quote: Vec<u8>,
    /// Transcript hash bound into the attestation via the platform's
    /// user_data field (64 bytes for SEV-SNP).
    pub user_data: [u8; 64],
}

/// Role of a session participant, used for AAD construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantRole {
    Initiator,
    Responder,
}

impl ParticipantRole {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ParticipantRole::Initiator => b":initiator",
            ParticipantRole::Responder => b":responder",
        }
    }
}
