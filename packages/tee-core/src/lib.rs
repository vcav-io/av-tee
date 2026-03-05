#![forbid(unsafe_code)]

pub mod attestation;
pub mod crypto;
pub mod types;

pub use attestation::{CvmRuntime, SimulatedCvm};
pub use crypto::{build_aad, decrypt_payload};

// Re-export tee-transcript for backwards compatibility.
pub use tee_transcript as transcript;
pub use tee_transcript::{TRANSCRIPT_VERSION, TranscriptInputs, compute_transcript_hash};
pub use types::{AttestationReport, EnclaveIdentity, EncryptedPayload};

// Re-export VFC types used by consumers.
pub use receipt_core::TeeType;
