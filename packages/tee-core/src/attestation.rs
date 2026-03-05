use async_trait::async_trait;
use receipt_core::TeeType;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::types::{AttestationReport, EnclaveIdentity};

/// Errors from CVM runtime operations.
#[derive(Debug, thiserror::Error)]
pub enum CvmError {
    #[error("attestation unavailable: {0}")]
    AttestationUnavailable(String),
    #[error("seal/unseal failed: {0}")]
    SealError(String),
}

/// Abstraction over TEE CVM capabilities.
///
/// Named `CvmRuntime` (not `EnclaveRuntime`) to be precise: with AMD SEV-SNP,
/// the entire VM is the trust boundary, not a separate enclave process.
///
/// `SimulatedCvm` provides a local-dev implementation with deterministic
/// test measurements and a self-signed attestation chain.
#[async_trait]
pub trait CvmRuntime: Send + Sync {
    /// Static enclave identity (measurement, platform, signing pubkey).
    fn identity(&self) -> &EnclaveIdentity;

    /// Fetch attestation report binding `user_data` to the CVM measurement.
    async fn get_attestation(&self, user_data: &[u8; 64]) -> Result<AttestationReport, CvmError>;

    /// Generate per-session ECDH keypair.
    ///
    /// The relay owns zeroization of the secret half — the return type wraps
    /// it in `Zeroizing` from the start.
    fn derive_session_keypair(&self) -> Result<(PublicKey, Zeroizing<StaticSecret>), CvmError>;

    /// Seal data to the CVM measurement (survives restart of same image).
    async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, CvmError>;

    /// Unseal data previously sealed by this CVM.
    async fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, CvmError>;

    /// Whether this is a real hardware TEE.
    ///
    /// Determines `assurance_level` in receipts:
    /// - `true` → `TeeAttested`
    /// - `false` → `SelfAsserted` (simulated mode)
    fn is_real_tee(&self) -> bool;
}

/// Simulated CVM for local development and testing.
///
/// - Measurement: `SHA-256("av-tee-simulated-v1")`
/// - `tee_type: Simulated` (always explicit, never omitted)
/// - Attestation: deterministic dummy quote
/// - seal/unseal: AES-256-GCM with measurement-derived key
pub struct SimulatedCvm {
    identity: EnclaveIdentity,
    seal_key: [u8; 32],
}

/// Deterministic simulated measurement.
pub const SIMULATED_MEASUREMENT_INPUT: &str = "av-tee-simulated-v1";

impl SimulatedCvm {
    pub fn new(receipt_signing_pubkey_hex: String) -> Self {
        let measurement = {
            let mut h = Sha256::new();
            h.update(SIMULATED_MEASUREMENT_INPUT.as_bytes());
            hex::encode(h.finalize())
        };

        // Derive seal key from measurement for deterministic testing
        let seal_key = {
            let mut h = Sha256::new();
            h.update(b"av-tee-seal-key:");
            h.update(measurement.as_bytes());
            let result: [u8; 32] = h.finalize().into();
            result
        };

        let identity = EnclaveIdentity {
            tee_type: TeeType::Simulated,
            measurement,
            platform_version: "simulated-v1".to_string(),
            receipt_signing_pubkey_hex,
        };

        Self { identity, seal_key }
    }
}

#[async_trait]
impl CvmRuntime for SimulatedCvm {
    fn identity(&self) -> &EnclaveIdentity {
        &self.identity
    }

    async fn get_attestation(&self, user_data: &[u8; 64]) -> Result<AttestationReport, CvmError> {
        // Deterministic dummy quote: "simulated-quote:" || user_data
        let mut quote = Vec::with_capacity(16 + 64);
        quote.extend_from_slice(b"simulated-quote:");
        quote.extend_from_slice(user_data);

        Ok(AttestationReport {
            tee_type: TeeType::Simulated,
            measurement: self.identity.measurement.clone(),
            quote,
            user_data: *user_data,
        })
    }

    fn derive_session_keypair(&self) -> Result<(PublicKey, Zeroizing<StaticSecret>), CvmError> {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Ok((public, Zeroizing::new(secret)))
    }

    async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, CvmError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| CvmError::SealError(e.to_string()))?;
        // Use a fixed nonce for simulated sealing (deterministic for testing)
        let nonce = Nonce::from_slice(&[0u8; 12]);
        cipher
            .encrypt(nonce, data)
            .map_err(|e| CvmError::SealError(e.to_string()))
    }

    async fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, CvmError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| CvmError::SealError(e.to_string()))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        cipher
            .decrypt(nonce, sealed)
            .map_err(|e| CvmError::SealError(e.to_string()))
    }

    fn is_real_tee(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cvm() -> SimulatedCvm {
        SimulatedCvm::new("deadbeef".repeat(8))
    }

    #[test]
    fn identity_uses_simulated_tee_type() {
        let cvm = test_cvm();
        assert_eq!(cvm.identity().tee_type, TeeType::Simulated);
    }

    #[test]
    fn identity_measurement_is_deterministic() {
        let cvm1 = test_cvm();
        let cvm2 = test_cvm();
        assert_eq!(cvm1.identity().measurement, cvm2.identity().measurement);
    }

    #[test]
    fn is_not_real_tee() {
        assert!(!test_cvm().is_real_tee());
    }

    #[tokio::test]
    async fn attestation_report_binds_user_data() {
        let cvm = test_cvm();
        let user_data = [42u8; 64];
        let report = cvm.get_attestation(&user_data).await.unwrap();
        assert_eq!(report.user_data, user_data);
        assert_eq!(report.tee_type, TeeType::Simulated);
        assert_eq!(report.measurement, cvm.identity().measurement);
    }

    #[tokio::test]
    async fn seal_unseal_roundtrip() {
        let cvm = test_cvm();
        let data = b"secret key material";
        let sealed = cvm.seal(data).await.unwrap();
        assert_ne!(sealed, data);
        let unsealed = cvm.unseal(&sealed).await.unwrap();
        assert_eq!(unsealed, data);
    }

    #[test]
    fn session_keypair_is_unique() {
        let cvm = test_cvm();
        let (pub1, _secret1) = cvm.derive_session_keypair().unwrap();
        let (pub2, _secret2) = cvm.derive_session_keypair().unwrap();
        assert_ne!(pub1.as_bytes(), pub2.as_bytes());
    }
}
