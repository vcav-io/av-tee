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
    /// Static enclave identity (measurement, platform). Does not include
    /// application keys — those are owned by the relay, not the CVM.
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

/// Version prefix for sealed blobs. Allows future seal format rotation.
const SEAL_VERSION_PREFIX: &[u8] = b"av-tee-seal-v1";

/// Simulated CVM for local development and testing.
///
/// - Measurement: `SHA-256("av-tee-simulated-v1")`
/// - `tee_type: Simulated` (always explicit, never omitted)
/// - Attestation: deterministic dummy quote
/// - seal/unseal: AES-256-GCM with measurement-derived key and random nonce
pub struct SimulatedCvm {
    identity: EnclaveIdentity,
    seal_key: [u8; 32],
}

/// Deterministic simulated measurement.
pub const SIMULATED_MEASUREMENT_INPUT: &str = "av-tee-simulated-v1";

impl SimulatedCvm {
    pub fn new() -> Self {
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
        };

        Self { identity, seal_key }
    }
}

impl Default for SimulatedCvm {
    fn default() -> Self {
        Self::new()
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

    /// Seal format: `PREFIX || random_nonce[12] || ciphertext`
    ///
    /// Uses a random nonce every time. AES-GCM requires unique nonces per
    /// encryption under the same key — a fixed nonce violates this even when
    /// the plaintext is high-entropy key material.
    async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, CvmError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let mut blob = Vec::with_capacity(SEAL_VERSION_PREFIX.len() + 12 + encrypted.len());
        blob.extend_from_slice(SEAL_VERSION_PREFIX);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend(encrypted);
        Ok(blob)
    }

    async fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, CvmError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        if !sealed.starts_with(SEAL_VERSION_PREFIX) {
            return Err(CvmError::SealError(
                "sealed blob missing version prefix (expected av-tee-seal-v1)".into(),
            ));
        }
        let rest = &sealed[SEAL_VERSION_PREFIX.len()..];
        if rest.len() < 12 {
            return Err(CvmError::SealError(
                "sealed blob too short for nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = rest.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| CvmError::SealError(e.to_string()))?;
        cipher
            .decrypt(nonce, ciphertext)
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
        SimulatedCvm::new()
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
    fn identity_does_not_contain_signing_key() {
        let cvm = test_cvm();
        let id = cvm.identity();
        // EnclaveIdentity has no receipt_signing_pubkey_hex field
        assert!(!id.measurement.is_empty());
        assert!(!id.platform_version.is_empty());
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
    async fn seal_uses_versioned_prefix() {
        let cvm = test_cvm();
        let data = b"test-key-material";
        let sealed = cvm.seal(data).await.unwrap();
        assert!(sealed.starts_with(SEAL_VERSION_PREFIX));
    }

    #[tokio::test]
    async fn seal_is_not_deterministic() {
        let cvm = test_cvm();
        let data = b"same-key-material";
        let sealed1 = cvm.seal(data).await.unwrap();
        let sealed2 = cvm.seal(data).await.unwrap();
        assert_ne!(sealed1, sealed2, "seal must use random nonce");
    }

    #[tokio::test]
    async fn seal_unseal_roundtrip() {
        let cvm = test_cvm();
        let data = b"secret key material";
        let sealed = cvm.seal(data).await.unwrap();
        assert_ne!(sealed.as_slice(), data);
        let unsealed = cvm.unseal(&sealed).await.unwrap();
        assert_eq!(unsealed, data);
    }

    #[tokio::test]
    async fn unseal_rejects_unversioned_blob() {
        let cvm = test_cvm();
        let raw = vec![0u8; 48];
        assert!(cvm.unseal(&raw).await.is_err());
    }

    #[tokio::test]
    async fn unseal_rejects_truncated_blob() {
        let cvm = test_cvm();
        // Just the prefix with no nonce or ciphertext
        let mut short = SEAL_VERSION_PREFIX.to_vec();
        short.extend_from_slice(&[0u8; 5]); // too short for 12-byte nonce
        assert!(cvm.unseal(&short).await.is_err());
    }

    #[test]
    fn session_keypair_is_unique() {
        let cvm = test_cvm();
        let (pub1, _secret1) = cvm.derive_session_keypair().unwrap();
        let (pub2, _secret2) = cvm.derive_session_keypair().unwrap();
        assert_ne!(pub1.as_bytes(), pub2.as_bytes());
    }
}
