use std::sync::OnceLock;

use async_trait::async_trait;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", test))]
use tee_core::TeeType;
use tee_core::attestation::{CvmError, CvmRuntime};
use tee_core::types::{AttestationReport, EnclaveIdentity};

#[cfg(target_os = "linux")]
use crate::snp_guest;

// Seal envelope constants
const SEAL_VERSION_PREFIX: &[u8] = b"av-tee-seal-v2";
const TEE_TYPE_SEV_SNP: u8 = 0x01;
const KEY_POLICY_SNP_VMPL0_VCEK_V1: u8 = 0x01;
const SEAL_HEADER_LEN: usize = 14 + 1 + 1 + 12; // prefix + tee_type + policy + nonce

/// Real SEV-SNP CVM runtime.
///
/// Owns the `/dev/sev-guest` device handle. Identity is lazily
/// initialized on first access. Sealing keys are derived on-demand
/// via `SNP_GET_DERIVED_KEY`.
pub struct SevSnpCvm {
    inner: SevSnpInner,
    identity: OnceLock<EnclaveIdentity>,
}

enum SevSnpInner {
    #[cfg(target_os = "linux")]
    Hardware(std::sync::Mutex<sev::firmware::guest::Firmware>),
    #[cfg(test)]
    Mock {
        measurement: String,
        seal_key: [u8; 32],
    },
    /// Never constructed — exists only to keep the enum non-empty on
    /// non-Linux non-test builds so match arms compile.
    #[cfg(not(any(target_os = "linux", test)))]
    #[allow(dead_code)]
    _Unreachable(std::convert::Infallible),
}

impl SevSnpCvm {
    /// Open the SEV-SNP guest device and create a new runtime.
    ///
    /// Only opens the device — identity is lazily populated on first
    /// call to `identity()`.
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self, CvmError> {
        let fw = snp_guest::open_device()?;
        Ok(Self {
            inner: SevSnpInner::Hardware(std::sync::Mutex::new(fw)),
            identity: OnceLock::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn mock_for_testing() -> Self {
        use sha2::{Digest, Sha256};
        let measurement = hex::encode(Sha256::digest(b"av-tee-snp-mock-v1"));
        let seal_key = {
            let mut h = Sha256::new();
            h.update(b"av-tee-mock-seal:");
            h.update(measurement.as_bytes());
            let r: [u8; 32] = h.finalize().into();
            r
        };
        Self {
            inner: SevSnpInner::Mock {
                measurement,
                seal_key,
            },
            identity: OnceLock::new(),
        }
    }

    fn init_identity(&self) -> Result<EnclaveIdentity, CvmError> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw.lock().map_err(|e| {
                    CvmError::AttestationUnavailable(format!("firmware mutex poisoned: {e}"))
                })?;
                let dummy_user_data = [0u8; 64];
                let parsed = snp_guest::get_ext_report(&mut fw, &dummy_user_data)?;
                Ok(EnclaveIdentity {
                    tee_type: TeeType::SevSnp,
                    measurement: parsed.measurement_hex,
                    platform_version: "snp-v1".to_string(),
                })
            }
            #[cfg(test)]
            SevSnpInner::Mock { measurement, .. } => Ok(EnclaveIdentity {
                tee_type: TeeType::SevSnp,
                measurement: measurement.clone(),
                platform_version: "mock-v1".to_string(),
            }),
            #[cfg(not(any(target_os = "linux", test)))]
            SevSnpInner::_Unreachable(infallible) => match *infallible {},
        }
    }

    fn derive_seal_key(&self) -> Result<Zeroizing<[u8; 32]>, CvmError> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw
                    .lock()
                    .map_err(|e| CvmError::SealError(format!("firmware mutex poisoned: {e}")))?;
                snp_guest::derive_seal_key(&mut fw)
            }
            #[cfg(test)]
            SevSnpInner::Mock { seal_key, .. } => Ok(Zeroizing::new(*seal_key)),
            #[cfg(not(any(target_os = "linux", test)))]
            SevSnpInner::_Unreachable(infallible) => match *infallible {},
        }
    }
}

#[async_trait]
impl CvmRuntime for SevSnpCvm {
    fn identity(&self) -> &EnclaveIdentity {
        self.identity.get_or_init(|| {
            self.init_identity()
                .expect("failed to initialize CVM identity from platform")
        })
    }

    #[allow(unused_variables)]
    async fn get_attestation(&self, user_data: &[u8; 64]) -> Result<AttestationReport, CvmError> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw.lock().map_err(|e| {
                    CvmError::AttestationUnavailable(format!("firmware mutex poisoned: {e}"))
                })?;
                let parsed = snp_guest::get_ext_report(&mut fw, user_data)?;
                Ok(AttestationReport {
                    tee_type: TeeType::SevSnp,
                    measurement: parsed.measurement_hex,
                    quote: parsed.report_bytes,
                    user_data: parsed.user_data,
                    vcek_cert_der: parsed.vcek_cert_der,
                })
            }
            #[cfg(test)]
            SevSnpInner::Mock { measurement, .. } => {
                let mut report = vec![0u8; 1184];
                report[0..4].copy_from_slice(&2u32.to_le_bytes());
                report[80..144].copy_from_slice(user_data);
                let meas_bytes = hex::decode(measurement).unwrap();
                report[144..144 + meas_bytes.len()].copy_from_slice(&meas_bytes);
                Ok(AttestationReport {
                    tee_type: TeeType::SevSnp,
                    measurement: measurement.clone(),
                    quote: report,
                    user_data: *user_data,
                    vcek_cert_der: None,
                })
            }
            #[cfg(not(any(target_os = "linux", test)))]
            SevSnpInner::_Unreachable(infallible) => match *infallible {},
        }
    }

    fn derive_session_keypair(&self) -> Result<(PublicKey, Zeroizing<StaticSecret>), CvmError> {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Ok((public, Zeroizing::new(secret)))
    }

    async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, CvmError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let key = self.derive_seal_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

        // Build header (used as AAD)
        let mut header = Vec::with_capacity(SEAL_HEADER_LEN);
        header.extend_from_slice(SEAL_VERSION_PREFIX);
        header.push(TEE_TYPE_SEV_SNP);
        header.push(KEY_POLICY_SNP_VMPL0_VCEK_V1);
        header.extend_from_slice(&nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let aead_payload = aes_gcm::aead::Payload {
            msg: data,
            aad: &header,
        };
        let ciphertext = cipher
            .encrypt(nonce, aead_payload)
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let mut blob = Vec::with_capacity(header.len() + ciphertext.len());
        blob.extend_from_slice(&header);
        blob.extend(ciphertext);
        Ok(blob)
    }

    async fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, CvmError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        if sealed.len() < SEAL_HEADER_LEN {
            return Err(CvmError::SealError(
                "sealed blob too short for header".into(),
            ));
        }
        if !sealed.starts_with(SEAL_VERSION_PREFIX) {
            return Err(CvmError::SealError(format!(
                "expected seal prefix {:?}, got {:?}",
                SEAL_VERSION_PREFIX,
                &sealed[..SEAL_VERSION_PREFIX.len().min(sealed.len())]
            )));
        }

        let tee_type = sealed[SEAL_VERSION_PREFIX.len()];
        if tee_type != TEE_TYPE_SEV_SNP {
            return Err(CvmError::SealError(format!(
                "unexpected tee_type {tee_type:#04x}, expected {TEE_TYPE_SEV_SNP:#04x}"
            )));
        }

        let policy_id = sealed[SEAL_VERSION_PREFIX.len() + 1];
        if policy_id != KEY_POLICY_SNP_VMPL0_VCEK_V1 {
            return Err(CvmError::SealError(format!(
                "unsupported key policy {policy_id:#04x}"
            )));
        }

        let header = &sealed[..SEAL_HEADER_LEN];
        let nonce_start = SEAL_VERSION_PREFIX.len() + 2;
        let nonce_bytes = &sealed[nonce_start..nonce_start + 12];
        let ciphertext = &sealed[SEAL_HEADER_LEN..];

        let key = self.derive_seal_key()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce_bytes);
        let aead_payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: header,
        };
        cipher
            .decrypt(nonce, aead_payload)
            .map_err(|e| CvmError::SealError(format!("decryption failed: {e}")))
    }

    fn is_real_tee(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tee_core::attestation::CvmRuntime;

    #[test]
    fn is_real_tee_returns_true() {
        let cvm = SevSnpCvm::mock_for_testing();
        assert!(cvm.is_real_tee());
    }

    #[test]
    fn identity_returns_sev_snp_tee_type() {
        let cvm = SevSnpCvm::mock_for_testing();
        let id = cvm.identity();
        assert!(matches!(id.tee_type, TeeType::SevSnp));
        assert!(!id.measurement.is_empty());
    }

    #[tokio::test]
    async fn mock_get_attestation_returns_report() {
        let cvm = SevSnpCvm::mock_for_testing();
        let user_data = [0x42u8; 64];
        let report = cvm.get_attestation(&user_data).await.unwrap();
        assert_eq!(report.user_data, user_data);
        assert!(!report.quote.is_empty());
        assert!(!report.measurement.is_empty());
    }

    #[tokio::test]
    async fn mock_seal_unseal_roundtrip() {
        let cvm = SevSnpCvm::mock_for_testing();
        let plaintext = b"secret data for sealing test";
        let sealed = cvm.seal(plaintext).await.unwrap();
        assert_ne!(&sealed[..], plaintext);
        let unsealed = cvm.unseal(&sealed).await.unwrap();
        assert_eq!(&unsealed[..], plaintext);
    }

    #[tokio::test]
    async fn mock_unseal_rejects_tampered_blob() {
        let cvm = SevSnpCvm::mock_for_testing();
        let sealed = cvm.seal(b"test").await.unwrap();
        let mut tampered = sealed.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xFF;
        }
        assert!(cvm.unseal(&tampered).await.is_err());
    }

    #[test]
    fn mock_derive_session_keypair_succeeds() {
        let cvm = SevSnpCvm::mock_for_testing();
        let (pub_key, secret) = cvm.derive_session_keypair().unwrap();
        let derived_pub = PublicKey::from(&*secret);
        assert_eq!(pub_key.as_bytes(), derived_pub.as_bytes());
    }

    #[tokio::test]
    async fn mock_unseal_rejects_wrong_prefix() {
        let cvm = SevSnpCvm::mock_for_testing();
        let bad = b"av-tee-seal-v1\x01\x01xxxxxxxxxxxx_ciphertext";
        assert!(cvm.unseal(bad).await.is_err());
    }

    #[tokio::test]
    async fn mock_unseal_rejects_wrong_tee_type() {
        let cvm = SevSnpCvm::mock_for_testing();
        let sealed = cvm.seal(b"test").await.unwrap();
        let mut tampered = sealed.clone();
        tampered[SEAL_VERSION_PREFIX.len()] = 0xFF;
        assert!(cvm.unseal(&tampered).await.is_err());
    }

    #[tokio::test]
    async fn mock_unseal_rejects_wrong_policy() {
        let cvm = SevSnpCvm::mock_for_testing();
        let sealed = cvm.seal(b"test").await.unwrap();
        let mut tampered = sealed.clone();
        tampered[SEAL_VERSION_PREFIX.len() + 1] = 0xFF;
        assert!(cvm.unseal(&tampered).await.is_err());
    }
}
