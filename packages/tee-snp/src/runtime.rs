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

#[cfg(any(target_os = "linux", test))]
use crate::snp_guest::{SealKeyRequest, seal_key_request};

// Seal envelope constants.
//
// Format v3: PREFIX || tee_type || key_policy || tcb_floor (u64 LE) || nonce[12]
// || AES-256-GCM(ciphertext), with the whole header as AAD.
const SEAL_VERSION_PREFIX: &[u8] = b"av-tee-seal-v3";
/// Envelope written by earlier versions (key derived from the measurement
/// only). Recognised so the rejection says what to do.
const LEGACY_SEAL_VERSION_PREFIX: &[u8] = b"av-tee-seal-v2";
const TEE_TYPE_SEV_SNP: u8 = 0x01;
/// VCEK root, VMPL 0; guest policy, measurement and TCB floor mixed in.
const KEY_POLICY_SNP_VMPL0_VCEK_POLICY_TCB: u8 = 0x02;
const SEAL_TCB_FLOOR_LEN: usize = 8;
const SEAL_HEADER_LEN: usize = 14 + 1 + 1 + SEAL_TCB_FLOOR_LEN + 12;

/// Whether every TCB component of `floor` is at or below `committed`.
///
/// Milan/Genoa TCB_VERSION layout (little-endian bytes): boot loader [0],
/// TEE [1], SNP [6], microcode [7].
fn tcb_at_least(committed: u64, floor: u64) -> bool {
    let c = committed.to_le_bytes();
    let f = floor.to_le_bytes();
    [0usize, 1, 6, 7].iter().all(|&i| c[i] >= f[i])
}

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
        committed_tcb: u64,
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
    /// Requests an attestation report up front, so a device that opens but
    /// cannot attest fails here (at startup) rather than on first use.
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self, CvmError> {
        let fw = snp_guest::open_device()?;
        let cvm = Self {
            inner: SevSnpInner::Hardware(std::sync::Mutex::new(fw)),
            identity: OnceLock::new(),
        };
        let identity = cvm.init_identity()?;
        let _ = cvm.identity.set(identity);
        Ok(cvm)
    }

    #[cfg(test)]
    pub(crate) fn mock_for_testing() -> Self {
        Self::mock_with_committed_tcb(MOCK_COMMITTED_TCB)
    }

    /// Mock whose platform reports `committed_tcb`.
    #[cfg(test)]
    pub(crate) fn mock_with_committed_tcb(committed_tcb: u64) -> Self {
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
                committed_tcb,
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

    /// The platform's committed TCB, used as the floor for new seals.
    fn committed_tcb(&self) -> Result<u64, CvmError> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw.lock().map_err(|e| {
                    CvmError::AttestationUnavailable(format!("firmware mutex poisoned: {e}"))
                })?;
                snp_guest::committed_tcb(&mut fw)
            }
            #[cfg(test)]
            SevSnpInner::Mock { committed_tcb, .. } => Ok(*committed_tcb),
            #[cfg(not(any(target_os = "linux", test)))]
            SevSnpInner::_Unreachable(infallible) => match *infallible {},
        }
    }

    /// Derive the sealing key for `tcb_floor` under the current key policy.
    #[cfg_attr(not(any(target_os = "linux", test)), allow(unused_variables))]
    fn derive_seal_key(&self, tcb_floor: u64) -> Result<Zeroizing<[u8; 32]>, CvmError> {
        #[cfg(any(target_os = "linux", test))]
        let request: SealKeyRequest = seal_key_request(tcb_floor);
        match &self.inner {
            #[cfg(target_os = "linux")]
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw
                    .lock()
                    .map_err(|e| CvmError::SealError(format!("firmware mutex poisoned: {e}")))?;
                snp_guest::derive_seal_key(&mut fw, request)
            }
            #[cfg(test)]
            SevSnpInner::Mock {
                seal_key,
                committed_tcb,
                ..
            } => {
                use sha2::{Digest, Sha256};
                // Like the firmware, refuse a TCB above the committed TCB.
                if !tcb_at_least(*committed_tcb, request.tcb_version) {
                    return Err(CvmError::SealError(
                        "SNP_GET_DERIVED_KEY failed: TCB above committed TCB".into(),
                    ));
                }
                let mut h = Sha256::new();
                h.update(seal_key);
                h.update(request.field_select.to_le_bytes());
                h.update(request.vmpl.to_le_bytes());
                h.update(request.tcb_version.to_le_bytes());
                Ok(Zeroizing::new(h.finalize().into()))
            }
            #[cfg(not(any(target_os = "linux", test)))]
            SevSnpInner::_Unreachable(infallible) => match *infallible {},
        }
    }
}

/// Committed TCB reported by the mock platform.
#[cfg(test)]
const MOCK_COMMITTED_TCB: u64 = u64::from_le_bytes([3, 0, 0, 0, 0, 0, 8, 115]);

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

        // The floor is the platform's committed TCB at sealing time. It is
        // recorded in the header (and authenticated as AAD) so unseal derives
        // the same key; a platform below the floor cannot derive it.
        let tcb_floor = self.committed_tcb()?;
        let key = self.derive_seal_key(tcb_floor)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

        // Build header (used as AAD)
        let mut header = Vec::with_capacity(SEAL_HEADER_LEN);
        header.extend_from_slice(SEAL_VERSION_PREFIX);
        header.push(TEE_TYPE_SEV_SNP);
        header.push(KEY_POLICY_SNP_VMPL0_VCEK_POLICY_TCB);
        header.extend_from_slice(&tcb_floor.to_le_bytes());
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

        if sealed.starts_with(LEGACY_SEAL_VERSION_PREFIX) {
            return Err(CvmError::SealedBlobRejected(
                "sealed with key policy 0x01 (measurement only); this version also binds the \
                 guest policy and a TCB floor, so the key must be regenerated"
                    .into(),
            ));
        }
        if !sealed.starts_with(SEAL_VERSION_PREFIX) {
            return Err(CvmError::SealedBlobRejected(
                "unknown seal format (expected av-tee-seal-v3)".into(),
            ));
        }
        if sealed.len() < SEAL_HEADER_LEN {
            return Err(CvmError::SealedBlobRejected(
                "sealed blob too short for header".into(),
            ));
        }

        let tee_type = sealed[SEAL_VERSION_PREFIX.len()];
        if tee_type != TEE_TYPE_SEV_SNP {
            return Err(CvmError::SealedBlobRejected(format!(
                "unexpected tee_type {tee_type:#04x}, expected {TEE_TYPE_SEV_SNP:#04x}"
            )));
        }

        let policy_id = sealed[SEAL_VERSION_PREFIX.len() + 1];
        if policy_id != KEY_POLICY_SNP_VMPL0_VCEK_POLICY_TCB {
            return Err(CvmError::SealedBlobRejected(format!(
                "unsupported key policy {policy_id:#04x}"
            )));
        }

        let floor_start = SEAL_VERSION_PREFIX.len() + 2;
        let tcb_floor = u64::from_le_bytes(
            sealed[floor_start..floor_start + SEAL_TCB_FLOOR_LEN]
                .try_into()
                .expect("8-byte slice"),
        );
        let committed = self.committed_tcb()?;
        if !tcb_at_least(committed, tcb_floor) {
            // A platform condition, not a bad blob: do not regenerate.
            return Err(CvmError::SealError(format!(
                "platform committed TCB {committed:#018x} is below the sealed key's TCB floor \
                 {tcb_floor:#018x}; refusing to unseal"
            )));
        }

        let header = &sealed[..SEAL_HEADER_LEN];
        let nonce_start = floor_start + SEAL_TCB_FLOOR_LEN;
        let nonce_bytes = &sealed[nonce_start..nonce_start + 12];
        let ciphertext = &sealed[SEAL_HEADER_LEN..];

        let key = self.derive_seal_key(tcb_floor)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|e| CvmError::SealError(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce_bytes);
        let aead_payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: header,
        };
        cipher.decrypt(nonce, aead_payload).map_err(|e| {
            CvmError::SealedBlobRejected(format!(
                "decryption failed ({e}): sealed by a different platform, launch or guest policy"
            ))
        })
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
        assert!(matches!(
            cvm.unseal(bad).await,
            Err(CvmError::SealedBlobRejected(_))
        ));
    }

    #[tokio::test]
    async fn seal_header_records_policy_and_tcb_floor() {
        let cvm = SevSnpCvm::mock_with_committed_tcb(MOCK_COMMITTED_TCB);
        let sealed = cvm.seal(b"key").await.unwrap();
        assert!(sealed.starts_with(SEAL_VERSION_PREFIX));
        let p = SEAL_VERSION_PREFIX.len();
        assert_eq!(sealed[p + 1], KEY_POLICY_SNP_VMPL0_VCEK_POLICY_TCB);
        assert_eq!(
            u64::from_le_bytes(sealed[p + 2..p + 10].try_into().unwrap()),
            MOCK_COMMITTED_TCB
        );
    }

    #[tokio::test]
    async fn unseal_rejects_blob_from_measurement_only_policy() {
        // Envelope written by the previous key policy (measurement only).
        let cvm = SevSnpCvm::mock_for_testing();
        let mut legacy = Vec::from(LEGACY_SEAL_VERSION_PREFIX);
        legacy.extend_from_slice(&[TEE_TYPE_SEV_SNP, 0x01]);
        legacy.extend_from_slice(&[0u8; 12]);
        legacy.extend_from_slice(&[0u8; 48]);
        let err = cvm.unseal(&legacy).await.unwrap_err();
        match err {
            CvmError::SealedBlobRejected(msg) => assert!(msg.contains("regenerated"), "{msg}"),
            other => panic!("expected SealedBlobRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unseal_rejects_tampered_tcb_floor() {
        let cvm = SevSnpCvm::mock_for_testing();
        let mut sealed = cvm.seal(b"key").await.unwrap();
        // Lower the recorded floor: the derived key and the AAD both change.
        let p = SEAL_VERSION_PREFIX.len() + 2;
        sealed[p] = sealed[p].wrapping_sub(1);
        assert!(matches!(
            cvm.unseal(&sealed).await,
            Err(CvmError::SealedBlobRejected(_))
        ));
    }

    #[tokio::test]
    async fn unseal_refuses_platform_below_tcb_floor() {
        let sealer = SevSnpCvm::mock_with_committed_tcb(MOCK_COMMITTED_TCB);
        let sealed = sealer.seal(b"key").await.unwrap();
        let mut lower = MOCK_COMMITTED_TCB.to_le_bytes();
        lower[7] -= 1; // microcode rolled back
        let rolled_back = SevSnpCvm::mock_with_committed_tcb(u64::from_le_bytes(lower));
        match rolled_back.unseal(&sealed).await.unwrap_err() {
            CvmError::SealError(msg) => assert!(msg.contains("below the sealed key's TCB floor")),
            other => panic!("expected SealError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unseal_survives_tcb_upgrade_above_floor() {
        let sealer = SevSnpCvm::mock_with_committed_tcb(MOCK_COMMITTED_TCB);
        let sealed = sealer.seal(b"key").await.unwrap();
        let mut higher = MOCK_COMMITTED_TCB.to_le_bytes();
        higher[6] += 1; // SNP firmware upgraded
        let upgraded = SevSnpCvm::mock_with_committed_tcb(u64::from_le_bytes(higher));
        assert_eq!(upgraded.unseal(&sealed).await.unwrap(), b"key");
    }

    #[test]
    fn tcb_comparison_is_per_component() {
        let base = u64::from_le_bytes([3, 0, 0, 0, 0, 0, 8, 115]);
        assert!(tcb_at_least(base, base));
        // Higher microcode does not compensate for a lower boot loader.
        let mixed = u64::from_le_bytes([2, 0, 0, 0, 0, 0, 8, 200]);
        assert!(!tcb_at_least(mixed, base));
        // Reserved bytes are ignored.
        let reserved = u64::from_le_bytes([3, 0, 9, 9, 9, 9, 8, 115]);
        assert!(tcb_at_least(base, reserved));
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
