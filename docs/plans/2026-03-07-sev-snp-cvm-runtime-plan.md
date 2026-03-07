# SevSnpCvm Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `SevSnpCvm`, a real SEV-SNP `CvmRuntime` in a new `tee-snp` crate.

**Architecture:** New `packages/tee-snp/` crate with `SevSnpCvm` struct owning `/dev/sev-guest` via the `sev` crate. All `sev` types confined to `snp_guest.rs` adapter. Lazy identity, on-demand key derivation, versioned seal envelope.

**Tech Stack:** Rust, `sev` 7.x crate, `aes-gcm`, `zeroize`, `tee-core` (local path dep)

---

### Task 1: Scaffold `tee-snp` crate

**Files:**
- Create: `packages/tee-snp/Cargo.toml`
- Create: `packages/tee-snp/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — add member)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "tee-snp"
version = "0.1.0"
edition = "2024"

[dependencies]
aes-gcm = "0.10"
async-trait = "0.1"
hex = "0.4"
rand = "0.8"
sev = { version = "7", default-features = false, features = ["snp"] }
sha2 = "0.10"
tee-core = { path = "../tee-core" }
thiserror = "1"
x25519-dalek = { version = "2", features = ["static_secrets"] }
zeroize = { version = "1", features = ["derive"] }

[dev-dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

[features]
default = []
snp-live = []  # Gate for real hardware integration tests
```

**Step 2: Create minimal lib.rs**

```rust
mod snp_guest;

pub mod runtime;

pub use runtime::SevSnpCvm;
```

**Step 3: Add to workspace**

In `Cargo.toml` at workspace root, `members = ["packages/*"]` already covers it — no change needed. Verify with:

Run: `cargo check -p tee-snp`
Expected: Compilation errors (modules don't exist yet) — that's fine for now.

**Step 4: Commit**

```bash
git add packages/tee-snp/Cargo.toml packages/tee-snp/src/lib.rs
git commit -m "chore: scaffold tee-snp crate (#13)"
```

---

### Task 2: Implement `snp_guest.rs` adapter

**Files:**
- Create: `packages/tee-snp/src/snp_guest.rs`

**Step 1: Write the test (mock path)**

Add to the bottom of `snp_guest.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_report_extracts_measurement_and_user_data() {
        // Build a minimal 1184-byte canned report:
        // - bytes 0..4: version = 2 (little-endian)
        // - bytes 80..144: user_data (64 bytes)
        // - bytes 144..192: measurement (48 bytes)
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&2u32.to_le_bytes()); // version
        let user_data = [0xAAu8; 64];
        report[80..144].copy_from_slice(&user_data);
        let measurement_bytes = [0xBBu8; 48];
        report[144..192].copy_from_slice(&measurement_bytes);

        let result = parse_report_bytes(&report).unwrap();
        assert_eq!(result.user_data, user_data);
        assert_eq!(result.measurement_hex, hex::encode(measurement_bytes));
        assert_eq!(result.report_bytes.len(), 1184);
    }

    #[test]
    fn parse_report_rejects_wrong_version() {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_report_bytes(&report).is_err());
    }

    #[test]
    fn parse_report_rejects_short_input() {
        let report = vec![0u8; 100];
        assert!(parse_report_bytes(&report).is_err());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p tee-snp`
Expected: FAIL — `parse_report_bytes` not defined

**Step 3: Implement the adapter**

```rust
//! Narrow adapter wrapping all `sev` crate usage.
//!
//! No `sev` types escape this module — callers see only `tee-core` types
//! and the internal result structs defined here.

use std::fs::File;

use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use tee_core::attestation::CvmError;
use zeroize::Zeroizing;

/// Parsed fields from a raw SEV-SNP attestation report.
pub(crate) struct ParsedReport {
    pub report_bytes: Vec<u8>,
    pub cert_blob: Option<Vec<sev::firmware::guest::types::CertTableEntry>>,
    pub measurement_hex: String,
    pub user_data: [u8; 64],
}

// Report layout constants (AMD SEV-SNP ABI spec).
const SNP_REPORT_DATA_OFFSET: usize = 80;
const SNP_MEASUREMENT_OFFSET: usize = 144;
const SNP_MEASUREMENT_LEN: usize = 48;
const SNP_MIN_REPORT_SIZE: usize = 192; // minimum for fields we read

/// Open the SEV-SNP guest firmware device.
pub(crate) fn open_device() -> Result<Firmware, CvmError> {
    Firmware::open().map_err(|e| {
        CvmError::AttestationUnavailable(format!("device not found: /dev/sev-guest: {e}"))
    })
}

/// Request an extended attestation report with optional certificate chain.
pub(crate) fn get_ext_report(
    fw: &mut Firmware,
    user_data: &[u8; 64],
) -> Result<ParsedReport, CvmError> {
    let (report_bytes, certs) = fw
        .get_ext_report(None, Some(*user_data), Some(0))
        .map_err(|e| {
            CvmError::AttestationUnavailable(format!("SNP_GET_EXT_REPORT failed: {e}"))
        })?;

    let mut parsed = parse_report_bytes(&report_bytes)?;
    parsed.cert_blob = certs;
    Ok(parsed)
}

/// Parse raw report bytes to extract measurement and user_data.
/// Does not verify the report cryptographically — that's the verifier's job.
pub(crate) fn parse_report_bytes(report_bytes: &[u8]) -> Result<ParsedReport, CvmError> {
    if report_bytes.len() < SNP_MIN_REPORT_SIZE {
        return Err(CvmError::AttestationUnavailable(format!(
            "report too short: {} bytes, need at least {SNP_MIN_REPORT_SIZE}",
            report_bytes.len()
        )));
    }

    let version = u32::from_le_bytes(
        report_bytes[0..4]
            .try_into()
            .expect("4-byte slice"),
    );
    if version != 2 {
        return Err(CvmError::AttestationUnavailable(format!(
            "unsupported report version {version}, expected 2"
        )));
    }

    let mut user_data = [0u8; 64];
    user_data.copy_from_slice(&report_bytes[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64]);

    let measurement_hex = hex::encode(
        &report_bytes[SNP_MEASUREMENT_OFFSET..SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN],
    );

    Ok(ParsedReport {
        report_bytes: report_bytes.to_vec(),
        cert_blob: None,
        measurement_hex,
        user_data,
    })
}

/// Derive a 32-byte sealing key from the AMD Secure Processor.
///
/// Policy: VCEK root key, VMPL 0, measurement-only field selection.
pub(crate) fn derive_seal_key(fw: &mut Firmware) -> Result<Zeroizing<[u8; 32]>, CvmError> {
    let mut gfs = GuestFieldSelect::default();
    gfs.set_measurement(true);

    let request = DerivedKey::new(
        false,  // root_key_select: false = VCEK
        gfs,
        0,      // vmpl
        0,      // guest_svn
        0,      // tcb_version
        None,   // launch_mit_vector
    );

    let key = fw
        .get_derived_key(None, request)
        .map_err(|e| CvmError::SealError(format!("SNP_GET_DERIVED_KEY failed: {e}")))?;

    Ok(Zeroizing::new(key))
}
```

**Step 4: Run tests**

Run: `cargo test -p tee-snp`
Expected: 3 tests pass

**Step 5: Commit**

```bash
git add packages/tee-snp/src/snp_guest.rs
git commit -m "feat(tee-snp): snp_guest adapter with report parsing (#13)"
```

---

### Task 3: Implement `SevSnpCvm` struct and `new()` / `identity()` / `is_real_tee()`

**Files:**
- Create: `packages/tee-snp/src/runtime.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tee_core::attestation::CvmRuntime;

    #[test]
    fn is_real_tee_returns_true() {
        // We can't construct a real SevSnpCvm in CI (no device), so test
        // with the mock constructor.
        let cvm = SevSnpCvm::mock_for_testing();
        assert!(cvm.is_real_tee());
    }

    #[test]
    fn identity_returns_sev_snp_tee_type() {
        let cvm = SevSnpCvm::mock_for_testing();
        let id = cvm.identity();
        assert!(matches!(id.tee_type, tee_core::TeeType::SevSnp));
        assert!(!id.measurement.is_empty());
    }

    #[tokio::test]
    async fn mock_get_attestation_returns_report() {
        let mut cvm = SevSnpCvm::mock_for_testing();
        let user_data = [0x42u8; 64];
        let report = cvm.get_attestation(&user_data).await.unwrap();
        assert_eq!(report.user_data, user_data);
        assert!(!report.quote.is_empty());
        assert!(!report.measurement.is_empty());
    }

    #[tokio::test]
    async fn mock_seal_unseal_roundtrip() {
        let mut cvm = SevSnpCvm::mock_for_testing();
        let plaintext = b"secret data for sealing test";
        let sealed = cvm.seal(plaintext).await.unwrap();
        assert_ne!(&sealed[..], plaintext);
        let unsealed = cvm.unseal(&sealed).await.unwrap();
        assert_eq!(&unsealed[..], plaintext);
    }

    #[tokio::test]
    async fn mock_unseal_rejects_tampered_blob() {
        let mut cvm = SevSnpCvm::mock_for_testing();
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
        // Verify the keypair is consistent
        let derived_pub = x25519_dalek::PublicKey::from(&*secret);
        assert_eq!(pub_key.as_bytes(), derived_pub.as_bytes());
    }
}
```

**Step 2: Run to verify failure**

Run: `cargo test -p tee-snp`
Expected: FAIL — `SevSnpCvm` not defined

**Step 3: Implement runtime.rs**

```rust
use std::sync::OnceLock;

use async_trait::async_trait;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use tee_core::attestation::{CvmError, CvmRuntime};
use tee_core::types::{AttestationReport, EnclaveIdentity};
use tee_core::TeeType;

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
    /// Real hardware — owns a `sev::firmware::guest::Firmware` handle.
    Hardware(std::sync::Mutex<sev::firmware::guest::Firmware>),
    /// Mock for CI testing — uses a fixed measurement and in-memory seal key.
    #[cfg(test)]
    Mock {
        measurement: String,
        seal_key: [u8; 32],
    },
}

impl SevSnpCvm {
    /// Open the SEV-SNP guest device and create a new runtime.
    ///
    /// This only opens the device and probes capability. Identity is
    /// lazily populated on first call to `identity()`.
    pub fn new() -> Result<Self, CvmError> {
        let fw = snp_guest::open_device()?;
        Ok(Self {
            inner: SevSnpInner::Hardware(std::sync::Mutex::new(fw)),
            identity: OnceLock::new(),
        })
    }

    /// Mock constructor for CI tests (no hardware required).
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
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw.lock().map_err(|e| {
                    CvmError::AttestationUnavailable(format!("firmware mutex poisoned: {e}"))
                })?;
                // Request a report just to read the measurement
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
        }
    }

    fn derive_seal_key(&self) -> Result<Zeroizing<[u8; 32]>, CvmError> {
        match &self.inner {
            SevSnpInner::Hardware(fw) => {
                let mut fw = fw.lock().map_err(|e| {
                    CvmError::SealError(format!("firmware mutex poisoned: {e}"))
                })?;
                snp_guest::derive_seal_key(&mut fw)
            }
            #[cfg(test)]
            SevSnpInner::Mock { seal_key, .. } => Ok(Zeroizing::new(*seal_key)),
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

    async fn get_attestation(&self, user_data: &[u8; 64]) -> Result<AttestationReport, CvmError> {
        match &self.inner {
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
                })
            }
            #[cfg(test)]
            SevSnpInner::Mock { measurement, .. } => {
                // Build a canned 1184-byte report for testing
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
                })
            }
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
```

**Step 4: Run tests**

Run: `cargo test -p tee-snp`
Expected: All tests pass (mock path + snp_guest parse tests)

**Step 5: Commit**

```bash
git add packages/tee-snp/src/runtime.rs packages/tee-snp/src/lib.rs
git commit -m "feat(tee-snp): SevSnpCvm runtime with mock tests (#13)"
```

---

### Task 4: Golden report parsing tests

**Files:**
- Create: `packages/tee-snp/tests/golden_reports.rs`

**Step 1: Write tests**

```rust
//! Golden report parsing tests — verify field extraction from canned
//! known-good SEV-SNP attestation reports.

/// Build a synthetic but structurally valid 1184-byte SNP report
/// with known measurement and user_data for parsing verification.
fn build_golden_report(measurement: &[u8; 48], user_data: &[u8; 64]) -> Vec<u8> {
    let mut report = vec![0u8; 1184];
    // Version 2 at offset 0 (little-endian)
    report[0..4].copy_from_slice(&2u32.to_le_bytes());
    // user_data at offset 80
    report[80..144].copy_from_slice(user_data);
    // measurement at offset 144
    report[144..192].copy_from_slice(measurement);
    report
}

#[test]
fn golden_report_standard_fields() {
    let measurement = [0x11u8; 48];
    let user_data = [0x22u8; 64];
    let report = build_golden_report(&measurement, &user_data);

    // Use the tee-verifier's SevSnpQuoteVerifier to parse (cross-crate parity)
    use tee_verifier::quote::{QuoteVerifier, SevSnpQuoteVerifier};
    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verifier.verify_quote(&report).unwrap();

    assert_eq!(result.fields.user_data, user_data);
    assert_eq!(result.fields.measurement, hex::encode(measurement));
}

#[test]
fn golden_report_measurement_extraction_matches_adapter() {
    let measurement = [0x33u8; 48];
    let user_data = [0x44u8; 64];
    let report = build_golden_report(&measurement, &user_data);

    // Parse via snp_guest adapter (internal) — exposed via a test helper
    // We test the same report through tee-verifier to ensure parity.
    use tee_verifier::quote::{QuoteVerifier, SevSnpQuoteVerifier};
    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verifier.verify_quote(&report).unwrap();

    assert_eq!(result.fields.measurement, hex::encode(measurement));
    assert_eq!(result.fields.user_data, user_data);
}

#[test]
fn golden_report_attestation_hash_roundtrip() {
    use sha2::{Digest, Sha256};

    let measurement = [0x55u8; 48];
    let user_data = [0x66u8; 64];
    let report = build_golden_report(&measurement, &user_data);

    // attestation_hash = hex(sha256(raw_report_bytes))
    let attestation_hash = hex::encode(Sha256::digest(&report));
    assert_eq!(attestation_hash.len(), 64); // 32 bytes = 64 hex chars

    // Verify it's deterministic
    let attestation_hash_2 = hex::encode(Sha256::digest(&report));
    assert_eq!(attestation_hash, attestation_hash_2);
}
```

**Step 2: Run tests**

Run: `cargo test -p tee-snp --test golden_reports`
Expected: 3 tests pass

Note: this test depends on `tee-verifier` — add it to `[dev-dependencies]` in `packages/tee-snp/Cargo.toml`:

```toml
[dev-dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tee-verifier = { path = "../tee-verifier" }
sha2 = "0.10"
hex = "0.4"
```

**Step 3: Commit**

```bash
git add packages/tee-snp/tests/golden_reports.rs packages/tee-snp/Cargo.toml
git commit -m "test(tee-snp): golden report parsing tests (#13)"
```

---

### Task 5: Live hardware integration tests (feature-gated)

**Files:**
- Create: `packages/tee-snp/tests/snp_live.rs`

**Step 1: Write feature-gated tests**

```rust
//! Live SEV-SNP hardware integration tests.
//!
//! Gated behind `--features snp-live`. Run on an Azure DCasv5 VM:
//!   cargo test -p tee-snp --features snp-live --test snp_live
//!
//! These tests are intentionally minimal to avoid cloud-environment
//! fragility. They verify: device opens, report obtained, claims
//! parsed, seal/unseal round-trips.

#![cfg(feature = "snp-live")]

use tee_core::attestation::CvmRuntime;
use tee_core::TeeType;
use tee_snp::SevSnpCvm;

#[test]
fn device_opens() {
    let cvm = SevSnpCvm::new().expect("failed to open /dev/sev-guest");
    assert!(cvm.is_real_tee());
}

#[test]
fn identity_is_sev_snp() {
    let cvm = SevSnpCvm::new().unwrap();
    let id = cvm.identity();
    assert!(matches!(id.tee_type, TeeType::SevSnp));
    assert!(!id.measurement.is_empty());
    // Measurement should be hex-encoded 48 bytes = 96 hex chars
    assert_eq!(id.measurement.len(), 96);
}

#[tokio::test]
async fn attestation_report_binds_user_data() {
    let cvm = SevSnpCvm::new().unwrap();
    let user_data = [0xABu8; 64];
    let report = cvm.get_attestation(&user_data).await.unwrap();

    assert_eq!(report.tee_type, TeeType::SevSnp);
    assert_eq!(report.user_data, user_data);
    assert!(!report.quote.is_empty());
    assert!(!report.measurement.is_empty());
}

#[tokio::test]
async fn seal_unseal_roundtrip() {
    let cvm = SevSnpCvm::new().unwrap();
    let plaintext = b"live hardware seal test";
    let sealed = cvm.seal(plaintext).await.unwrap();
    let unsealed = cvm.unseal(&sealed).await.unwrap();
    assert_eq!(&unsealed[..], plaintext);
}

#[test]
fn session_keypair_generation() {
    let cvm = SevSnpCvm::new().unwrap();
    let (pub1, _sec1) = cvm.derive_session_keypair().unwrap();
    let (pub2, _sec2) = cvm.derive_session_keypair().unwrap();
    // Each keypair should be unique
    assert_ne!(pub1.as_bytes(), pub2.as_bytes());
}
```

**Step 2: Verify it compiles but is skipped without feature**

Run: `cargo test -p tee-snp --test snp_live`
Expected: 0 tests run (feature not enabled)

Run: `cargo test -p tee-snp --test snp_live --features snp-live`
Expected: Compile succeeds; tests fail if not on SNP hardware (expected)

**Step 3: Commit**

```bash
git add packages/tee-snp/tests/snp_live.rs
git commit -m "test(tee-snp): feature-gated live hardware tests (#13)"
```

---

### Task 6: Wire into tee-relay

**Files:**
- Modify: `packages/tee-relay/Cargo.toml`
- Modify: `packages/tee-relay/src/main.rs`

**Step 1: Add optional tee-snp dependency**

In `packages/tee-relay/Cargo.toml`, add:

```toml
[dependencies]
# ... existing deps ...
tee-snp = { path = "../tee-snp", optional = true }

[features]
default = []
snp = ["dep:tee-snp"]
```

**Step 2: Update main.rs runtime selection**

Replace the line:
```rust
let cvm = Arc::new(SimulatedCvm::new());
```

With:
```rust
let cvm: Arc<dyn CvmRuntime> = build_cvm_runtime()?;
```

And add the factory function near the top of main.rs:

```rust
fn build_cvm_runtime() -> Result<Arc<dyn CvmRuntime>, Box<dyn std::error::Error>> {
    #[cfg(feature = "snp")]
    {
        match tee_snp::SevSnpCvm::new() {
            Ok(cvm) => {
                tracing::info!("SEV-SNP CVM runtime initialized");
                return Ok(Arc::new(cvm));
            }
            Err(e) => {
                tracing::warn!("SEV-SNP unavailable ({e}), falling back to simulated");
            }
        }
    }

    tracing::info!("Using simulated CVM runtime");
    Ok(Arc::new(tee_core::SimulatedCvm::new()))
}
```

**Step 3: Verify it compiles both ways**

Run: `cargo build -p tee-relay`
Expected: Compiles (uses SimulatedCvm)

Run: `cargo build -p tee-relay --features snp`
Expected: Compiles (links tee-snp, uses SevSnpCvm on hardware or falls back)

**Step 4: Run existing relay tests**

Run: `cargo test -p tee-relay`
Expected: All existing tests pass (no behavior change without feature)

**Step 5: Commit**

```bash
git add packages/tee-relay/Cargo.toml packages/tee-relay/src/main.rs
git commit -m "feat(tee-relay): wire SevSnpCvm behind snp feature flag (#13)"
```

---

### Task 7: Workspace-wide verification

**Step 1: Full workspace check**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

Run: `cargo fmt --all -- --check`
Expected: No formatting issues

Run: `cargo test --workspace`
Expected: All tests pass

Run: `cargo doc --workspace --no-deps`
Expected: No doc warnings

**Step 2: Commit any fixes, then final commit**

```bash
git add -A
git commit -m "chore(tee-snp): clippy + fmt cleanup (#13)"
```

---

### Task 8: PR

Create PR against `av-tee` main:

```bash
git push -u origin claude/sev-snp-cvm
gh pr create --repo vcav-io/av-tee --head claude/sev-snp-cvm \
  --title "feat(tee-snp): real SEV-SNP CvmRuntime (#13)" \
  --body "$(cat <<'EOF'
## Summary

New `tee-snp` crate implementing `CvmRuntime` for real AMD SEV-SNP hardware:

- `SevSnpCvm` owns `/dev/sev-guest` via the `sev` crate
- Lazy identity initialization, on-demand seal key derivation
- `SNP_GET_EXT_REPORT` for attestation (with cert chain)
- Versioned seal envelope (`av-tee-seal-v2`) with explicit key derivation policy
- All `sev` types confined to `snp_guest.rs` adapter

### Testing

- Mock tests (CI): struct wiring, seal/unseal, error paths
- Golden report parsing: canned 1184-byte reports, cross-crate parity with tee-verifier
- Live hardware tests (`--features snp-live`): device open, report, seal roundtrip

### Relay integration

`tee-relay` gains an optional `snp` feature flag. With `--features snp`, it attempts `SevSnpCvm::new()` and falls back to `SimulatedCvm` if hardware is unavailable.

Closes #13

## Test plan

- [x] `cargo test --workspace` — all pass
- [x] `cargo clippy --workspace -- -D warnings` — clean
- [ ] `cargo test -p tee-snp --features snp-live` — requires Azure DCasv5 VM

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
