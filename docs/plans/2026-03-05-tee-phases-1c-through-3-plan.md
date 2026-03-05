# AgentVault-TEE Phases 1c-3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close Phase 1 gaps, build tee-verifier, add reproducible Docker builds, integrate TEE verification into av-claude, and deliver productization (docs, deployment ref, operator blindness tests).

**Architecture:** Seal/unseal replaces env var key injection. New `tee-verifier` crate provides granular attestation + measurement verification with `TransparencySource` trait. Transcript hashing lives in a separate `tee-transcript` crate (shared by producer and verifier, neither imports the other). Docker-based reproducible builds produce artifact hashes (not SNP measurements). av-claude MCP `verify_receipt` gains TEE receipt introspection (full cryptographic TEE verification requires the Rust tee-verifier).

**Tech Stack:** Rust 1.88.0, ed25519-dalek, sha2, aes-gcm, axum, serde, toml (for allowlist), Docker multi-stage builds, TypeScript (av-claude MCP/client)

---

## Implementation constraints

These are mandatory guardrails. Do not deviate:

1. **Seal/unseal must use random nonce.** `sealed_blob = PREFIX || nonce[12] || ciphertext`. Never use a fixed nonce for AES-GCM, even in simulated mode. Prepend random nonce to ciphertext; unseal reads it back.
2. **tee-verifier must NOT depend on tee-core.** Transcript hashing lives in `tee-transcript` (new crate). Both `tee-core` and `tee-verifier` depend on `tee-transcript`. A verifier must not import the producer's code.
3. **SimulatedCvm must NOT own receipt_signing_pubkey_hex.** Decouple CVM identity from application key. `/tee/info` serves the pubkey from `AppState`, not from `CvmRuntime::identity()`.
4. **Avoid `reqwest` in test code unless necessary.** Prefer calling handler functions directly with mock state. For process-level tests, use `ureq` or hyper's client (already in dep tree).
5. **If quote parsing is not possible, add `user_data_hex` to `TeeAttestation` in VFC.** Without it, tee-verifier cannot check that attestation user_data matches the transcript hash. This is a prerequisite PR.
6. **Test receipts via JSON fixtures, not programmatic construction.** Reduces coupling to receipt-core internal APIs. Fixture receipts go in `tests/fixtures/receipts/`.
7. **Golden fixture must compute-then-assert in one step.** No "FILL_AFTER_FIRST_RUN" placeholders in committed code. Use a bootstrap test that computes and prints, then a separate committed test with the hardcoded value.

---

## Prerequisite: VFC `TeeAttestation.user_data_hex` field

**Repo:** vault-family-core
**Why:** The current `TeeAttestation` has `quote` (opaque blob) but no way for a verifier to extract `user_data` without parsing the platform-specific quote format. Adding `user_data_hex: Option<String>` (the 64-byte transcript hash in hex) lets tee-verifier check `user_data == recomputed_transcript_hash` without quote parsing.

**Change:** Add to `TeeAttestation` in `receipt_v2.rs`:
```rust
/// Platform user_data field from the attestation report (hex).
/// For SEV-SNP this is the 64 bytes bound to the quote via REPORT_DATA.
/// Verifiers recompute the transcript hash and check it matches this field.
#[serde(skip_serializing_if = "Option::is_none")]
pub user_data_hex: Option<String>,
```

Also add `artifact_hash: Option<String>` to the allowlist `MeasurementEntry` (addressed in Task 5A.1).

**Update tee-relay** to populate the new field when building receipts.

**Commit, bump VFC rev pin in av-tee.** This must land before Wave 5A.

---

## Wave 4: Phase 1 Closure

### Task 4.0: Decouple SimulatedCvm from signing pubkey

**Files:**
- Modify: `packages/tee-core/src/types.rs`
- Modify: `packages/tee-core/src/attestation.rs`
- Modify: `packages/tee-relay/src/main.rs`
- Modify: `packages/tee-relay/src/relay.rs`
- Modify: `packages/tee-relay/src/types.rs`
- Modify: `packages/tee-relay/src/handlers.rs`
- Modify: `packages/tee-relay/src/echo.rs`

**Why:** Currently `SimulatedCvm::new(receipt_signing_pubkey_hex)` creates an awkward "bootstrap CVM → load key → reconstruct CVM" dance. CVM identity should be `{tee_type, measurement, platform_version}` only. The signing pubkey is an application concern, not a CVM concern.

**Step 1: Write failing test**

Add to `attestation.rs` tests:

```rust
#[test]
fn simulated_cvm_identity_does_not_include_signing_key() {
    let cvm = SimulatedCvm::new();
    let id = cvm.identity();
    // Identity should contain measurement, tee_type, platform_version only
    assert_eq!(id.tee_type, TeeType::Simulated);
    assert!(!id.measurement.is_empty());
    assert!(!id.platform_version.is_empty());
}
```

**Step 2: Run test — should fail** (SimulatedCvm::new() still requires a String arg)

**Step 3: Remove `receipt_signing_pubkey_hex` from `EnclaveIdentity`**

In `types.rs`:
```rust
pub struct EnclaveIdentity {
    pub tee_type: TeeType,
    pub measurement: String,
    pub platform_version: String,
    // receipt_signing_pubkey_hex REMOVED — app concern, not CVM concern
}
```

Update `SimulatedCvm::new()` to take no arguments.

**Step 4: Move signing pubkey to AppState/TeeInfoResponse**

In `relay.rs`, `AppState` already has `signing_key`. Derive pubkey from it:
```rust
// In handlers serving /tee/info:
let pubkey_hex = hex::encode(state.app.signing_key.verifying_key().as_bytes());
```

Update `TeeInfoResponse::from()` to take `(&EnclaveIdentity, &str)` where the second arg is the pubkey hex. Or construct it manually in the handler.

**Step 5: Update receipt construction**

In `build_tee_receipt_v2()`, use `receipt_core::public_key_to_hex(&state.signing_key.verifying_key())` directly instead of `identity.receipt_signing_pubkey_hex`.

**Step 6: Update echo mode similarly**

**Step 7: Run full test suite**

Run: `cargo test --workspace`
Expected: ALL PASS

**Step 8: Commit**

```
feat: decouple SimulatedCvm from signing pubkey — CVM identity is measurement only
```

---

### Task 4.1: Seal/unseal — random nonce in versioned seal format

**Files:**
- Modify: `packages/tee-core/src/attestation.rs`

**Step 1: Write failing tests**

Add to `attestation.rs` tests:

```rust
#[tokio::test]
async fn seal_uses_versioned_prefix() {
    let cvm = SimulatedCvm::new();
    let data = b"test-key-material";
    let sealed = cvm.seal(data).await.unwrap();
    assert!(sealed.starts_with(b"av-tee-seal-v1"));
}

#[tokio::test]
async fn seal_is_not_deterministic() {
    // Random nonce means same plaintext produces different ciphertext
    let cvm = SimulatedCvm::new();
    let data = b"same-key-material";
    let sealed1 = cvm.seal(data).await.unwrap();
    let sealed2 = cvm.seal(data).await.unwrap();
    assert_ne!(sealed1, sealed2, "seal must use random nonce");
}

#[tokio::test]
async fn unseal_rejects_unversioned_blob() {
    let cvm = SimulatedCvm::new();
    let raw = vec![0u8; 48];
    assert!(cvm.unseal(&raw).await.is_err());
}

#[tokio::test]
async fn versioned_seal_unseal_roundtrip() {
    let cvm = SimulatedCvm::new();
    let data = b"secret key material v2";
    let sealed = cvm.seal(data).await.unwrap();
    let unsealed = cvm.unseal(&sealed).await.unwrap();
    assert_eq!(unsealed, data);
}
```

**Step 2: Run tests — should fail**

**Step 3: Implement random-nonce seal/unseal**

```rust
const SEAL_VERSION_PREFIX: &[u8] = b"av-tee-seal-v1";

// Seal format: PREFIX || random_nonce[12] || ciphertext
async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, CvmError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
        .map_err(|e| CvmError::SealError(e.to_string()))?;

    // Random nonce — critical for AES-GCM security
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
        return Err(CvmError::SealError("sealed blob too short for nonce".into()));
    }
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
        .map_err(|e| CvmError::SealError(e.to_string()))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CvmError::SealError(e.to_string()))
}
```

Add `rand` to tee-core's dependencies if not already present.

**Step 4: Run tests**

Run: `cargo test -p tee-core`
Expected: ALL PASS

**Step 5: Commit**

```
feat: versioned seal with random nonce — PREFIX || nonce[12] || ciphertext
```

---

### Task 4.2: Seal/unseal key lifecycle — wire into main.rs

**Files:**
- Create: `packages/tee-relay/src/key_lifecycle.rs`
- Modify: `packages/tee-relay/src/lib.rs`
- Modify: `packages/tee-relay/src/main.rs`
- Test: `packages/tee-relay/tests/seal_key_lifecycle.rs` (new)

**Step 1: Write failing test**

Create `packages/tee-relay/tests/seal_key_lifecycle.rs`:

```rust
use std::sync::Arc;
use tee_core::SimulatedCvm;
use tee_core::attestation::CvmRuntime;

#[tokio::test]
async fn first_boot_generates_and_seals_key() {
    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    assert!(!sealed_path.exists());

    let cvm = Arc::new(SimulatedCvm::new());
    let signing_key = tee_relay::key_lifecycle::load_or_generate_signing_key(
        cvm.as_ref(), &sealed_path,
    ).await.unwrap();

    assert!(sealed_path.exists());
    let _vk = signing_key.verifying_key(); // key is valid
}

#[tokio::test]
async fn second_boot_recovers_sealed_key() {
    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    let cvm = Arc::new(SimulatedCvm::new());

    let key1 = tee_relay::key_lifecycle::load_or_generate_signing_key(
        cvm.as_ref(), &sealed_path,
    ).await.unwrap();
    let key2 = tee_relay::key_lifecycle::load_or_generate_signing_key(
        cvm.as_ref(), &sealed_path,
    ).await.unwrap();

    assert_eq!(key1.to_bytes(), key2.to_bytes());
}
```

**Step 2: Run test — should fail** (module doesn't exist)

**Step 3: Add tempfile dev-dep** to `packages/tee-relay/Cargo.toml`

**Step 4: Implement `key_lifecycle.rs`**

```rust
use std::path::Path;
use ed25519_dalek::SigningKey;
use tee_core::attestation::CvmRuntime;

pub async fn load_or_generate_signing_key(
    cvm: &dyn CvmRuntime,
    sealed_path: &Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if sealed_path.exists() {
        let sealed_bytes = std::fs::read(sealed_path)?;
        let key_bytes = cvm.unseal(&sealed_bytes).await
            .map_err(|e| format!("failed to unseal signing key: {e}"))?;
        let seed: [u8; 32] = key_bytes.try_into()
            .map_err(|_| "sealed key is not 32 bytes")?;
        Ok(SigningKey::from_bytes(&seed))
    } else {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let seed = signing_key.to_bytes();
        let sealed = cvm.seal(&seed).await
            .map_err(|e| format!("failed to seal signing key: {e}"))?;
        if let Some(parent) = sealed_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(sealed_path, sealed)?;
        Ok(signing_key)
    }
}
```

**Step 5: Export from lib.rs, wire into main.rs**

In `main.rs`, the init order is now clean (no bootstrap CVM needed):

```rust
async fn run_relay_mode() {
    let cvm = Arc::new(SimulatedCvm::new());

    // Load or generate signing key
    let sealed_key_path = std::env::var("AV_TEE_DATA_DIR")
        .unwrap_or_else(|_| "/tmp/av-tee".to_string());
    let sealed_key_path = std::path::PathBuf::from(sealed_key_path).join("sealed_signing_key");

    let signing_key = if cvm.is_real_tee() {
        if std::env::var("AV_SIGNING_KEY_HEX").is_ok() {
            panic!("AV_SIGNING_KEY_HEX must not be set in real TEE mode");
        }
        tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_key_path)
            .await.expect("failed to load/generate sealed signing key")
    } else {
        match std::env::var("AV_SIGNING_KEY_HEX") {
            Ok(hex_str) if hex_str != "0".repeat(64) => {
                let decoded = hex::decode(&hex_str).expect("invalid hex");
                let seed: [u8; 32] = decoded.try_into().expect("must be 32 bytes");
                ed25519_dalek::SigningKey::from_bytes(&seed)
            }
            _ => {
                tracing::info!("No AV_SIGNING_KEY_HEX, using seal/unseal key lifecycle");
                tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_key_path)
                    .await.expect("failed to load/generate sealed signing key")
            }
        }
    };
    // ... rest of setup, CVM already constructed without needing pubkey
}
```

**Step 6: Run full test suite**

Run: `cargo test --workspace`
Expected: ALL PASS

**Step 7: Commit**

```
feat: seal/unseal key lifecycle — replace env var injection
```

---

### Task 4.3: CI plaintext logging lint

**Files:**
- Create: `scripts/loglint.sh`
- Modify: `.github/workflows/ci.yml`

**Design decisions (from review feedback):**
- Annotation-only, no line-number allowfile. Lines require `// SAFETY: no plaintext` or `// LOGLINT: GLOBAL-SAFE` (file-level).
- Lines containing `REDACTED` or using the redacting Debug impls auto-pass.
- Expand beyond logging: `dbg!`, `println!`, `eprintln!`, `panic!` with formatting, `.context()`.

**Step 1: Write loglint.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

# CI lint: detect potentially unsafe logging in session-adjacent code.
# Requires annotation-based opt-out only.

RELAY_SRC="packages/tee-relay/src"

# Modules that handle decrypted data
SENSITIVE_MODULES=(
    "$RELAY_SRC/relay.rs"
    "$RELAY_SRC/session.rs"
    "$RELAY_SRC/handlers.rs"
    "$RELAY_SRC/echo.rs"
    "$RELAY_SRC/error.rs"
)

PATTERNS='tracing::(info|warn|error|debug|trace)!|log::(info|warn|error|debug|trace)!|\.context\s*\(|anyhow!\s*\('
GLOBAL_BAN='dbg!|println!|eprintln!'

EXIT_CODE=0

check_line() {
    local file="$1" lineno="$2" line="$3"
    # Auto-pass: annotation present
    echo "$line" | grep -qE '// SAFETY: no plaintext|// LOGLINT:' && return 0
    # Auto-pass: line contains REDACTED (using redacting Debug impl)
    echo "$line" | grep -q 'REDACTED' && return 0
    # Auto-pass: comment-only line
    echo "$line" | grep -qE '^\s*//' && return 0
    return 1
}

# Check sensitive modules for logging patterns
for file in "${SENSITIVE_MODULES[@]}"; do
    [ -f "$file" ] || continue
    # Check for file-level opt-out
    head -5 "$file" | grep -q '// LOGLINT: GLOBAL-SAFE' && continue

    while IFS=: read -r lineno line; do
        if ! check_line "$file" "$lineno" "$line"; then
            echo "LINT: $file:$lineno — unannotated logging in sensitive module"
            echo "  $line"
            EXIT_CODE=1
        fi
    done < <(grep -nE "$PATTERNS" "$file" || true)
done

# Global: dbg!/println!/eprintln! banned in all non-test source
for file in $(find packages -name '*.rs' -not -path '*/tests/*' -not -path '*/target/*'); do
    while IFS=: read -r lineno line; do
        if ! check_line "$file" "$lineno" "$line"; then
            echo "LINT: $file:$lineno — $GLOBAL_BAN in non-test code"
            echo "  $line"
            EXIT_CODE=1
        fi
    done < <(grep -nE "$GLOBAL_BAN" "$file" || true)
done

[ $EXIT_CODE -eq 0 ] && echo "loglint: PASS"
exit $EXIT_CODE
```

**Step 2: Run locally, annotate existing lines**

Run: `bash scripts/loglint.sh`

For each flagged line, add `// SAFETY: no plaintext` (the line logs metadata only, no user content).

**Step 3: Add to CI**

In `.github/workflows/ci.yml`, after Test:
```yaml
      - name: Plaintext logging lint
        run: bash scripts/loglint.sh
```

**Step 4: Run full CI locally**

Run: `cargo test --workspace && bash scripts/loglint.sh`

**Step 5: Commit**

```
feat: CI plaintext logging lint — annotation-based, no line-number allowfile
```

---

## Wave 5A: tee-verifier crate

### Task 5A.0: Extract tee-transcript crate

**Files:**
- Create: `packages/tee-transcript/Cargo.toml`
- Create: `packages/tee-transcript/src/lib.rs`
- Modify: `packages/tee-core/Cargo.toml` (depend on tee-transcript)
- Modify: `packages/tee-core/src/lib.rs` (re-export or remove transcript module)
- Modify: `packages/tee-core/src/transcript.rs` → delete, replaced by tee-transcript
- Modify: `packages/tee-relay/Cargo.toml` (depend on tee-transcript)
- Modify: `packages/tee-relay/src/relay.rs` (update import)
- Modify: `Cargo.toml` (workspace members)

**Why:** tee-verifier must not depend on tee-core. Both producer (tee-core/tee-relay) and verifier (tee-verifier) need transcript hashing. Extract to shared crate.

**Step 1: Create tee-transcript crate**

`packages/tee-transcript/Cargo.toml`:
```toml
[package]
name = "tee-transcript"
version = "0.1.0"
edition = "2024"

[dependencies]
sha2 = "0.10"
hex = "0.4"
```

`packages/tee-transcript/src/lib.rs`: Move contents of `tee-core/src/transcript.rs` here verbatim, including tests.

**Step 2: Update tee-core**

- `Cargo.toml`: add `tee-transcript = { path = "../tee-transcript" }`
- `src/lib.rs`: replace `pub mod transcript;` with `pub use tee_transcript as transcript;` (or just remove and let callers import tee-transcript directly)
- Delete `src/transcript.rs`

**Step 3: Update tee-relay**

- `Cargo.toml`: add `tee-transcript = { path = "../tee-transcript" }`
- `src/relay.rs`: change `use tee_core::transcript::{...}` to `use tee_transcript::{...}`

**Step 4: Add to workspace members**

**Step 5: Run tests**

Run: `cargo test --workspace`
Expected: ALL PASS

**Step 6: Commit**

```
refactor: extract tee-transcript crate — shared between producer and verifier
```

---

### Task 5A.1: Scaffold tee-verifier crate

**Files:**
- Create: `packages/tee-verifier/Cargo.toml`
- Create: `packages/tee-verifier/src/lib.rs`
- Create: `packages/tee-verifier/src/result.rs`
- Create: `packages/tee-verifier/src/allowlist.rs`
- Create: `packages/tee-verifier/src/verify.rs`
- Create: `packages/tee-verifier/src/identity.rs`
- Modify: `Cargo.toml` (workspace members)

**Key:** Depends on `tee-transcript`, NOT `tee-core`.

`packages/tee-verifier/Cargo.toml`:
```toml
[package]
name = "tee-verifier"
version = "0.1.0"
edition = "2024"

[dependencies]
tee-transcript = { path = "../tee-transcript" }

# VFC types (receipt structures only)
receipt-core = { git = "https://github.com/vcav-io/vault-family-core.git", rev = "UPDATED_REV" }

# Crypto
ed25519-dalek = { version = "2", features = ["rand_core"] }
sha2 = "0.10"

# Serialization
hex = "0.4"
base64 = "0.22"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Error handling
thiserror = "1"
```

**Note: VFC rev must include the `user_data_hex` field from the prerequisite PR.**

Scaffold all modules with types from the design doc. `verify.rs` has a `todo!()` body.

`result.rs`:
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationStatus {
    QuoteUnverified,
    QuoteVerified,
}

#[derive(Debug, Clone)]
pub struct TeeVerificationResult {
    pub measurement_match: Option<super::MeasurementEntry>,
    pub attestation_status: AttestationStatus,
    pub attestation_hash_valid: bool,
    pub transcript_hash_valid: bool,
    pub submission_hashes_present: bool,
    pub receipt_signature_valid: bool,
}

impl TeeVerificationResult {
    pub fn is_valid(&self) -> bool {
        self.measurement_match.is_some()
            && self.attestation_hash_valid
            && self.transcript_hash_valid
            && self.submission_hashes_present
            && self.receipt_signature_valid
    }
}
```

`allowlist.rs` — includes `artifact_hash`:
```rust
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MeasurementEntry {
    pub measurement: String,
    pub build_id: String,
    pub git_rev: String,
    #[serde(default)]
    pub oci_digest: Option<String>,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub toolchain: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}
```

`identity.rs`:
```rust
/// Stable identity of a TEE relay instance.
///
/// | Event           | measurement | receipt_signing_pubkey_hex |
/// |-----------------|-------------|---------------------------|
/// | Key rotation    | same        | changes                   |
/// | Reimage         | changes     | changes                   |
/// | Enclave restart | same        | changes (new sealed key)  |
///
/// Clients pin on `measurement`. Accept any pubkey attested under that measurement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayIdentity {
    pub tee_type: TeeType,
    pub measurement: String,
    pub receipt_signing_pubkey_hex: String,
}
```

**Step 1: Scaffold all files, verify compilation**

Run: `cargo check -p tee-verifier`

**Step 2: Commit**

```
feat: scaffold tee-verifier crate — types, allowlist, identity, verify stub
```

---

### Task 5A.2: Allowlist tests

**Files:**
- Modify: `packages/tee-verifier/src/allowlist.rs`

Add tests: parse TOML, exact match, prefix-no-match, empty allowlist, load from file. See design doc for details — implementation from scaffold should make these pass immediately.

Run: `cargo test -p tee-verifier allowlist`

Commit: `test: allowlist loading, exact matching, and edge cases`

---

### Task 5A.3: Core verification logic

**Files:**
- Modify: `packages/tee-verifier/src/verify.rs`
- Create: `tests/fixtures/receipts/valid_simulated.json`
- Create: `tests/fixtures/receipts/no_tee_attestation.json`

**Approach: fixture-based testing.** Build fixture receipts by:
1. Running the tee-relay echo mode once, capturing a real receipt from the integration test output
2. Or: write a small helper binary/test that builds and serializes a receipt to JSON

**Step 1: Generate fixture receipts**

Add a test in `packages/tee-relay/tests/` that writes a signed receipt to `tests/fixtures/receipts/valid_simulated.json`:

```rust
#[tokio::test]
async fn generate_fixture_receipt() {
    // ... spin up echo/relay, get a receipt, serialize to JSON
    // ... write to tests/fixtures/receipts/valid_simulated.json
    // This test is #[ignore] by default — run manually to regenerate fixtures
}
```

Also create `no_tee_attestation.json` — a standard receipt without TEE fields.

**Step 2: Write verifier tests using fixtures**

In `packages/tee-verifier/src/verify.rs` tests:

```rust
#[test]
fn valid_simulated_receipt_passes() {
    let receipt_json = include_str!("../../tests/fixtures/receipts/valid_simulated.json");
    let receipt: ReceiptV2 = serde_json::from_str(receipt_json).unwrap();
    let measurement = receipt.unsigned.tee_attestation.as_ref().unwrap()
        .measurement.as_ref().unwrap().clone();
    let allowlist = test_allowlist(&measurement);
    let result = verify_tee_receipt(&receipt, &allowlist).unwrap();
    assert!(result.is_valid());
}

#[test]
fn unknown_measurement_fails() {
    let receipt_json = include_str!("../../tests/fixtures/receipts/valid_simulated.json");
    let receipt: ReceiptV2 = serde_json::from_str(receipt_json).unwrap();
    let allowlist = test_allowlist("sha256:wrong");
    let result = verify_tee_receipt(&receipt, &allowlist).unwrap();
    assert!(result.measurement_match.is_none());
    assert!(!result.is_valid());
}

#[test]
fn missing_tee_attestation_errors() {
    let receipt_json = include_str!("../../tests/fixtures/receipts/no_tee_attestation.json");
    let receipt: ReceiptV2 = serde_json::from_str(receipt_json).unwrap();
    let allowlist = test_allowlist("anything");
    assert!(matches!(
        verify_tee_receipt(&receipt, &allowlist),
        Err(VerifyError::MissingTeeAttestation)
    ));
}
```

**Step 3: Implement verify_tee_receipt**

Core logic:

```rust
pub fn verify_tee_receipt(
    receipt: &ReceiptV2,
    allowlist: &dyn TransparencySource,
) -> Result<TeeVerificationResult, VerifyError> {
    let unsigned = &receipt.unsigned;
    let tee_att = unsigned.tee_attestation.as_ref()
        .ok_or(VerifyError::MissingTeeAttestation)?;

    // 1. Verify receipt signature using pubkey from tee_attestation
    let receipt_signature_valid = { /* ed25519 verify via receipt_core::verify_receipt_v2 */ };

    // 2. Verify attestation_hash == sha256(base64_decode(quote))
    let attestation_hash_valid = { /* decode quote, hash, compare */ };

    // 3. Measurement allowlist (exact match)
    let measurement_match = allowlist.is_allowed(
        tee_att.measurement.as_deref().unwrap_or("")
    );

    // 4. Recompute transcript hash, compare to user_data_hex
    let transcript_hash_valid = {
        // Uses tee_transcript::compute_transcript_hash (NOT tee_core)
        // Compare against tee_att.user_data_hex (the new VFC field)
    };

    // 5. Check submission hashes present
    let submission_hashes_present = unsigned.commitments.initiator_submission_hash.is_some()
        && unsigned.commitments.responder_submission_hash.is_some();

    Ok(TeeVerificationResult { /* ... */ })
}
```

**Step 4: Run tests**

Run: `cargo test -p tee-verifier`

**Step 5: Commit**

```
feat: tee-verifier core — attestation hash, transcript hash, measurement allowlist
```

---

## Wave 5B: Reproducible Docker build (parallel with 5A)

### Task 5B.1: Dockerfile.enclave

**Files:**
- Create: `Dockerfile.enclave`

Multi-stage build. Runtime stage uses `debian:bookworm-slim`. Use `cargo build --release -p tee-relay` (not the stub trick with `|| true` — use `cargo fetch` for dep caching instead):

```dockerfile
# --- Build stage ---
FROM rust:1.88.0-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY packages/ packages/
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN cargo build --release -p tee-relay

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home avtee
USER avtee
COPY --from=builder /build/target/release/tee-relay /usr/local/bin/tee-relay
VOLUME ["/var/lib/av-tee"]
ENV AV_TEE_DATA_DIR=/var/lib/av-tee
EXPOSE 3100
ENTRYPOINT ["tee-relay"]
```

Commit: `feat: Dockerfile.enclave — reproducible multi-stage build`

---

### Task 5B.2: Build script

**Files:**
- Create: `scripts/build-enclave.sh`

Extracts `build_id`, `oci_digest`, `artifact_hash`. Prints clear note: "artifact_hash is NOT the SNP measurement."

Commit: `feat: build-enclave.sh — artifact hash extraction`

---

### Task 5B.3: CI workflow

**Files:**
- Create: `.github/workflows/enclave-build.yml`

Triggers on tags (`v*`) and `workflow_dispatch`. Builds image, extracts artifact hash, uploads image as artifact.

Commit: `ci: enclave build workflow — image + artifact hash`

---

### Task 5B.4: Reproducible builds doc

**Files:**
- Create: `docs/reproducible-builds.md`

Document: what's reproducible (artifact hash, OCI digest), what's not yet (SNP measurement), how to reproduce, allowlist format. Explicit statement: "reproducible build inputs are pinned and artifact hash is reproducible. Reproducible SNP measurement requires platform-specific tooling not yet integrated."

Commit: `docs: reproducible builds — artifact hash vs SNP measurement`

---

## Wave 6: Integration

### Task 6.1: TEE receipt introspection in av-claude verify_receipt

**Files (av-claude repo):**
- Modify: `packages/agentvault-client/src/verify-receipt.ts`
- Modify: `packages/agentvault-mcp-server/src/__tests__/verify-receipt.test.ts`

**Scope clarification:** This is TEE receipt **introspection**, not full verification. The TS layer extracts and surfaces `tee_attestation` fields. Full cryptographic verification (measurement allowlist, transcript recomputation, attestation chain) requires the Rust `tee-verifier` crate.

**Step 1: Extend VerifyResult**

```typescript
export interface TeeInfo {
  tee_type: string;
  measurement: string;
  attestation_hash: string;
  receipt_signing_pubkey_hex: string;
  transcript_hash_hex: string;
  note: string;
}

export interface VerifyResult {
  // ... existing fields ...
  tee_info?: TeeInfo;
}
```

**Step 2: Detect and extract in verifyReceipt()**

After commitment verification, if `receipt['tee_attestation']` exists and is an object, populate `tee_info` with extracted fields and note: `"TEE fields present. Full verification requires tee-verifier (Rust)."`

**Step 3: Add test**

**Step 4: Run tests**

Run: `cd packages/agentvault-client && npm test`
Run: `cd packages/agentvault-mcp-server && npm test`

**Step 5: Commit**

```
feat: verify_receipt surfaces tee_attestation info from TEE receipts
```

**Future path note:** For real verification in av-claude, the cleanest path is exposing a small CLI or HTTP endpoint in tee-relay that wraps `tee-verifier`, then having the MCP server shell out or HTTP call to it. Not ideal, but closer to real verification without WASM.

---

### Task 6.2: Key rotation docs

**Files:** `docs/key-rotation.md` (av-tee)

Document: attestation-bound rotation, rotation = restart, multiple concurrent keys, old receipt verifiability, what this doesn't provide (revocation, continuity).

Commit: `docs: key rotation — attestation-bound, rotation = restart`

---

### Task 6.3: Cross-language transcript hash golden fixture

**Files:**
- Create: `tests/fixtures/transcript_golden.json` (av-tee)
- Modify: `packages/tee-transcript/src/lib.rs`

**Step 1: Write bootstrap test** (computes and prints, used once to capture value):

```rust
#[test]
#[ignore] // Run manually: cargo test -p tee-transcript golden_bootstrap -- --ignored --nocapture
fn golden_bootstrap() {
    let inputs = TranscriptInputs { /* fixed test values */ };
    let hash = compute_transcript_hash(&inputs);
    println!("GOLDEN_HASH={}", hex::encode(hash));
}
```

**Step 2: Run bootstrap, capture hash**

Run: `cargo test -p tee-transcript golden_bootstrap -- --ignored --nocapture`

**Step 3: Write committed test with hardcoded value**

```rust
#[test]
fn golden_fixture_parity() {
    let inputs = TranscriptInputs { /* same fixed test values */ };
    let hash = compute_transcript_hash(&inputs);
    assert_eq!(
        hex::encode(hash),
        "ACTUAL_COMPUTED_VALUE_HERE",
        "golden fixture changed — update TS verifier if this changes"
    );
}
```

**Step 4: Write JSON fixture with same inputs + expected hash**

```json
{
  "inputs": { ... },
  "expected_hash_hex": "ACTUAL_COMPUTED_VALUE_HERE"
}
```

**Step 5: Run test**

Run: `cargo test -p tee-transcript golden_fixture`
Expected: PASS

**Step 6: Commit**

```
test: golden transcript hash fixture for cross-language parity
```

---

### Task 6.4: Cross-repo CLAUDE.md notes

**Files:**
- Modify: `CLAUDE.md` (av-tee)
- Modify: `CLAUDE.md` (av-claude)

Add to both:
```
- **tee-verifier** (git dep between repos) — TEE receipt verification. Intended path: published crate or VFC-hosted. Do not let this calcify as a git dep.
```

Commit in each repo.

---

## Wave 7: Productization

### Task 7.1: Documentation — av-claude (execution environments + trust model)

**Files (av-claude):**
- Create: `docs/execution-environments.md`

Content: two-lane framing, trust model table, important limitations (TEE doesn't hide from provider, relay sees plaintext inside enclave), guidance (standard for dev, TEE for sensitive).

Commit: `docs: execution environments — standard vs confidential lane, trust model`

---

### Task 7.2: Documentation — av-tee threat model

**Files (av-tee):**
- Create: `docs/threat-model.md`

Content: what CVM protects (operator, host OS, co-tenants, binary tampering, key injection), what it doesn't (provider, side channels, firmware, DoS, metadata), operator blindness guarantees and limits, simulated mode caveats.

Commit: `docs: TEE threat model — what CVM protects and what it doesn't`

---

### Task 7.3: Operator blindness test harness

**Files (av-tee):**
- Create: `packages/tee-relay/tests/operator_blindness.rs`

**Design (from review feedback):** Pure local test, no network. Call handler/decrypt functions directly with a tracing test subscriber that captures all log output.

```rust
//! Operator blindness test: proves relay software does not emit plaintext
//! via logs, errors, or panics.
//!
//! NOTE: In simulated mode this proves software isolation, not SEV-SNP
//! operator blindness. Still valuable — catches accidental plaintext leaks.

use tracing_subscriber::fmt::TestWriter;

#[tokio::test]
async fn canary_not_in_logs_after_decryption() {
    // 1. Set up tracing subscriber that captures to a buffer
    let (writer, output) = capture_tracing_output();

    // 2. Generate a unique canary UUID
    let canary = uuid::Uuid::new_v4().to_string();

    // 3. Build a valid encrypted payload containing the canary as plaintext
    //    Use tee_transcript + tee_core crypto directly
    let cvm = SimulatedCvm::new();
    let (session_pub, session_secret) = cvm.derive_session_keypair().unwrap();
    // ... encrypt JSON containing canary via tee_core::crypto::encrypt_payload

    // 4. Call the decryption + handler path directly
    //    e.g. decrypt_payload(...) → process → build receipt

    // 5. Force a panic in a subprocess to check panic output (optional)

    // 6. Read all captured log output
    let logs = output.lock().unwrap().clone();

    // 7. THE CRITICAL ASSERTION
    assert!(
        !logs.contains(&canary),
        "OPERATOR BLINDNESS VIOLATION: canary found in logs!\n\
         This means plaintext is leaking through logging.\n\
         Logs: {logs}"
    );
}

// Also test with RUST_BACKTRACE=1 tracing level = trace
```

**Implementation note:** Use `tracing_subscriber::fmt::Layer` with a custom writer that captures to a `Arc<Mutex<String>>`. Or use the `tracing-test` crate if available.

For the panic test variant: spawn a `std::thread` that panics with the canary, verify the custom panic hook suppresses it.

Commit: `test: operator blindness harness — canary-based, no network, captures tracing output`

---

### Task 7.4: Deployment reference

**Files (av-tee):**
- Create: `docker-compose.tee.yml`
- Create: `docs/deployment.md`

**docker-compose.tee.yml defaults to standard relay mode** (not echo). Echo mode requires explicit `AV_TEE_ECHO_MODE=true` override:

```yaml
services:
  tee-relay:
    build:
      context: .
      dockerfile: Dockerfile.enclave
    ports:
      - "3100:3100"
    environment:
      - RUST_LOG=info
      - AV_TEE_DATA_DIR=/var/lib/av-tee
      # Standard relay mode by default. For echo testing:
      # - AV_TEE_ECHO_MODE=true
    volumes:
      - tee-data:/var/lib/av-tee

volumes:
  tee-data:
```

`docs/deployment.md`: local testing, verifying deployment, production prerequisites.

Commit: `docs: deployment reference — docker-compose + production guide`

---

## Summary

| Wave | Tasks | Repo | Key change from v1 plan |
|------|-------|------|------------------------|
| Prereq | VFC `user_data_hex` field | VFC | NEW — enables transcript verification |
| 4 | 4.0-4.3 | av-tee | 4.0 is NEW (decouple CVM); 4.1 uses random nonce; 4.3 annotation-only |
| 5A | 5A.0-5A.3 | av-tee | 5A.0 is NEW (tee-transcript crate); fixture-based tests |
| 5B | 5B.1-5B.4 | av-tee | Cleaner Dockerfile (no stub trick) |
| 6 | 6.1-6.4 | both | 6.1 is "introspection" not "verification"; 6.4 is NEW (CLAUDE.md notes) |
| 7 | 7.1-7.4 | both | 7.3 is pure local (no network); 7.4 defaults to relay mode |

Total: ~21 tasks across 6 waves (including prerequisite).

Dependency: Prereq → Wave 4 → Wave 5A (5B parallel) → Wave 6 → Wave 7
