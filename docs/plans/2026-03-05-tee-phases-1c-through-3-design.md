# AgentVault-TEE: Phases 1 closure through 3 — Design

**Date:** 2026-03-05
**Scope:** Close Phase 1 gaps, implement Phase 2 (hardening), Phase 3 (productization)
**Repos:** av-tee (primary), av-claude (integration), VFC (types if needed)

---

## Decisions locked

| Decision | Choice | Rationale |
|----------|--------|-----------|
| tee-verifier location | `av-tee/packages/tee-verifier` | Keeps TEE trust boundary self-contained; av-claude is a consumer |
| Transparency log | Define interface + static allowlist; defer log service | Avoids infrastructure burden; allowlist is the real security boundary |
| Reproducible builds | Docker-based (OCI image) | Natural unit for CVM deployment; matches Azure/GCP confidential containers |
| Documentation | Both repos: av-claude gets lane framing, av-tee gets TEE threat model | Protocol-level framing vs implementation-level detail |
| Key rotation | Attestation-bound (rotation = enclave restart) | Simplest correct approach; attestation already binds pubkey via transcript hash |

---

## Wave 4: Phase 1 closure

### 4.1 Seal/unseal key lifecycle

**Current state:** `tee-relay/main.rs` reads `AV_SIGNING_KEY_HEX` from env.
`SimulatedCvm` has `seal()`/`unseal()` but they aren't wired in.

**Target:**

1. First boot: generate Ed25519 keypair, `cvm.seal(versioned_blob)` to persistent storage
2. Subsequent boots: `cvm.unseal()`, restore key
3. Env var `AV_SIGNING_KEY_HEX` is dev/test fallback only

**Invariants to enforce in code:**

- If `cvm.is_real_tee()` returns true, `AV_SIGNING_KEY_HEX` env var MUST be ignored
  (hard error if set, to prevent accidental injected dev keys in production)
- Seal format is versioned: `b"av-tee-seal-v1" || key_bytes` — allows future seal
  format rotation without breaking existing sealed blobs

**Storage definition:**

- Sealed blob path: `$AV_TEE_DATA_DIR/sealed_signing_key` (configurable, defaults to `/var/lib/av-tee/`)
- Permissions: 0600, owned by relay process user
- On reimage: sealed blob is lost, new key generated, new attestation binds new key
  (this is correct — rotation = restart is the intended model)

### 4.2 CI plaintext logging lint

**Approach:** Deny-by-default in session-adjacent modules, not pattern-matching allowlist.

**Mechanism:**

- `scripts/loglint.sh` scans tee-relay source for:
  - `tracing::{info,warn,error,debug,trace}!` in session/crypto/relay modules
  - `dbg!` anywhere
  - `println!` / `eprintln!` anywhere
  - `panic!` with formatting (beyond simple string literals)
  - `.context(...)` / `anyhow!(...)` where context string references prompt/input/body
- Lines in flagged modules require `// SAFETY: no plaintext` annotation to pass
- Unannotated logging calls in `relay_core.rs`, `session.rs`, `crypto.rs`, `handlers.rs` fail CI
- Allowlist file: `scripts/loglint.allow` with exact `file:line` patterns, kept small and reviewable
- Added as a CI step in `.github/workflows/ci.yml`

---

## Wave 5: Verifier + reproducible builds (parallel)

### 5A: `tee-verifier` crate

**Location:** `av-tee/packages/tee-verifier`

**Core API:**

```rust
pub fn verify_tee_receipt(
    receipt: &ReceiptV2,
    allowlist: &dyn TransparencySource,
) -> Result<TeeVerificationResult>
```

**Verification result type — granular, not pass/fail:**

```rust
pub enum AttestationStatus {
    /// Quote parsed, hash matches, but platform cert chain not available/verified
    QuoteUnverified,
    /// Full SNP chain validated
    QuoteVerified,
}

pub struct TeeVerificationResult {
    pub measurement_match: Option<MeasurementEntry>,  // None = unknown
    pub attestation_status: AttestationStatus,
    pub attestation_hash_valid: bool,
    pub transcript_hash_valid: bool,
    pub submission_hashes_present: bool,
    pub receipt_signature_valid: bool,
}
```

This three-state design (measurement unknown / quote unverified / quote verified)
prevents Phase 2 from collapsing into a boolean that hides important distinctions.

**Verification logic (v1):**

1. Verify attestation blob has known envelope format
2. Verify `attestation_hash == sha256(quote_bytes)`
3. Extract measurement from evidence, match against allowlist (exact match only)
4. Recompute transcript hash from receipt commitments + claims + `receipt_signing_pubkey_hex`
5. Verify attestation user_data equals recomputed transcript hash
   (this is how receipt_signing_pubkey is "bound in attestation" — via transcript hash,
   not by stuffing the key into a vendor-specific field)
6. Verify receipt signature under `receipt_signing_pubkey_hex`

**Measurement allowlist format:**

```toml
[[measurements]]
measurement = "sha256:abcdef..."
build_id = "av-tee-v0.2.0-1"
git_rev = "abc1234"
oci_digest = "sha256:..."
toolchain = "rustc 1.88.0, cargo-lock-hash sha256:..."
timestamp = "2026-03-10T00:00:00Z"
```

- Exact match only (no prefix matching, no wildcards)
- Multiple entries allowed (supports rollback to prior build)
- `oci_digest` and `toolchain` included for human reproducibility, not matched by verifier

**Simulated mode:**

- No runtime flag. Instead, the allowlist must explicitly include entries with
  `tee_type = "Simulated"`. Production allowlists simply omit simulated entries.
- Optional: compile-time `--features simulated-verifier` that relaxes quote parsing
  for test environments

**TransparencySource trait:**

```rust
pub trait TransparencySource {
    fn is_allowed(&self, measurement: &str) -> Result<Option<MeasurementEntry>>;
}
```

- `StaticAllowlist` impl ships now (loads from TOML file)
- Log-backed impl can add inclusion proofs later without changing the interface

**Tests:**

- Valid simulated receipt passes
- Tampered measurement fails (returns `measurement_match: None`)
- Missing TEE fields error
- Allowlist enforcement (simulated entry rejected when not in allowlist)
- Transcript hash recomputation matches tee-core's computation

### 5B: Reproducible Docker build

**Key distinction: build artifact hash vs SNP measurement**

These are different things:

- **Build artifact hash:** `sha256(enclave_relay_binary_bytes)` — reproducible from source
- **OCI digest:** hash of the image manifest — reproducible from Dockerfile
- **SNP measurement:** derived from initial VM state at launch — requires platform tooling

Wave 5B produces the first two. Real SNP measurement is "recorded from attestation
during deployment" until deterministic measurement computation tooling is available.

**Do not call the build artifact hash "measurement" in scripts or docs.**

**Deliverables:**

- `Dockerfile.enclave` — multi-stage, pinned base image, locked toolchain + `Cargo.lock`
- `scripts/build-enclave.sh` — builds image, outputs:
  - `build_id` (git describe)
  - `oci_digest` (image manifest hash)
  - `artifact_hash` (sha256 of the relay binary)
- CI workflow `.github/workflows/enclave-build.yml`:
  - Builds image
  - Computes and logs `build_id`, `oci_digest`, `artifact_hash`
  - Uploads image as artifact
- `docs/reproducible-builds.md`:
  - Exact procedure to reproduce the artifact hash
  - States clearly: "reproducible build inputs are pinned and artifact hash is reproducible.
    Reproducible SNP measurement requires platform-specific tooling not yet integrated."

---

## Wave 5.5: RelayIdentity contract (new, from review feedback)

**Before Wave 6 integration, define the identity contract:**

```rust
pub struct RelayIdentity {
    pub tee_type: TeeType,
    pub measurement: String,
    pub receipt_signing_pubkey_hex: String,
}
```

**Document:**

- What changes on key rotation: `receipt_signing_pubkey_hex` changes, measurement stays same
- What changes on reimage: both change
- How clients should cache and compare identity (pin measurement, accept any pubkey
  attested under that measurement)
- What the verifier reports to calling code (the `TeeVerificationResult` above)

This prevents drift between tee-relay, tee-verifier, and av-claude integration.

Lives in `tee-verifier` as a public type, documented in `docs/relay-identity.md`.

---

## Wave 6: Integration

### 6A: Wire tee-verifier into av-claude

- Add `tee-verifier` as git dep in av-claude
- Extend `verify_receipt` MCP tool: detect TEE receipt -> call `verify_tee_receipt()`
- Structured verification results returned to MCP caller:
  - `lane: "tee"`
  - `measurement_entry: { build_id, git_rev }` (or null if unknown)
  - `attestation_hash_valid: bool`
  - `transcript_hash_valid: bool`
- Allowlist sourcing:
  - Default path: `$AV_TEE_ALLOWLIST_PATH` or `config/tee-allowlist.toml`
  - Log on startup: `"TEE measurement allowlist loaded: N entries"` (no content dumped)
- **Cross-repo dep note:** git dep is acceptable for now. Intended eventual path is
  published crate (or VFC-hosted). Add a note to CLAUDE.md to prevent calcification.

**Tests:**

- MCP verify_receipt dispatches to TEE verifier for TEE receipts
- Rejects receipt with measurement not in allowlist
- Handles missing allowlist gracefully (returns error, doesn't panic)

### 6B: Key rotation documentation

No code. Document in `av-tee/docs/key-rotation.md`:

- Signing key is bound into attestation via transcript hash
- Rotation = enclave restart -> new key -> new attestation
- Verifiers check attestation, not a separate key registry
- Multiple keys can be valid simultaneously (multiple enclave instances)
- Old receipts remain verifiable as long as the receipt contains the attestation evidence

### 6C: Cross-language hash parity CI (from review feedback)

- CI job that runs `compute_transcript_hash` in Rust and any TS recomputation
  (if av-claude has one) against golden fixture inputs
- Asserts identical output
- Prevents the class of bug that only surfaces when verifier and relay disagree

---

## Wave 7: Productization (parallel)

### 7A: Documentation — av-claude

Add to protocol docs:

- "Execution Environments" section: standard vs confidential lane
- Trust model table:

| Property | Standard lane | Confidential lane (TEE) |
|----------|--------------|------------------------|
| Operator sees inputs | Yes | No (encrypted ingress) |
| Model provider sees inputs | Yes | Yes |
| Receipt proves output bounded | Yes | Yes |
| Receipt binds execution environment | No | Yes (measurement + attestation) |
| Verifiable code identity | No | Yes (reproducible build + allowlist) |

- Guidance: "Standard for development and low-sensitivity. TEE for sensitive workloads."
- Explicit: "TEE does not hide prompts from the model provider."

### 7B: Documentation — av-tee

- `docs/threat-model.md`: TEE-specific threat model
  - What the CVM protects against (operator, host OS, co-tenants)
  - What it doesn't protect against (model provider, side channels, compromised firmware)
  - Operator blindness guarantees and their limits
- `docs/deployment.md`: how to run the enclave image
  - Prerequisites (SEV-SNP capable host, attestation service)
  - Configuration
  - Verifying the deployment

### 7C: Operator blindness test harness

**Approach:** Canary-based, not generic "no plaintext" assertions.

1. Generate a unique canary string (UUID) per test run
2. Include canary as part of the encrypted input payload
3. Run tee-relay in simulated mode, process the session
4. Capture ALL output: stdout, stderr, log files, any artifacts directory
5. Run with both `RUST_BACKTRACE=0` and `RUST_BACKTRACE=1`
6. Force a controlled panic during one test variant to check panic output
7. Grep all captured output for the exact canary string
8. Assert: canary MUST NOT appear in any captured output

**Naming:** "software plaintext isolation test" — in simulated mode this proves
the software doesn't emit plaintext, not that SEV-SNP works. That's still valuable.

### 7D: Deployment reference

- `docker-compose.tee.yml`: minimal working example
  - Enclave relay container
  - Config for simulated mode (for local testing)
  - Example encrypted session submission
- README walkthrough: start -> submit -> receive receipt -> verify

---

## Dependency graph

```
Wave 4  (Phase 1 closure: seal/unseal + CI lint)
  |
  v
Wave 5A (tee-verifier)    ||   Wave 5B (Docker build)
  |                              |
  v                              |
Wave 5.5 (RelayIdentity)        |
  |                              |
  v                              |
Wave 6A (av-claude integration)  |
Wave 6B (key rotation docs)     |
Wave 6C (cross-lang hash CI)    |
  |                              |
  v                              v
Wave 7A (av-claude docs)  ||  Wave 7B (av-tee docs)
Wave 7C (blindness tests) ||  Wave 7D (deployment ref)
```

Waves 5A/5B are fully parallel. Wave 5.5 gates Wave 6A. Wave 7 items are all parallel
once Waves 5-6 are complete.

---

## Repo impact summary

| Repo | Waves touched | What changes |
|------|--------------|--------------|
| av-tee | 4, 5A, 5B, 5.5, 6B, 6C, 7B, 7C, 7D | New crate, Docker build, docs, tests |
| av-claude | 6A, 7A | New git dep, MCP tool extension, protocol docs |
| VFC | None expected | Types already exist from Phase 0 |
