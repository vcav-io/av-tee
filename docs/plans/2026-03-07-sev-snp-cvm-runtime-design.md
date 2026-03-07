# Design: SevSnpCvm — Real SEV-SNP CvmRuntime

**Issue:** av-tee #13
**Date:** 2026-03-07

## Architecture

New crate `packages/tee-snp/` depending on `tee-core` (for the `CvmRuntime`
trait) and `sev` (for hardware access). All `sev` types confined to this crate
— `CvmRuntime` returns only `tee-core` types.

```
tee-core (portable)          tee-snp (linux-only)
├── CvmRuntime trait    ←──  ├── SevSnpCvm
├── SimulatedCvm             ├── snp_guest.rs  (sev crate adapter)
├── types.rs                 └── Cargo.toml (depends on tee-core + sev)
└── crypto.rs
```

**Key principle:** depend on `sev` at the hardware edge, but never let `sev`
types leak into the protocol or runtime core.

## SevSnpCvm struct

```rust
pub struct SevSnpCvm {
    dev: File,                           // owns the /dev/sev-guest handle
    identity: OnceCell<EnclaveIdentity>, // lazily populated on first call
}
```

No cached seal key. No eager initialization beyond opening the device and
probing capability.

## Method implementations

| Method | Behavior |
|--------|----------|
| `new()` | Open `/dev/sev-guest`, probe capability. That's it. |
| `identity()` | Lazy: if `OnceCell` empty, request a report (reading measurement), cache `EnclaveIdentity`. Return `&EnclaveIdentity`. |
| `get_attestation(user_data)` | `SNP_GET_EXT_REPORT` with `user_data`. Return raw report bytes (no hard-coded length) + cert blob. Extract measurement + user_data from parsed fields. |
| `derive_session_keypair()` | `StaticSecret::random_from_rng(OsRng)` |
| `seal(data)` | Derive key on-demand via `SNP_GET_DERIVED_KEY` with explicit policy, then AES-256-GCM with versioned envelope. |
| `unseal(sealed)` | Parse envelope header, derive key with matching policy, decrypt. |
| `is_real_tee()` | `true` |

## Seal envelope format (versioned)

```
"av-tee-seal-v2" (14 bytes)   — format version
tee_type (1 byte)              — 0x01 = SevSnp
key_policy_id (1 byte)         — 0x01 = "snp-vmpl0-vcek-v1"
nonce (12 bytes)
ciphertext (variable)          — AES-256-GCM with AAD over the header
```

AEAD associated data = `header[0..28]` (everything before ciphertext). Binds
format version, TEE type, and key derivation policy to the ciphertext.
Forward-compatible: new policy IDs can be added without breaking existing
sealed blobs.

## Key derivation policy

Explicit and versioned in code:

```rust
const KEY_POLICY_SNP_VMPL0_VCEK_V1: u8 = 0x01;

fn derive_seal_key(&self) -> Result<Zeroizing<[u8; 32]>, CvmError> {
    // SNP_GET_DERIVED_KEY with:
    //   root_key: VCEK
    //   vmpl: 0
    //   guest_field_select: measurement only
    snp_guest::derive_key(&self.dev, KeyPolicy {
        root_key: RootKey::Vcek,
        vmpl: 0,
        guest_field_select: GuestFieldSelect::MEASUREMENT,
    })
}
```

Called inside `seal()` and `unseal()` — not cached. The firmware call is fast
enough and avoids stale-key risks.

## snp_guest.rs — adapter module

Narrow internal interface wrapping all `sev` crate usage:

```rust
pub(crate) fn open_device() -> Result<File, CvmError>;
pub(crate) fn probe_capability(dev: &File) -> Result<(), CvmError>;
pub(crate) fn get_ext_report(dev: &File, user_data: &[u8; 64]) -> Result<ExtReportResult, CvmError>;
pub(crate) fn derive_key(dev: &File, policy: KeyPolicy) -> Result<Zeroizing<[u8; 32]>, CvmError>;

pub(crate) struct ExtReportResult {
    pub report_bytes: Vec<u8>,       // raw report, no hard-coded length
    pub cert_blob: Option<Vec<u8>>,  // certificate chain if platform provides it
    pub measurement_hex: String,     // parsed from report
    pub user_data: [u8; 64],         // parsed from report
}
```

## Error mapping

Reuse existing `CvmError` variants with structured context strings:

```
CvmError::AttestationUnavailable("device not found: /dev/sev-guest")
CvmError::AttestationUnavailable("ioctl SNP_GET_EXT_REPORT not supported")
CvmError::AttestationUnavailable("report request failed: <kernel error>")
CvmError::AttestationUnavailable("report parse failed: unexpected length <N>")
CvmError::SealError("derived key request failed: <kernel error>")
```

Preserves distinguishable failure modes without adding new enum variants.

## Relay integration

Real conditional compilation, not `cfg!` branching:

```rust
#[cfg(feature = "snp")]
use tee_snp::SevSnpCvm;

fn build_runtime() -> Result<Box<dyn CvmRuntime>, Box<dyn Error>> {
    #[cfg(feature = "snp")]
    { return Ok(Box::new(SevSnpCvm::new()?)); }

    #[cfg(not(feature = "snp"))]
    { Ok(Box::new(SimulatedCvm::new())) }
}
```

## Testing

| Category | What | Where |
|----------|------|-------|
| **Mock (CI)** | Struct wiring, seal/unseal round-trip, error paths, lazy identity init | `tee-snp/src/` unit tests |
| **Golden report parsing** | Canned known-good reports (standard + extended), verify measurement/user_data extraction | `tee-snp/tests/golden_reports.rs` |
| **Live hardware** (`--features snp-live`) | Device opens, report obtained, claims parsed, seal/unseal round-trips | `tee-snp/tests/snp_live.rs` |

Live tests kept minimal: no cloud-environment-fragile assertions.

## Hardware requirements

- Azure DCasv5 or ECasv5 VM (AMD SEV-SNP)
- Linux kernel with `/dev/sev-guest` support
- GCP C3D confidential VM as second-platform validation target

## Dependencies

- `sev` crate (virtee/sev) — SEV-SNP guest device interface
- `tee-core` (local path) — `CvmRuntime` trait
- `aes-gcm`, `zeroize`, `rand`, `hex` — same as tee-core
- `once_cell` or `std::sync::OnceLock` — lazy identity caching
