# Reproducible Builds

## What's reproducible

- **Artifact hash**: SHA-256 of the `tee-relay` binary extracted from the Docker image.
  Given the same source tree, `Cargo.lock`, and `Dockerfile.enclave`, the binary hash
  should be identical across builds with the same toolchain.
- **OCI digest**: The content-addressable hash of the container image layers.

## What's not yet reproducible

- **SNP measurement**: The AMD SEV-SNP `MEASUREMENT` field depends on the full VM image
  layout, firmware, kernel, and initrd — not just the application binary. Reproducible
  SNP measurement requires platform-specific tooling (e.g., `sev-snp-measure`) that is
  not yet integrated.

## How to reproduce

```bash
# Clone at the exact commit
git clone https://github.com/vcav-io/av-tee.git
cd av-tee
git checkout <tag-or-commit>

# Build
bash scripts/build-enclave.sh
# Prints artifact_hash — compare against published value
```

## Allowlist format

The `tee-verifier` crate uses a TOML allowlist mapping known-good measurements
and artifact hashes to human-readable labels:

```toml
[[entries]]
measurement = "abc123..."
artifact_hash = "def456..."
label = "v1.0.0 release"
```

The `artifact_hash` field is optional — it provides an additional cross-check
but is not required for attestation verification.

## Key distinction

| Field | Source | Verifiable today? |
|-------|--------|-------------------|
| `artifact_hash` | `sha256(binary)` | Yes — reproducible build |
| `measurement` | SNP `REPORT_DATA` | No — requires `sev-snp-measure` |
| `user_data` | Transcript hash | Yes — recomputable from receipt |
