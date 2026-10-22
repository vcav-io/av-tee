# Reproducible Builds

## What's reproducible

- **Artifact hash**: SHA-256 of the `tee-relay` binary extracted from the Docker image.
  Given the same source tree, `Cargo.lock`, and `Dockerfile.enclave`, the binary hash
  should be identical across builds with the same toolchain.
- **OCI digest**: The content-addressable hash of the container image layers.

## What's not yet reproducible

- **SNP measurement**: The AMD SEV-SNP `MEASUREMENT` field is the launch measurement of
  what the hypervisor loads into the guest at launch. It depends on the platform's VM image
  layout, not on the application binary. There's no measured boot yet, so on GCP N2D with the
  relay running in Docker it most likely covers the guest firmware only, not the kernel, the
  container image or the `tee-relay` binary. Reproducing it requires platform-specific tooling
  (e.g., `sev-snp-measure`) that is not yet integrated.

The reproducible `artifact_hash` therefore isn't bound to the attestation report today: a
matching measurement doesn't show that this binary ran.

## How to reproduce

```bash
# Clone at the exact commit
git clone https://github.com/vcav-io/selkey-tee.git
cd selkey-tee
git checkout <tag-or-commit>

# Build
bash scripts/build-enclave.sh
# Prints artifact_hash — compare against published value
```

## Allowlist format

The `tee-verifier` crate uses a TOML allowlist (`StaticAllowlist::from_toml`) mapping
known-good measurements to the build they came from:

```toml
[[entries]]
measurement = "<SEV-SNP MEASUREMENT, 96 lowercase hex characters>"
build_id = "v1.0.0"
git_rev = "<full git commit>"
artifact_hash = "<sha256 of the tee-relay binary>"
```

`measurement`, `build_id` and `git_rev` are required. `artifact_hash`, `oci_digest`,
`toolchain` and `timestamp` are optional. `artifact_hash` is recorded for reference: the
verifier doesn't compare it with anything, because the measurement doesn't cover the
binary (see above).

## Key distinction

| Field | Source | Verifiable today? |
|-------|--------|-------------------|
| `artifact_hash` | `sha256(binary)` | Yes — reproducible build |
| `measurement` | SNP report `MEASUREMENT` (launch measurement) | No — requires `sev-snp-measure`, and doesn't yet cover the relay binary |
| `user_data` | SNP report `REPORT_DATA` (transcript hash) | Yes — recomputable from receipt |
