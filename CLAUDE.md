# AgentVault-TEE

Confidential execution lane for the AgentVault relay. Runs inside an AMD SEV-SNP
Confidential VM with remote attestation and encrypted ingress.

## Trust boundary

The entire relay process runs inside the attested CVM. "In-enclave" means
"in the attested VM's private memory". Network egress to model providers still
exists — provider sees plaintext (explicit non-goal to solve here).

Phase 1 produces attestable receipts but clients do not yet verify attestation
before encrypting inputs. Do not treat Phase 1 as secure against active MITM
until `tee-verifier` is shipped (Phase 2).

## Build & Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

Requires Rust 1.88.0+ (pinned in `rust-toolchain.toml` to match av-claude).

## Packages

| Package | Type | Description |
|---------|------|-------------|
| `packages/tee-core` | Library | CVM abstraction, crypto, transcript hashing |
| `packages/tee-relay` | Binary | TEE-hardened relay (depends on tee-core + VFC crates) |

## Dependencies

- **vault-family-core** (git dep) — shared receipt types, execution lane, TEE attestation
- tee-relay will depend on tee-core via path dep
