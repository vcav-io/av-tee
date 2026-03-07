# Contributing to av-tee

## Prerequisites

- **Rust 1.88.0+** (pinned in `rust-toolchain.toml`)
- **vault-family-core** — this repo depends on [vault-family-core](https://github.com/vcav-io/vault-family-core) as a git dependency. Both repos are public and accessible.

## Building

```bash
cargo build --workspace
cargo test --workspace
```

Note: `tee-snp` tests marked `#[ignore]` require a real AMD SEV-SNP confidential VM (e.g., GCP N2D with AMD Milan). These run in CI on confidential runners, not locally.

## CI Checks

All PRs must pass:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Submitting Changes

1. Fork the repository
2. Create a branch from `main`
3. Make your changes
4. Ensure all CI checks pass locally
5. Open a pull request with a clear description of the change

## What to Contribute

- Bug fixes with a clear reproduction case
- Documentation improvements
- Threat model critique
- Test coverage improvements

## Security

If you discover a security vulnerability, please do **not** open a public issue. Email contact@vcav.io with details.
