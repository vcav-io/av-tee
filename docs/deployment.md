# Deployment Reference

## Local testing

```bash
# Echo mode (no API key needed)
SELKEY_TEE_ECHO_MODE=true cargo run -p tee-relay

# Relay mode (needs Anthropic API key)
ANTHROPIC_API_KEY=sk-... cargo run -p tee-relay
```

## Docker

```bash
# Build and run with docker-compose
docker compose -f docker-compose.tee.yml up --build

# Or use the build script for reproducible builds
bash scripts/build-enclave.sh
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SELKEY_TEE_ECHO_MODE` | `false` | Enable echo mode (no LLM calls) |
| `SELKEY_TEE_DATA_DIR` | `/tmp/selkey-tee` | Directory for sealed signing key |
| `SELKEY_SIGNING_KEY_HEX` | (auto) | Override signing key (dev only) |
| `ANTHROPIC_API_KEY` | (none) | Anthropic API key for relay mode |
| `SELKEY_MODEL_ID` | `claude-sonnet-4-5-20250929` | Model to use |
| `ANTHROPIC_BASE_URL` | (default) | Custom API base URL |
| `SELKEY_MAX_COMPLETION_TOKENS` | `4096` | Max completion tokens |
| `SELKEY_OPERATOR_ID` | `selkey-tee-relay-dev` | Operator identifier in receipts |
| `SELKEY_SESSION_TTL_SECS` | `600` | Session timeout in seconds |
| `SELKEY_PORT` | `3100` | HTTP port to bind |
| `RUST_LOG` | `info` | Log level filter |

## Verifying a deployment

```bash
# Check enclave identity
curl -s http://localhost:3100/tee/info | jq .

# Expected response includes:
# - tee_type: "Simulated" (or "SEV-SNP" on SEV-SNP hardware)
# - measurement: hex string
# - receipt_signing_pubkey_hex: hex string
```

## Production prerequisites

The relay is a prototype, not yet secure. The items below are necessary before any
production use, but they are not sufficient: even with all of them, the measurement
doesn't cover the relay code and the gaps listed under [Known gaps](#known-gaps) remain.

1. **Real CVM**: Deploy on AMD SEV-SNP or equivalent. `SimulatedCvm` provides
   no hardware isolation. The image built from `Dockerfile.enclave` doesn't enable the
   `snp` feature, so it always runs `SimulatedCvm`.
2. **Measurement verification**: Publish measurements via transparency log or
   static allowlist. Verifiers must check measurements.
3. **Key lifecycle**: The sealed signing key persists across restarts. See
   `docs/key-rotation.md` for rotation procedures.
4. **Network isolation**: The relay binds to `127.0.0.1:$SELKEY_PORT` (default 3100), and
   there's currently no setting to change the bind address. Inside a container that means
   Docker's port mapping (as in `docker-compose.tee.yml`) can't reach it; a reverse proxy
   or other forwarder inside the same network namespace is needed for external access.
5. **Monitoring**: The relay logs metadata (session IDs, error types) but never
   plaintext. All log lines are annotated with `// SAFETY: no plaintext`.

## Known gaps

Beyond the caveats in the README (simulated default image, no measured boot, clients
don't verify attestation before sending inputs, provider-reported model identity), the
current relay and verifier have these gaps. Work on them is in progress.

- **Runtime selection.** A build with the `snp` feature falls back to the simulated
  runtime, with a warning, when SEV-SNP initialisation fails. Check `tee_type` in
  `/tee/info` and in receipts.
- **Contract enforcement.** Contract support is checked when inference starts, after
  both inputs are submitted. Any inline output schema is accepted (no strict-schema
  rules or schema registry), and `entropy_budget_bits`, `entropy_enforcement`,
  `enforcement_policy_hash`, `timing_class`, `session_ttl_secs` and `invite_ttl_secs` are
  accepted but not enforced. No guardian enforcement policy is applied.
- **Access control.** `POST /sessions` and `/tee/info` are unauthenticated, and there are
  no rate or session-count limits.
- **Transcript.** Transcript v2 doesn't bind the relay configuration (provider endpoint,
  model ID, mode), and its encoding is being replaced by a length-prefixed format.
- **Sealing.** On SEV-SNP the sealing key is bound to the launch measurement only, not to
  the guest policy or a TCB floor.
- **Verification.** `tee-verifier` checks the receipt signature against the key named in
  `tee_attestation`, not a pinned key: verify the receipt against a pinned relay key as
  well (for example with `verifier-core`). It doesn't check that `tee_attestation.tee_type`
  matches the quote verifier, it gives a simulated quote the same status as a verified
  hardware quote, and its SEV-SNP report checks (TCB policy, VMPL, guest policy, chip
  binding, certificate validity) are incomplete. Allowlist entries don't record what a measurement covers.
