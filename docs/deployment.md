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
| `ANTHROPIC_BASE_URL` | (default) | Custom API base URL. Bound into the transcript through `relay_config_hash` and published at `/tee/info`, so it must not contain user info, a query or a fragment (the relay refuses to start) |
| `SELKEY_ENV` | (unset) | Environment label, bound into the transcript through `relay_config_hash` |
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
# - tee_type: "Simulated" (or "SevSnp" in production)
# - measurement: hex string
# - receipt_signing_pubkey_hex: hex string
```

## Production prerequisites

Before using in production:

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
