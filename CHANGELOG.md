# Changelog

## Unreleased

### Changed

- Transcript v3 (`av-tee-transcript-v3`). Every field is length-prefixed (big-endian u64 length,
  then the bytes) after its field name, so no value can be read as part of another field
  whatever characters it contains. v1 and v2 interpolated values into a JSON-like string without
  escaping. v3 adds `relay_config_hash`, the SHA-256 of the length-prefixed relay configuration
  (`av-tee-relay-config-v1`): provider id, provider base URL, requested model id, policy lockfile
  hash, model profile allowlist hash, source revision and mode flags.
  - The relay attests v3 transcripts for completed and failed sessions. `GET /tee/info` adds
    `transcript_version`, `relay_config` and `relay_config_hash`.
  - `tee-verifier` verifies v3 transcripts when the caller supplies the relay configuration
    (`verify_tee_receipt_with_options`, `VerifyOptions::relay_config`), and returns the matched
    configuration. v1 and v2 transcripts still verify and are labelled "code/config unbound",
    except when a relay config is supplied (or `require_transcript_v3` is set), where they are
    invalid. A v3 match is labelled "relay config asserted (not code-attested)".
  - `ANTHROPIC_BASE_URL` with user info, a query or a fragment stops startup.
  - Golden vectors, including pairs of inputs with quote and delimiter characters that collide
    under the v2 encoding: `tests/fixtures/transcript_v3_golden.json`.
  - Build-time `SELKEY_TEE_GIT_REV` records the source revision; runtime `SELKEY_ENV` is bound
    as the environment label.

- The relay issues receipt v3 (`3.0.0`) instead of receipt v2, for completed and failed sessions,
  returned as `receipt` (was `receipt_v2`) from `GET /sessions/:id/output`.
  - Encrypted submissions must carry `commitment_nonce` (64 lowercase hex characters, generated
    by the client) next to `role` and `context`. Submissions without one, or with a malformed
    one, are rejected. Input commitments use scheme `SHA256_N32_JCS_V3`.
  - `POST /sessions` computes contract hash v2 from the contract JSON as received and rejects
    contracts with unknown members or other than two participants. The session `contract_hash`
    (and so the submission AAD) is the contract hash v2.
  - Contexts with numbers outside +/-(2^53-1) are rejected.
  - `tee-verifier` accepts v3 and v2 receipts.
  - Receipts carry no `budget_usage` claim (the TEE lane doesn't measure channel capacity).
  - Echo mode requires `commitment_nonce` too and returns `initiator_input_commitment` /
    `responder_input_commitment` (v3 commitments) instead of `initiator_decrypted_sha256_hex` /
    `responder_decrypted_sha256_hex`.
  - All vault-family-core dependencies are pinned to `734b885`.
  - The transcript (`av-tee-transcript-v2`) and the other `av-tee-*` separators are unchanged.
- Renamed AgentVault → Selkey. The repo is now `selkey-tee` (formerly `av-tee`).
  This is a clean break with no compatibility aliases:
  - Environment variables `AV_*` → `SELKEY_*`. For example, `AV_TEE_DATA_DIR` → `SELKEY_TEE_DATA_DIR`,
    `AV_TEE_ECHO_MODE` → `SELKEY_TEE_ECHO_MODE` and `AV_OPERATOR_ID` → `SELKEY_OPERATOR_ID`.
  - Default operator ID `av-tee-relay-dev` → `selkey-tee-relay-dev`.
  - Default data directories `/tmp/av-tee` → `/tmp/selkey-tee` and `/var/lib/av-tee` → `/var/lib/selkey-tee`.
    Existing deployments must move their `sealed_signing_key` or set `SELKEY_TEE_DATA_DIR`.
  - Container image name `av-tee-relay` → `selkey-tee-relay`.
  - Cryptographic domain separators and version tags (`av-tee-seal-v1`/`-v2`, `av-tee:aad:v1:`,
    `av-tee-session-v1:`, `av-tee-transcript-v1`/`-v2`, `av-tee-simulated-v1`, and others) are unchanged,
    so existing sealed keys, transcripts and receipts stay valid.
