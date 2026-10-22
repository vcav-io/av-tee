# Changelog

## Unreleased

### Changed

- `tee-verifier` requires a v3 transcript by default. v1 and v2 (legacy) transcript matches are
  still reported in `transcript_schema` but don't count as valid unless the caller sets the new
  `VerifyOptions::allow_legacy_transcripts` and supplies no relay config. This replaces
  `VerifyOptions::require_transcript_v3`, which is removed. Since a v3 transcript verifies only
  against a caller-supplied relay config, verifiers must now pass `relay_config` (or opt in to
  legacy transcripts) for any receipt to be valid.

- TEE lane parity with the Selkey relay:
  - `POST /sessions` checks contract support before any input is submitted (prompt template,
    relay key pin, model profile and constraints, output schema, entropy budget) and answers
    `400` with an error message instead of accepting inputs and aborting at inference.
  - Output schemas must be strict inline schemas (no schema registry in tee-relay); the entropy
    upper bound is computed from the schema, ignoring self-declared bounds.
  - The contract entropy budget is enforced per session (`Gate`/`Strict` reject, `Advisory`
    logs).
  - Contracts setting fields tee-relay doesn't enforce are rejected: `timing_class`,
    `enforcement_policy_hash`, `model_profile_id`/`model_profile_hash`, `model_constraints`,
    `session_ttl_secs`, `invite_ttl_secs`. `metadata` is accepted as descriptive only.
  - Output is validated as JSON Schema draft 7 (with formats) regardless of `$schema`, and
    strict inline schemas may not carry `$schema`. The strict check visits every subschema:
    `enum`/`const` nodes may not carry subschemas, and object/array keywords are allowed only on
    nodes of that type. jsonschema is built without HTTP/file reference resolution.
  - Output is normalised (integral numbers written as floats become integers) before
    validation, and delivered in canonical RFC 8785 form; `output` and `output_hash` in the
    receipt cover the same canonical bytes.
  - Failure receipts for schema-rejected output have status `rejected` and `signal_class`
    `schema_validation_failed` (was `error` / `inference_error`); provider failures are
    `provider_error`.

- `tee-verifier` SEV-SNP report checks (applied when the receipt carries the VCEK):
  - TCB fields are read from the ABI layout (SNP at byte 6, microcode at byte 7 of TCB_VERSION;
    they were read from reserved bytes 4 and 5). `TcbPolicy` minimums now apply to the right
    components, and REPORTED_TCB must equal the TCB in the VCEK's SPL extensions.
  - KEY_INFO is decoded per the ABI: SIGNING_KEY (bits 4:2) must be VCEK and MASK_CHIP_KEY must
    be clear. Bit 0 (AUTHOR_KEY_EN) was previously treated as the signing key flag.
  - New `ReportPolicy`: VMPL (default 0), MIGRATE_MA (rejected by default), SMT (accepted by
    default; configurable), CHIP_ID present and equal to the VCEK hwID (default on).
  - VCEK and ASK validity windows (`VerificationConfig::verification_time`) and an optional
    `RevocationCheck` hook (`RevokedSerials`).
  - Report versions 2 to 5 are accepted (the checked fields have the same offsets).
  - No default TCB policy: `TcbPolicy` and `VerificationConfig` no longer implement `Default`.
    Build `VerificationConfig::new(TcbPolicy::minimums(..))`; `VerifyOptions::snp` is an
    `Option`, and a receipt with a VCEK but no configuration is `QuoteInvalid(TcbPolicyRequired)`.
  - Milan and Genoa only (no Turin).

- TEE runtime hardening:
  - The relay no longer falls back to the simulated runtime silently. A build without `snp`
    starts only with `SELKEY_ALLOW_SIMULATED=1`; an `snp` build exits if SEV-SNP initialisation
    (opening `/dev/sev-guest` and requesting a report) fails, unless that variable is set.
    `Dockerfile.enclave` takes `--build-arg CARGO_FEATURES=snp`; `docker-compose.tee.yml` sets
    `SELKEY_ALLOW_SIMULATED=1` for the default build and documents passing `/dev/sev-guest`.
    CI checks the `snp` build.
  - `SELKEY_BIND_ADDR` sets the listen address (default `127.0.0.1`; an invalid value stops
    startup). The compose file sets `0.0.0.0` in the container and publishes on
    `127.0.0.1:3100`.
  - **Sealing (breaking for existing SEV-SNP deployments):** seal format `av-tee-seal-v3`, key
    policy `0x02`: the sealing key also binds the guest policy and a TCB floor (the committed TCB
    at sealing time, recorded in the blob). Each runtime has its own sealed key file
    (`sealed_signing_key.sev-snp`, `sealed_signing_key` for simulated). Keys sealed as
    `av-tee-seal-v2` are not used; the SEV-SNP runtime generates a new receipt signing key. Clients pinning the old key must re-pin. A rejected
    sealed key no longer stops every restart; platform failures and TCB rollback still stop
    startup.
  - `tee-verifier`: the receipt signature is checked against a pinned relay key
    (`VerifyOptions::pinned_receipt_key`, `verify_tee_receipt_pinned`); without one the status
    is `ValidUnpinned`, which `is_valid*` rejects. A key named in `tee_attestation` that differs
    from the pin is `KeyMismatch`.
  - `tee-verifier`: `SimulatedQuoteVerifier` reports `QuoteSimulated` (never `QuoteVerified`;
    use `is_valid_simulated()` in tests). `QuoteVerifier::tee_type()` is new, and
    `tee_attestation.tee_type` must match it. A simulated quote in a `TEE_ATTESTED` receipt is
    rejected.
  - `tee-verifier`: allowlist entries take `platform` (`gcp-snp-ovmf`, `snp-direct-boot`,
    `simulated`) and `description`; `build_id` and `git_rev` are optional. Unknown fields and
    malformed SEV-SNP measurements are rejected. Populating GCP firmware measurements:
    docs/deployment.md.

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
    configuration. v1 and v2 transcripts are labelled "code/config unbound" and count as
    valid only with `VerifyOptions::allow_legacy_transcripts` and no relay config (see above). A v3 match is labelled "relay config asserted (not code-attested)".
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
