# Changelog

## Unreleased

### Changed

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
