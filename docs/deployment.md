# Deployment Reference

## Local testing

A build without the `snp` feature has only the simulated runtime (no hardware isolation), and
starts only with `SELKEY_ALLOW_SIMULATED=1`:

```bash
# Echo mode (no API key needed)
SELKEY_ALLOW_SIMULATED=1 SELKEY_TEE_ECHO_MODE=true cargo run -p tee-relay

# Relay mode (needs Anthropic API key)
SELKEY_ALLOW_SIMULATED=1 ANTHROPIC_API_KEY=sk-... cargo run -p tee-relay
```

## Docker

```bash
# Build and run with docker-compose (simulated runtime, published on 127.0.0.1:3100).
# Relay mode needs ANTHROPIC_API_KEY in the host environment; compose passes it through.
ANTHROPIC_API_KEY=sk-... docker compose -f docker-compose.tee.yml up --build

# Or use the build script for reproducible builds
bash scripts/build-enclave.sh

# SEV-SNP build
CARGO_FEATURES=snp bash scripts/build-enclave.sh
```

The compose file sets `SELKEY_BIND_ADDR=0.0.0.0` inside the container and publishes the port
on the host's loopback only (`127.0.0.1:3100:3100`). With plain `docker run`, set
`SELKEY_BIND_ADDR=0.0.0.0` and publish with `-p 127.0.0.1:3100:3100`.

## SEV-SNP runtime

Build with the `snp` feature (`--build-arg CARGO_FEATURES=snp`, or
`cargo build --release -p tee-relay --features snp`) and run on an SEV-SNP guest:

- Pass the guest device: `--device /dev/sev-guest` (compose: uncomment `devices:` and remove
  `SELKEY_ALLOW_SIMULATED`). The image runs as the non-root user `selkeytee`, which needs
  read/write access to the device (for example a udev rule or `--group-add` with the device's
  group).
- At startup the relay opens `/dev/sev-guest` and requests an attestation report. If that fails,
  it logs the reason and **exits** (fail closed). It falls back to the simulated runtime only if
  `SELKEY_ALLOW_SIMULATED=1` is set, and then logs that it is running simulated. Receipts from
  the simulated runtime are `SELF_ASSERTED`, `/tee/info` reports `tee_type` `Simulated`, and the
  relay configuration bound into the transcript has `simulated: true`.

## Sealed signing key

On first start the relay generates its receipt signing key and seals it to the platform in
`$SELKEY_TEE_DATA_DIR`, in a file per runtime: `sealed_signing_key.sev-snp` for SEV-SNP and
`sealed_signing_key` for the simulated runtime, so a simulated fallback never touches the
SEV-SNP key. On SEV-SNP the sealing key (format `av-tee-seal-v3`,
key policy `0x02`) is derived from the VCEK at VMPL 0 with the **guest policy**, the **launch
measurement** and a **TCB floor** mixed in. The floor is the platform's committed TCB at
sealing time and is recorded in the blob, so:

- a guest launched with a different policy (for example with debugging or a migration agent
  allowed) or a different measurement cannot unseal the key;
- a platform whose committed TCB was rolled back below the committed TCB at sealing time (the
  floor) cannot unseal it (the relay exits with an
  error naming the TCB floor; it does not generate a new key);
- TCB upgrades above the floor keep the key.

If the sealed key exists but this CVM rejects it (older seal format or key policy, different
platform, launch or guest policy, or a damaged file), the relay by default moves the file
aside as `<file>.rejected-<unix time>` (it is never deleted), generates and seals a
new key, and logs an error with the new `receipt_signing_pubkey_hex`. It does not restart in a
loop. Set `SELKEY_SEAL_STRICT=1` to exit instead and leave the file in place. Device or
firmware failures always stop startup and never trigger a new key.

### Migration from `av-tee-seal-v2`

Keys sealed by earlier versions (`av-tee-seal-v2`, key policy `0x01`: measurement only) cannot
be unsealed under the new policy. On the first start after upgrading:

1. The SEV-SNP runtime now uses `sealed_signing_key.sev-snp`, so it generates and seals a new
   receipt signing key there and leaves the old `sealed_signing_key` untouched (keep or delete it
   once no receipt signed with it needs checking).
2. The receipt signing key changes. Don't take the new key from `GET /tee/info` alone: that
   endpoint is unauthenticated. Take it from a receipt issued after the restart whose attestation
   verifies with `is_valid()` when the key named in its `tee_attestation` is pinned
   (chain-verified quote, DEBUG off, allowlisted measurement, v3 transcript binding the key),
   and compare that key with
   the key in the relay's startup log. Then update every client and verifier that pins it (for
   example `relay_verifying_key_hex` in contracts and `VerifyOptions::pinned_receipt_key`).
   While the measurement doesn't cover the relay code, this shows the key is held in a genuine
   SNP VM, not which code holds it.
3. Receipts signed with the old key stay verifiable with the old key.

The simulated runtime's seal format (`av-tee-seal-v1`) is unchanged.

## Measurement allowlist (GCP)

On GCP Confidential VMs (N2D, SEV-SNP) the launch measurement covers Google's OVMF firmware
and the VM's vCPU count, not the kernel, the container or the relay. An allowlist entry for
it uses `platform = "gcp-snp-ovmf"`, and a match supports only the claim
"genuine GCP SNP VM running Google-endorsed firmware; relay code not measured".

Google publishes a signed endorsement for each firmware build it deploys, listing the
SEV-SNP measurement for each vCPU count. To populate the allowlist (see Google's
"Verify Confidential VM firmware" documentation for the current commands):

1. Install Google's `gcetcbendorsement` tool (from `github.com/google/gce-tcb-verifier`).
2. On a VM of the type you deploy, read an attestation report (e.g. with `go-sev-guest`'s
   `attest` tool) and take its `MEASUREMENT`; or obtain the firmware digest from a report.
3. Download the endorsement for that firmware from Google's `gce_tcb_integrity` bucket,
   verify its signature with `gcetcbendorsement verify`, and list its SEV-SNP measurements with
   `gcetcbendorsement inspect`.
4. Add one entry per vCPU count you deploy, recording the endorsement in `description`:

```toml
[[entries]]
measurement = "<96 lowercase hex characters>"
platform = "gcp-snp-ovmf"
description = "Google OVMF endorsement <digest>, 2 vCPUs (n2d-standard-2)"
```

Repeat when Google rolls out new firmware. `tests/fixtures/gcp_ovmf_allowlist.example.toml` shows
the format with placeholder values. The allowlist parser rejects unknown fields and SEV-SNP
entries whose measurement isn't 48 bytes of lowercase hex. Fetching endorsements is a manual,
networked step; nothing in this repo fetches them.

## Verifying receipts

Use `tee_verifier::verify_tee_receipt_pinned` (or `VerifyOptions::pinned_receipt_key`) with the
relay key from your configuration. Without a pinned key the signature status is
`ValidUnpinned` and no `is_valid*` method accepts the result. `tee_attestation.tee_type` must
match the quote verifier's platform, and a simulated quote is reported as `QuoteSimulated`,
never as verified. Parse v3 receipts with `receipt_core::parse_receipt_v3_strict` before passing
them to `TeeReceipt::V3`.

For SEV-SNP receipts, set `VerifyOptions::snp` to
`VerificationConfig::new(tcb_policy)`. Without it, a receipt that carries a VCEK is reported as
`QuoteInvalid(TcbPolicyRequired)`; there is no default TCB policy.

- `tcb_policy`: `TcbPolicy::minimums(boot_loader, tee, snp, microcode)` with floors from AMD's
  current security bulletins for the product family you run on. (`TcbPolicy::reject_all_zero()`
  accepts any non-zero TCB and is not a floor.)
- `report_policy`: expected VMPL (default 0), whether SMT is acceptable (default yes, as on GCP
  N2D), whether a migration agent is acceptable (default no), and whether CHIP_ID must match the
  VCEK (default yes).
- `revocation`: optional. AMD publishes a CRL per product family at
  `https://kdsintf.amd.com/vcek/v1/{Milan,Genoa}/crl`. Fetch it out of band, verify it is signed
  by the ARK, and pass the revoked serial numbers as `RevokedSerials`.
- `verification_time`: the time the VCEK and ASK must be valid at (default: now).

Only AMD Milan and Genoa are supported. Turin (different TCB layout and hwID length, no bundled
roots) is rejected.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SELKEY_TEE_ECHO_MODE` | `false` | Enable echo mode (no LLM calls) |
| `SELKEY_TEE_DATA_DIR` | `/tmp/selkey-tee` | Directory for sealed signing key |
| `SELKEY_SIGNING_KEY_HEX` | (auto) | Override signing key (dev only) |
| `ANTHROPIC_API_KEY` | (none) | Anthropic API key for relay mode |
| `SELKEY_MODEL_ID` | `claude-sonnet-4-5-20250929` | Model to use |
| `ANTHROPIC_BASE_URL` | (default) | Custom API base URL. Bound into the transcript through `relay_config_hash` and published at `/tee/info`, so it must not contain user info, a query or a fragment (the relay refuses to start). The full URL, including its path, is public: don't put secrets in the path |
| `SELKEY_ENV` | (unset) | Environment label, bound into the transcript through `relay_config_hash` |
| `SELKEY_MAX_COMPLETION_TOKENS` | `4096` | Max completion tokens |
| `SELKEY_OPERATOR_ID` | `selkey-tee-relay-dev` | Operator identifier in receipts |
| `SELKEY_SESSION_TTL_SECS` | `600` | Session timeout in seconds |
| `SELKEY_PORT` | `3100` | HTTP port to bind |
| `SELKEY_BIND_ADDR` | `127.0.0.1` | IP address to listen on. Set `0.0.0.0` inside a container and publish the port on loopback. An invalid value stops startup |
| `SELKEY_ALLOW_SIMULATED` | (unset) | `1` permits the simulated runtime (no hardware isolation). Without it the relay refuses to start unless SEV-SNP initialises |
| `SELKEY_SEAL_STRICT` | (unset) | `1` makes a sealed key this CVM rejects stop startup, instead of moving it aside and generating a new key |
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

1. **Real CVM**: Deploy on AMD SEV-SNP with an `snp` build (see above). `SimulatedCvm` provides
   no hardware isolation. The default image built from `Dockerfile.enclave` doesn't enable the
   `snp` feature, so it runs only the simulated runtime, and only with
   `SELKEY_ALLOW_SIMULATED=1`.
2. **Measurement verification**: Publish measurements via transparency log or
   static allowlist. Verifiers must check measurements.
3. **Key lifecycle**: The sealed signing key persists across restarts. See
   `docs/key-rotation.md` for rotation procedures.
4. **Network isolation**: The relay binds to `$SELKEY_BIND_ADDR:$SELKEY_PORT` (default
   `127.0.0.1:3100`). `/tee/info` and `POST /sessions` are unauthenticated, so publish the port
   on loopback or behind an authenticating proxy.
5. **Monitoring**: The relay logs metadata (session IDs, error types) but never
   plaintext. All log lines are annotated with `// SAFETY: no plaintext`.

## Known gaps

Beyond the caveats in the README (simulated default image, provider-reported model identity),
the current relay and verifier have these gaps:

- **Measurement doesn't cover the relay code.** There's no measured boot. On GCP N2D the SNP
  launch measurement covers Google's firmware, so a receipt supports only "genuine GCP SNP VM;
  relay code not measured", and the sealed key is bound to a measurement other guest code
  shares.
- **Relay configuration is operator-asserted.** The `relay_config` published at `/tee/info`
  and bound into transcript v3 is what the relay states it runs with, not an attested fact.
- **No client input path.** Selkey clients don't yet encrypt inputs to the TEE lane or verify
  its attestation before sending them.
- **Relay key trust.** There is no trust root for the receipt signing key beyond the key the
  verifier pins. `/tee/info` is unauthenticated, so take a new key from a verified receipt (see
  [Migration from `av-tee-seal-v2`](#migration-from-av-tee-seal-v2)).
- **Access control.** `POST /sessions` and `/tee/info` are unauthenticated, and there are no
  rate or session-count limits.
- **Entropy is per session only.** The relay doesn't accumulate disclosure across sessions;
  there is no cross-session ledger in the TEE lane.
- **Contract coverage.** Fields tee-relay doesn't enforce (`timing_class`,
  `enforcement_policy_hash`, model profile or constraints, session or invite TTL) are rejected
  at `POST /sessions` rather than enforced, there is no schema registry, and Anthropic is the
  only provider.
- **Platforms.** Only AMD Milan and Genoa are supported by the SEV-SNP report checks; Turin is
  rejected.
- **No live transparency log** for measurements
  ([#15](https://github.com/vcav-io/selkey-tee/issues/15)).
