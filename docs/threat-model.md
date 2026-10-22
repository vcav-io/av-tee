# TEE Threat Model

## What the CVM protects

| Threat | Protection | Mechanism |
|--------|-----------|-----------|
| Operator reading plaintext | CVM memory encryption (not guaranteed yet) | SEV-SNP encrypted VM RAM; doesn't help if the operator can run different guest code, which depends on measured boot covering the relay |
| Host OS tampering | Attestation + measurement | Launch measurement in the attestation report (see note below) |
| Co-tenant side-loading | VM isolation | CVM is a separate VM with own address space |
| Binary tampering | Measurement verification (not yet effective) | Verifiers check measurement against allowlist; the measurement does not yet cover the relay binary |
| Key injection by operator | Seal/unseal lifecycle (not guaranteed yet) | Signing key generated inside CVM, sealed to platform; depends on measured boot covering the relay |

These protections apply only to a real SEV-SNP CVM. The default container image has only the
simulated runtime and starts only with `SELKEY_ALLOW_SIMULATED=1`; an `snp` build refuses to
start if SEV-SNP initialisation fails, unless that variable is set (see the README).

The sealed signing key (SEV-SNP) is bound to the guest policy, the launch measurement and a TCB
floor, so it cannot be unsealed by a guest launched with a different policy or on a platform
whose committed TCB was rolled back below the committed TCB at sealing time. It is still bound to a measurement that doesn't
cover the relay, so other code in a guest with the same firmware measurement could unseal it.

**Note on measurement coverage:** the SNP launch measurement covers what the hypervisor loads
at launch. Without measured boot (kernel, initrd, command line and a verified root filesystem),
it does not cover the relay binary, and on a typical setup running the relay in Docker it most
likely covers the guest firmware only. Until measured boot is in place, a known-good
measurement does not identify the relay code that ran.

## What the CVM does NOT protect

| Threat | Why | Mitigation |
|--------|-----|------------|
| Provider sees plaintext | Relay must send plaintext to LLM API | By design — provider attestation is separate |
| Side-channel attacks | SEV-SNP has known side-channel surface | Platform vendor patches, not application-level |
| Firmware compromise | CVM trusts AMD PSP firmware | Supply chain trust — out of scope |
| Denial of service | Operator controls network/compute | Operational, not confidentiality |
| Metadata leakage | Timing, message sizes, session counts visible | Timing classes (contract field), padding (future) |
| Relay software bugs | CVM protects memory, not logic | Code review, testing, reproducible builds |

## Operator blindness

The relay is designed so that the operator (whoever runs the CVM) cannot
observe session plaintext even though they provision the infrastructure.

**Intended guarantees (with real CVM).** These are not met yet: the operator is trusted for
now. Each depends on measured boot covering the relay (see the note above).
- Operator cannot read RAM (SEV-SNP memory encryption): **not guaranteed yet**, because
  memory encryption doesn't help if the operator can run different guest code
- Operator cannot inject a different binary: **not guaranteed yet**
- Operator cannot inject a signing key (seal/unseal lifecycle): **not guaranteed yet**
- Session keys are per-session ephemeral ECDH (forward secrecy)

**Guarantees (software only, simulated mode):**
- Relay software does not log plaintext (annotation-based lint)
- Panic hook suppresses payload values
- Session keys are zeroized after use

**NOT guaranteed:**
- Operator can observe network traffic metadata (connection times, sizes)
- Operator can deny service (stop the relay, block network)
- A compromised or substituted relay binary could exfiltrate data (measurement does not yet
  detect this)
- Model identity in receipts is provider-reported: the relay records the model ID returned by
  the provider's API (or the configured model ID if the provider omits it), and nothing
  verifies which model ran
- The provider endpoint, requested model ID and mode flags are bound into the transcript
  (v3) through `relay_config_hash`, so a verifier can check which configuration the attested
  transcript was computed with. This doesn't show which code computed it: the measurement on
  GCP N2D covers Google's firmware, not the relay ("relay code not measured")

## Transcript binding assurance levels

The verifier recomputes the transcript hash (v3: SHA-512 over a length-prefixed
encoding of all commitments and the relay configuration hash; v1/v2: SHA-512 over
an interpolated JSON-like string) and compares it to a reference value from the
receipt. `transcript_schema` records which version matched: v3 binds a relay
configuration hash (the caller supplies the configuration, and gets it back to apply
its own policy); v1 and v2 are labelled "code/config unbound" and don't count as
valid when the caller supplied a configuration. The relay configuration is
operator-asserted: on GCP the measurement doesn't cover the relay code, so the
`relay_config` published at `/tee/info` and bound into the transcript is what the
relay says it runs with, not an attested fact ("relay config asserted (not
code-attested)"). The
`TranscriptBinding` field in `TeeVerificationResult` records *which* reference
was used, because the assurance levels differ significantly:

| Binding | Source field | Assurance | When it occurs |
|---------|-------------|-----------|----------------|
| **UserData** | `tee_attestation.user_data_hex` | Hardware-bound — the hash is inside the SEV-SNP attestation report, signed by the platform. Shows the report was requested by code in a CVM with this launch measurement (which doesn't yet cover the relay binary). | Real CVM with attestation support |
| **TranscriptHashFallback** | `tee_attestation.transcript_hash_hex` | Relay-asserted — the hash is correct but set by the relay software, not bound into the attestation. A compromised relay could substitute a different hash without detection. | Simulated mode, or real CVM before `user_data` binding was deployed |
| **None** | *(neither field present)* | Unverifiable — no reference exists to compare against. | Malformed or very old receipts |

### Recommendations for callers

- **Production verifiers** should require `TranscriptBinding::UserData`. Accept
  `TranscriptHashFallback` only during a migration window when older receipts
  are still in circulation.
- **Display/debugging UIs** may show the binding level alongside the
  `transcript_hash_valid` boolean so operators can triage assurance.
- `is_valid()` and `is_valid_sans_quote()` check `transcript_hash_valid` but
  do **not** enforce a minimum binding level — callers must check
  `transcript_binding` themselves if they need hardware-bound assurance.

## Verifier checks

- **Pinned key.** `tee-verifier` checks the receipt signature against the relay key from the
  caller's configuration (`VerifyOptions::pinned_receipt_key`). The key named in
  `tee_attestation.receipt_signing_pubkey_hex` must equal it. Without a pinned key the result
  is `SignatureStatus::ValidUnpinned`, which no `is_valid*` method accepts: a receipt that names
  its own key only shows that it is internally consistent.
- **Platform type.** `tee_attestation.tee_type` must match the quote verifier's platform, so a
  simulated quote can't stand in for an SEV-SNP receipt (or the reverse).
- **Simulated quotes** are reported as `AttestationStatus::QuoteSimulated`, never as
  `QuoteVerified`; `is_valid()` and `is_valid_parsed()` reject them, and
  `is_valid_simulated()` exists for development and tests. A simulated quote in a receipt that
  claims `TEE_ATTESTED` is rejected.
- **SEV-SNP report checks** (when the receipt carries the VCEK): VCEK → ASK → ARK chain against
  the bundled AMD roots; report signature; the report is VCEK-signed (KEY_INFO.SIGNING_KEY = 0,
  chip key not masked) and not DEBUG; VMPL equals the expected VMPL (default 0); MIGRATE_MA is
  rejected by default; SMT is accepted by default (GCP N2D runs with SMT) and can be rejected
  with `ReportPolicy::allow_smt = false`; REPORTED_TCB equals the TCB the VCEK certifies and
  meets the caller's `TcbPolicy` minimums (there is no default: chain verification needs an
  explicit policy, set from AMD's current security bulletins); CHIP_ID is present and equals the VCEK hwID; the VCEK and ASK
  are within their validity windows; and an optional `RevocationCheck` (for example
  `RevokedSerials` from a verified AMD CRL) is consulted. Nothing is fetched from the network.
  Only Milan and Genoa are supported.
- **Measurement allowlist entries** state what they cover (`platform`). A `gcp-snp-ovmf` match
  supports only "genuine GCP SNP VM running Google-endorsed firmware; relay code not measured".

## Contract checks

`POST /sessions` rejects a contract the relay can't run as specified before any input is
submitted: an unsupported prompt template, a relay key pin that isn't this relay's key, a
non-strict output schema (including any `$schema` or `$ref` at any depth, or subschemas under
`enum`/`const` nodes), a schema whose entropy upper
bound exceeds the contract's budget (with `Gate` or `Strict` enforcement), or a field tee-relay
doesn't enforce (`timing_class`, `enforcement_policy_hash`, model profile or constraints,
session or invite TTL). Output is validated as JSON Schema draft 7 whatever the schema
declares, and the validator is built without HTTP or file reference resolution, so a schema
cannot make the relay fetch or read anything. The relay enforces the entropy budget per session only. Accumulating disclosure across
sessions is tracked client-side (the selkey-mcp entropy ledger), not by tee-relay.

## Simulated mode caveats

`SimulatedCvm` provides no hardware isolation. It exercises the same code
paths but with assurance_level `SelfAsserted`. Use simulated mode for:
- Development and testing
- Understanding the protocol flow
- CI/CD (no CVM available)

Do NOT use simulated mode for production confidentiality.
