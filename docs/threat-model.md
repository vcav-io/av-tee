# TEE Threat Model

## What the CVM protects

| Threat | Protection | Mechanism |
|--------|-----------|-----------|
| Operator reading plaintext | CVM memory encryption | SEV-SNP encrypted VM RAM |
| Host OS tampering | Attestation + measurement | Launch measurement in the attestation report (see note below) |
| Co-tenant side-loading | VM isolation | CVM is a separate VM with own address space |
| Binary tampering | Measurement verification (not yet effective) | Verifiers check measurement against allowlist; the measurement does not yet cover the relay binary |
| Key injection by operator | Seal/unseal lifecycle | Signing key generated inside CVM, sealed to platform |

These protections apply only to a real SEV-SNP CVM. The shipped container image runs the
simulated runtime (see the README).

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

**Guarantees (with real CVM):**
- Operator cannot read RAM (SEV-SNP memory encryption)
- Operator cannot inject a different binary: **not guaranteed yet**. The measurement does not
  cover the relay binary until measured boot is in place (see the note above)
- Operator cannot inject a signing key (seal/unseal lifecycle)
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
  the provider's API, and nothing verifies which model ran

## Transcript binding assurance levels

The verifier recomputes the transcript hash (SHA-512 over canonical JSON of all
commitments) and compares it to a reference value from the receipt. The
`TranscriptBinding` field in `TeeVerificationResult` records *which* reference
was used, because the assurance levels differ significantly:

| Binding | Source field | Assurance | When it occurs |
|---------|-------------|-----------|----------------|
| **UserData** | `tee_attestation.user_data_hex` | Hardware-bound — the hash is inside the SEV-SNP attestation report, signed by the platform. Proves the transcript was committed by code running in the measured CVM. | Real CVM with attestation support |
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

## Simulated mode caveats

`SimulatedCvm` provides no hardware isolation. It exercises the same code
paths but with assurance_level `SelfAsserted`. Use simulated mode for:
- Development and testing
- Understanding the protocol flow
- CI/CD (no CVM available)

Do NOT use simulated mode for production confidentiality.
