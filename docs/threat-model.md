# TEE Threat Model

## What the CVM protects

| Threat | Protection | Mechanism |
|--------|-----------|-----------|
| Operator reading plaintext | CVM memory encryption | SEV-SNP encrypted VM RAM |
| Host OS tampering | Attestation + measurement | Code identity bound to attestation report |
| Co-tenant side-loading | VM isolation | CVM is a separate VM with own address space |
| Binary tampering | Measurement verification | Verifiers check measurement against allowlist |
| Key injection by operator | Seal/unseal lifecycle | Signing key generated inside CVM, sealed to platform |

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
- Operator cannot inject a different binary (measurement verification)
- Operator cannot inject a signing key (seal/unseal lifecycle)
- Session keys are per-session ephemeral ECDH (forward secrecy)

**Guarantees (software only, simulated mode):**
- Relay software does not log plaintext (annotation-based lint)
- Panic hook suppresses payload values
- Session keys are zeroized after use

**NOT guaranteed:**
- Operator can observe network traffic metadata (connection times, sizes)
- Operator can deny service (stop the relay, block network)
- A compromised relay binary could exfiltrate data (mitigated by measurement)

## Simulated mode caveats

`SimulatedCvm` provides no hardware isolation. It exercises the same code
paths but with assurance_level `SelfAsserted`. Use simulated mode for:
- Development and testing
- Understanding the protocol flow
- CI/CD (no CVM available)

Do NOT use simulated mode for production confidentiality.
