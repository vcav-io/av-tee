# selkey-tee

The confidential execution lane for [Selkey](https://github.com/vcav-io/selkey). It runs the
Selkey relay protocol inside an AMD SEV-SNP confidential VM.

**Status: EXPERIMENTAL.** Don't rely on it for production confidentiality yet. See
[Caveats](#caveats).

## What it does

The relay runs entirely inside the attested CVM. For each session it computes a transcript hash
(SHA-512 over canonical JSON) that commits to:

- the contract hash
- the prompt template hash
- the initiator and responder submission hashes
- the output hash
- the receipt signing public key
- the asserted model identity (provider/model)

This 64-byte hash goes into the SEV-SNP attestation report's `REPORT_DATA` field, so the
hardware-signed report covers the whole transcript. See `packages/tee-transcript`.

Receipts from a real SEV-SNP CVM carry assurance level `TEE_ATTESTED`. Receipts from the
simulated runtime (development and CI), like those from the software lane, carry `SELF_ASSERTED`.

The relay generates its receipt signing key inside the CVM and seals it to the platform, so an
operator can't inject one. See [docs/key-rotation.md](docs/key-rotation.md).

## Packages

| Package | Description |
|---------|-------------|
| `packages/tee-core` | CVM runtime abstraction, simulated runtime, session crypto |
| `packages/tee-snp` | Real AMD SEV-SNP runtime (`/dev/sev-guest`) |
| `packages/tee-transcript` | Transcript hashing, shared by the relay and the verifier |
| `packages/tee-relay` | The TEE-hardened relay binary |
| `packages/tee-verifier` | TEE receipt verification (attestation, transcript, measurement) |

## Status

- The real SEV-SNP runtime (`tee-snp`) was validated on GCP N2D confidential VMs (AMD Milan),
  where all 20 tests passed (commits `f89dcd3` and `58b58e7`). Later changes, including binding
  model identity into the transcript (v2), haven't been re-validated on hardware in this repo's
  history.
- CI runs on standard runners using the simulated runtime.

## Caveats

- **Clients don't yet verify attestation before sending inputs.** The relay produces attestable
  receipts, but don't treat it as secure against an active man-in-the-middle until clients
  verify attestation first.
- **Builds aren't yet reproducible end to end.** The binary artifact hash is reproducible, but
  the SNP measurement isn't. See [docs/reproducible-builds.md](docs/reproducible-builds.md).
- **No live transparency log yet.** Publishing enclave measurements is still open:
  [#15 Live transparency log service for enclave measurements](https://github.com/vcav-io/selkey-tee/issues/15).
- **The model provider still sees the prompt in plaintext.** The relay has to send it to the
  provider's API. This is an explicit non-goal here. See [docs/threat-model.md](docs/threat-model.md).
- **Anthropic is the only provider in the TEE lane.**

## Running it

- Local runs, Docker, environment variables and deployment checks:
  [docs/deployment.md](docs/deployment.md)
- Reproducible enclave builds: [docs/reproducible-builds.md](docs/reproducible-builds.md)
- Key rotation: [docs/key-rotation.md](docs/key-rotation.md)
- Threat model: [docs/threat-model.md](docs/threat-model.md)
- Build, test and CI checks: [CONTRIBUTING.md](CONTRIBUTING.md)

## How it relates

- [vcav-io/selkey](https://github.com/vcav-io/selkey) is the Selkey protocol and the software
  relay lane.
- [vcav-io/vault-family-core](https://github.com/vcav-io/vault-family-core) provides the shared
  receipt types, execution lane and TEE attestation types. This repo uses it as a git
  dependency.

## Licence

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
