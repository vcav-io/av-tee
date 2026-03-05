# Key Rotation

## Model: Attestation-Bound Rotation

The TEE relay's Ed25519 signing key is sealed to the CVM. Rotation happens
by restarting the enclave with the sealed key file removed:

1. Delete `/var/lib/av-tee/sealed_signing_key`
2. Restart the relay process
3. A new key is generated, sealed, and used for all subsequent receipts

The new key is automatically attested via the CVM's attestation report.
Verifiers check that the key was attested under a known-good measurement.

## What rotation provides

- **Key compromise recovery**: A new key can be deployed without reimaging
- **Operational flexibility**: Operators can rotate without coordination
- **Attestation continuity**: Same measurement, different key — verifiers
  accept any key attested under the measurement

## What rotation does NOT provide

- **Revocation**: Old keys remain valid for verifying old receipts. There is
  no CRL or OCSP equivalent. Verifiers accept any key ever attested under
  a valid measurement.
- **Key continuity**: The new key has no cryptographic relationship to the
  old key. There is no key derivation chain.
- **Multiple concurrent keys**: Only one key is active at a time. During
  rotation there is a brief window where the relay has no signing key.

## Old receipt verifiability

Receipts signed with the old key remain valid. The `tee_attestation` block
in each receipt records the `receipt_signing_pubkey_hex` that signed it.
Verifiers extract this key and use it for signature verification regardless
of what key the relay currently uses.

## Rotation procedure

```bash
# 1. Stop the relay (optional — prevents mid-session interruption)
docker compose stop tee-relay

# 2. Remove sealed key
docker compose exec tee-relay rm /var/lib/av-tee/sealed_signing_key

# 3. Restart — new key is generated and sealed
docker compose start tee-relay

# 4. Verify new key via /tee/info
curl -s http://localhost:3100/tee/info | jq .receipt_signing_pubkey_hex
```
