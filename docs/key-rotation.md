# Key Rotation

## Model: Attestation-Bound Rotation

The TEE relay's Ed25519 signing key is sealed to the CVM. Rotation happens
by restarting the enclave with the sealed key file removed:

1. Move `$SELKEY_TEE_DATA_DIR/sealed_signing_key.sev-snp` aside (`sealed_signing_key` for the
   simulated runtime; the data directory is `/var/lib/selkey-tee` in `docker-compose.tee.yml`)
2. Restart the relay process
3. A new key is generated, sealed, and used for all subsequent receipts

The new key is automatically attested via the CVM's attestation report.
Verifiers check that the key was attested under a known-good measurement.

**Caveat:** until measured boot ships, the launch measurement doesn't cover the
relay binary, so a key attested under a known-good measurement doesn't identify
the relay code that holds it. Until then, verifiers should pin the relay key
they trust rather than accept any key attested under a measurement.

Rotation also happens automatically when the sealed key exists but the CVM rejects it (for
example after an upgrade changed the sealing key policy): the old file is moved aside and a new
key is generated, unless `SELKEY_SEAL_STRICT=1`. See "Sealed signing key" in
[deployment.md](deployment.md#sealed-signing-key).

## What rotation provides

- **Key compromise recovery**: A new key can be deployed without reimaging
- **Operational flexibility**: Operators can rotate without coordination
- **Attestation continuity**: Same measurement, different key — once the
  measurement covers the relay, verifiers can accept any key attested under it
  (until then, pin the key; see the caveat above)

## What rotation does NOT provide

- **Revocation**: Old keys remain valid for verifying old receipts. There is
  no CRL or OCSP equivalent. A verifier that accepts attested keys accepts any
  key ever attested under a valid measurement.
- **Key continuity**: The new key has no cryptographic relationship to the
  old key. There is no key derivation chain.
- **Multiple concurrent keys**: Only one key is active at a time. During
  rotation there is a brief window where the relay has no signing key.

## Old receipt verifiability

Receipts signed with the old key remain valid. The `tee_attestation` block
in each receipt records the `receipt_signing_pubkey_hex` that signed it.
A verifier can use this key for signature verification, regardless of what key
the relay currently uses, only after it has verified the attestation for it and
it matches a relay key the verifier trusts (see the caveat above).

## Rotation procedure

```bash
# 0. Record the current public key (old receipts verify with the public key alone)
curl -s http://localhost:3100/tee/info | jq .receipt_signing_pubkey_hex

# 1. Stop the relay (open sessions are lost)
docker compose -f docker-compose.tee.yml stop tee-relay

# 2. Move the sealed key aside in the data volume. `exec` needs a running
#    container, so use a one-off container on the same volume. On the simulated
#    runtime the file is `sealed_signing_key` (no suffix).
docker compose -f docker-compose.tee.yml run --rm --no-deps --entrypoint mv tee-relay \
  /var/lib/selkey-tee/sealed_signing_key.sev-snp /var/lib/selkey-tee/sealed_signing_key.sev-snp.retired

# 3. Restart — new key is generated and sealed
docker compose -f docker-compose.tee.yml start tee-relay

# 4. Verify new key via /tee/info
curl -s http://localhost:3100/tee/info | jq .receipt_signing_pubkey_hex
```

Once the new key is confirmed, delete the `.retired` file: verifying old
receipts needs only the recorded public key, and the retired blob can still be unsealed
by the same measurement (with the simulated runtime it is effectively the plaintext key).
Delete it promptly after a suspected compromise.
