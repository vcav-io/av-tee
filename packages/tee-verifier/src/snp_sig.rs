use ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};

use crate::quote::QuoteVerifyError;

/// SEV-SNP attestation report layout constants (AMD SEV-SNP ABI spec rev 1.55+).
///
/// Report structure (1184 bytes total):
///   0..4     version (u32)
///   4..8     guest_svn (u32)
///   8..16    policy (u64)        — bit 19 = DEBUG
///  52..56    signature_algo (u32) — 1 = ECDSA P-384/SHA-384
///  72..76    flags (u32)         — bit 0 = SIGNING_KEY (0=VCEK, 1=VLEK)
/// 672..1184  signature structure: r[72] || s[72] || reserved[368]
const SIGNED_REGION_END: usize = 672;
const SIG_ALGO_OFFSET: usize = 52;
const SIG_R_OFFSET: usize = 672;
const SIG_S_OFFSET: usize = 744;
const SIG_COMPONENT_LEN: usize = 72;
const POLICY_OFFSET: usize = 8;
const FLAGS_OFFSET: usize = 72;

/// Expected ECDSA P-384 with SHA-384 algorithm identifier.
const ECDSA_P384_SHA384: u32 = 1;

/// Verify the ECDSA P-384 signature on an SEV-SNP attestation report.
///
/// The signed region is bytes 0..672 of the 1184-byte report.
/// The signature (r, s) is stored in little-endian at offsets 672 and 744,
/// each zero-padded to 72 bytes. We reverse byte order and trim to 48 bytes
/// (P-384 field element size) before constructing the signature.
///
/// The signature algorithm field is at offset 52 (in the report header),
/// NOT inside the signature structure.
pub fn verify_report_signature(
    report_bytes: &[u8],
    vcek_pubkey: &VerifyingKey,
) -> Result<(), QuoteVerifyError> {
    if report_bytes.len() < SIG_S_OFFSET + SIG_COMPONENT_LEN {
        return Err(QuoteVerifyError::ChainInvalid(
            "report too short for signature extraction".into(),
        ));
    }

    // Check signature algorithm field
    let sig_algo = u32::from_le_bytes(
        report_bytes[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if sig_algo != ECDSA_P384_SHA384 {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "unsupported signature algorithm {sig_algo}, expected {ECDSA_P384_SHA384} (ECDSA P-384)"
        )));
    }

    // Check report policy bits
    check_report_policy(report_bytes)?;

    // Extract r and s components (little-endian, 72 bytes zero-padded → 48 bytes big-endian)
    let r_le = &report_bytes[SIG_R_OFFSET..SIG_R_OFFSET + SIG_COMPONENT_LEN];
    let s_le = &report_bytes[SIG_S_OFFSET..SIG_S_OFFSET + SIG_COMPONENT_LEN];

    let r_be = le_to_be_trimmed(r_le);
    let s_be = le_to_be_trimmed(s_le);

    // Construct the ECDSA signature from (r, s) in big-endian fixed-width format
    let mut sig_bytes = [0u8; 96]; // 48 + 48
    let r_start = 48 - r_be.len();
    sig_bytes[r_start..48].copy_from_slice(&r_be);
    let s_start = 48 + 48 - s_be.len();
    sig_bytes[s_start..96].copy_from_slice(&s_be);

    let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!("invalid ECDSA signature encoding: {e}"))
    })?;

    // Verify: the signed region is hashed with SHA-384 internally by the verifier
    let signed_region = &report_bytes[..SIGNED_REGION_END];
    vcek_pubkey
        .verify(signed_region, &signature)
        .map_err(|e| QuoteVerifyError::ChainInvalid(format!("report signature invalid: {e}")))
}

/// Check report policy and flags for security-critical bits.
///
/// POLICY (offset 8, u64): bit 19 = DEBUG (must be 0 for production).
/// FLAGS (offset 72, u32): bit 0 = SIGNING_KEY (0=VCEK, 1=VLEK; must be 0).
fn check_report_policy(report_bytes: &[u8]) -> Result<(), QuoteVerifyError> {
    // FLAGS.SIGNING_KEY (bit 0): must be 0 (VCEK). 1 means VLEK.
    let flags = u32::from_le_bytes(
        report_bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if flags & 1 != 0 {
        return Err(QuoteVerifyError::ChainInvalid(
            "report signed with VLEK (FLAGS.SIGNING_KEY=1), only VCEK is accepted".into(),
        ));
    }

    // POLICY.DEBUG (bit 19): must be 0 (production mode).
    let policy = u64::from_le_bytes(
        report_bytes[POLICY_OFFSET..POLICY_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if policy & (1 << 19) != 0 {
        return Err(QuoteVerifyError::ChainInvalid(
            "report has DEBUG policy bit set (bit 19), rejecting non-production report".into(),
        ));
    }

    Ok(())
}

/// Convert a little-endian zero-padded byte slice to big-endian, trimming
/// leading zeros from the result (which were trailing zeros in LE).
fn le_to_be_trimmed(le_bytes: &[u8]) -> Vec<u8> {
    let mut be: Vec<u8> = le_bytes.iter().rev().copied().collect();
    // Trim leading zeros but keep at least one byte
    let first_nonzero = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be.drain(..first_nonzero);
    be
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    /// Build a synthetic 1184-byte SNP report and sign it with the given key.
    fn build_signed_report(signing_key: &SigningKey, debug: bool, vlek: bool) -> Vec<u8> {
        use ecdsa::signature::Signer;

        let mut report = vec![0u8; 1184];
        // Version 2
        report[0..4].copy_from_slice(&2u32.to_le_bytes());

        // Policy (offset 8): bit 19 = DEBUG
        let mut policy: u64 = 0;
        if debug {
            policy |= 1 << 19;
        }
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());

        // Flags (offset 72): bit 0 = SIGNING_KEY (0=VCEK, 1=VLEK)
        let mut flags: u32 = 0;
        if vlek {
            flags |= 1;
        }
        report[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());

        // Signature algo = 1 (ECDSA P-384) — at offset 52, inside signed region
        report[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4]
            .copy_from_slice(&ECDSA_P384_SHA384.to_le_bytes());

        // Some user_data
        report[80..144].copy_from_slice(&[0xAA; 64]);

        // Measurement
        report[144..192].copy_from_slice(&[0xBB; 48]);

        // Sign the first 672 bytes (includes all header fields)
        let signed_region = &report[..SIGNED_REGION_END];
        let signature: Signature = signing_key.sign(signed_region);

        // Encode r and s in little-endian, zero-padded to 72 bytes
        let sig_bytes = signature.to_bytes();
        let r_be = &sig_bytes[..48];
        let s_be = &sig_bytes[48..];

        let r_le = be_to_le_padded(r_be, SIG_COMPONENT_LEN);
        let s_le = be_to_le_padded(s_be, SIG_COMPONENT_LEN);

        report[SIG_R_OFFSET..SIG_R_OFFSET + SIG_COMPONENT_LEN].copy_from_slice(&r_le);
        report[SIG_S_OFFSET..SIG_S_OFFSET + SIG_COMPONENT_LEN].copy_from_slice(&s_le);

        report
    }

    fn be_to_le_padded(be_bytes: &[u8], pad_len: usize) -> Vec<u8> {
        let mut le: Vec<u8> = be_bytes.iter().rev().copied().collect();
        le.resize(pad_len, 0);
        le
    }

    #[test]
    fn valid_report_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let report = build_signed_report(&signing_key, false, false);

        verify_report_signature(&report, &verifying_key).unwrap();
    }

    #[test]
    fn tampered_region_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let mut report = build_signed_report(&signing_key, false, false);

        // Tamper with signed region
        report[100] ^= 0xFF;

        let err = verify_report_signature(&report, &verifying_key).unwrap_err();
        assert!(
            matches!(err, QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("signature invalid")),
            "expected signature invalid, got: {err}"
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let wrong_key = SigningKey::random(&mut OsRng);
        let wrong_verifying = VerifyingKey::from(&wrong_key);
        let report = build_signed_report(&signing_key, false, false);

        let err = verify_report_signature(&report, &wrong_verifying).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("signature invalid")
        ));
    }

    #[test]
    fn wrong_algo_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let mut report = build_signed_report(&signing_key, false, false);

        // Set algo to 0 (invalid)
        report[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());

        let err = verify_report_signature(&report, &verifying_key).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("unsupported signature algorithm")
        ));
    }

    #[test]
    fn debug_bit_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let report = build_signed_report(&signing_key, true, false);

        let err = verify_report_signature(&report, &verifying_key).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("DEBUG")
        ));
    }

    #[test]
    fn vlek_bit_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let report = build_signed_report(&signing_key, false, true);

        let err = verify_report_signature(&report, &verifying_key).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("VLEK")
        ));
    }
}
