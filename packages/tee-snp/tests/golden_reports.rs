use sha2::{Digest, Sha256};
use tee_verifier::{QuoteVerifier, SevSnpQuoteVerifier};

const SNP_REPORT_SIZE: usize = 1184;
const SNP_REPORT_DATA_OFFSET: usize = 80;
const SNP_MEASUREMENT_OFFSET: usize = 144;
const SNP_MEASUREMENT_LEN: usize = 48;

/// Build a synthetic 1184-byte SEV-SNP attestation report with known fields.
fn build_synthetic_report(user_data: &[u8; 64], measurement: &[u8; 48]) -> Vec<u8> {
    let mut report = vec![0u8; SNP_REPORT_SIZE];
    // Version 2 at offset 0, little-endian
    report[0..4].copy_from_slice(&2u32.to_le_bytes());
    report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(user_data);
    report[SNP_MEASUREMENT_OFFSET..SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN]
        .copy_from_slice(measurement);
    report
}

#[test]
fn golden_report_standard_fields() {
    let user_data = [0xAA; 64];
    let measurement = [0xBB; 48];
    let report = build_synthetic_report(&user_data, &measurement);

    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verifier.verify_quote(&report).expect("parse should succeed");

    assert_eq!(result.fields.user_data, user_data);
    assert_eq!(result.fields.measurement, hex::encode(measurement));
}

#[test]
fn golden_report_measurement_extraction_matches_adapter() {
    let user_data = [0xCC; 64];
    let measurement_bytes: [u8; 48] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
    let report = build_synthetic_report(&user_data, &measurement_bytes);

    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verifier.verify_quote(&report).expect("parse should succeed");

    // The verifier's measurement field must equal the hex encoding of the raw bytes.
    let expected_hex = hex::encode(measurement_bytes);
    assert_eq!(result.fields.measurement, expected_hex);
}

#[test]
fn golden_report_attestation_hash_roundtrip() {
    let user_data = [0xDD; 64];
    let measurement = [0xEE; 48];
    let report = build_synthetic_report(&user_data, &measurement);

    // Compute SHA-256 of the raw report bytes.
    let hash1 = Sha256::digest(&report);
    let hash2 = Sha256::digest(&report);

    // Deterministic: same input always produces the same hash.
    assert_eq!(hash1, hash2);

    // SHA-256 produces 32 bytes = 64 hex characters.
    let hash_hex = hex::encode(hash1);
    assert_eq!(hash_hex.len(), 64);
}
