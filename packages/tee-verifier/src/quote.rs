use receipt_core::TeeType;
use sha2::{Digest, Sha256};

use crate::result::AttestationStatus;

/// Typed errors for quote verification failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QuoteVerifyError {
    #[error("no quote field in tee_attestation")]
    MissingQuote,
    #[error("base64 decode failed")]
    Base64DecodeFailed,
    #[error("wrong length: got {got}, expected {expected}")]
    WrongLength { got: usize, expected: usize },
    #[error("invalid prefix")]
    InvalidPrefix,
    #[error("SNP report parse failed: {0}")]
    SnpParseFailed(String),
    #[error("certificate chain invalid: {0}")]
    ChainInvalid(String),
    #[error("quote user_data does not match receipt user_data_hex")]
    UserDataMismatch,
    #[error("quote measurement does not match receipt measurement")]
    MeasurementMismatch,
    #[error("receipt has quote but no user_data_hex")]
    MissingReceiptUserData,
    #[error("receipt has quote but no measurement")]
    MissingReceiptMeasurement,
    #[error(
        "receipt tee_type {receipt:?} does not match the quote verifier's platform {verifier:?}"
    )]
    TeeTypeMismatch {
        receipt: Option<TeeType>,
        verifier: TeeType,
    },
    #[error("simulated attestation in a receipt that claims TEE_ATTESTED assurance")]
    SimulatedClaimsTeeAttested,
}

/// The level of cryptographic assurance the verifier provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    /// Simulated quote: format checked. There is no platform signature, so
    /// this never counts as platform verification.
    Simulated,
    /// Fields extracted and format validated, but no platform signature checked.
    Parsed,
    /// Full platform cryptographic chain verified (e.g., VCEK -> ASK -> ARK).
    ChainVerified,
}

/// Fields extracted from a verified attestation quote.
/// These are the platform's claims — they must be cross-checked
/// against the receipt's claims before the quote is considered binding.
#[derive(Debug)]
pub struct QuoteFields {
    /// The user_data / report_data bound into the platform attestation (64 bytes).
    pub user_data: [u8; 64],
    /// Platform measurement extracted from the quote (hex-encoded).
    pub measurement: String,
}

/// Verified quote: extracted fields plus the assurance level achieved.
#[derive(Debug)]
pub struct VerifiedQuote {
    pub fields: QuoteFields,
    pub level: VerificationLevel,
}

/// Verifies a raw attestation quote and extracts platform-bound fields.
///
/// Implementations handle platform-specific parsing (simulated prefix,
/// SNP report struct, etc). The caller (`verify_tee_receipt`) is responsible
/// for cross-checking extracted fields against receipt claims.
pub trait QuoteVerifier: Send + Sync {
    /// The platform this verifier handles. A receipt whose
    /// `tee_attestation.tee_type` differs is rejected before the quote is
    /// parsed.
    fn tee_type(&self) -> TeeType;

    fn verify_quote(&self, quote_bytes: &[u8]) -> Result<VerifiedQuote, QuoteVerifyError>;
}

// ---------------------------------------------------------------------------
// SimulatedQuoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for simulated TEE quotes produced by `SimulatedCvm`.
///
/// Simulated quotes have format: `b"simulated-quote:" || user_data` (80 bytes).
/// Anyone can produce one, so a simulated quote shows nothing about the
/// platform. Returns `VerificationLevel::Simulated`, which maps to
/// `AttestationStatus::QuoteSimulated` and never to `QuoteVerified`.
pub struct SimulatedQuoteVerifier;

const SIMULATED_PREFIX: &[u8] = b"simulated-quote:";
const SIMULATED_QUOTE_LEN: usize = 16 + 64; // prefix + user_data

impl QuoteVerifier for SimulatedQuoteVerifier {
    fn tee_type(&self) -> TeeType {
        TeeType::Simulated
    }

    fn verify_quote(&self, quote_bytes: &[u8]) -> Result<VerifiedQuote, QuoteVerifyError> {
        if quote_bytes.len() != SIMULATED_QUOTE_LEN {
            return Err(QuoteVerifyError::WrongLength {
                got: quote_bytes.len(),
                expected: SIMULATED_QUOTE_LEN,
            });
        }
        if &quote_bytes[..16] != SIMULATED_PREFIX {
            return Err(QuoteVerifyError::InvalidPrefix);
        }

        let mut user_data = [0u8; 64];
        user_data.copy_from_slice(&quote_bytes[16..]);

        // SimulatedCvm measurement: sha256("av-tee-simulated-v1")
        let measurement = hex::encode(Sha256::digest(b"av-tee-simulated-v1"));

        Ok(VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement,
            },
            level: VerificationLevel::Simulated,
        })
    }
}

// ---------------------------------------------------------------------------
// SevSnpQuoteVerifier
// ---------------------------------------------------------------------------

/// SEV-SNP attestation report verifier (field extraction).
///
/// Extracts REPORT_DATA and MEASUREMENT from a version 2 to 5 report and
/// returns `VerificationLevel::Parsed`. `verify_tee_receipt` then verifies
/// the VCEK → ASK → ARK chain, the report signature, the report policy
/// (VMPL, MIGRATE_MA, SMT), the TCB and the chip id when the receipt
/// carries the VCEK (see `snp_chain`).
pub struct SevSnpQuoteVerifier {
    _private: (), // Force use of constructors
}

impl SevSnpQuoteVerifier {
    /// Parse-only mode: extract fields from SNP report.
    /// Does NOT verify the cryptographic chain.
    /// Returns `VerificationLevel::Parsed`, not `ChainVerified`.
    pub fn parsing_only() -> Self {
        Self { _private: () }
    }
}

// AMD SEV-SNP attestation report layout (fixed-size C struct per ABI spec).
#[cfg(test)]
const SNP_REPORT_SIZE: usize = crate::snp_report::SNP_REPORT_SIZE;
#[cfg(test)]
const SNP_VERSION_OFFSET: usize = 0;
const SNP_REPORT_DATA_OFFSET: usize = 80;
const SNP_MEASUREMENT_OFFSET: usize = 144;
const SNP_MEASUREMENT_LEN: usize = 48;

impl QuoteVerifier for SevSnpQuoteVerifier {
    fn tee_type(&self) -> TeeType {
        TeeType::SevSnp
    }

    fn verify_quote(&self, quote_bytes: &[u8]) -> Result<VerifiedQuote, QuoteVerifyError> {
        // Size and version (2 to 5) checks.
        crate::snp_report::parse_report_fields(quote_bytes)?;

        let mut user_data = [0u8; 64];
        user_data
            .copy_from_slice(&quote_bytes[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64]);

        let measurement = hex::encode(
            &quote_bytes[SNP_MEASUREMENT_OFFSET..SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN],
        );

        Ok(VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement,
            },
            level: VerificationLevel::Parsed,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cross-check quote-extracted fields against receipt claims and map
/// the verification level to an `AttestationStatus`.
///
/// Both `user_data_hex` and `measurement` are mandatory in the receipt
/// when a quote is present. A receipt that provides a quote but doesn't
/// commit to the fields the quote binds is structurally broken.
pub(crate) fn cross_check_and_map(
    verified: &VerifiedQuote,
    receipt_user_data_hex: Option<&str>,
    receipt_measurement: Option<&str>,
) -> Result<AttestationStatus, QuoteVerifyError> {
    // Cross-check 1 (mandatory): quote user_data must match receipt user_data_hex
    let quote_user_data_hex = hex::encode(verified.fields.user_data);
    match receipt_user_data_hex {
        Some(receipt_ud) if quote_user_data_hex != receipt_ud => {
            return Err(QuoteVerifyError::UserDataMismatch);
        }
        None => {
            return Err(QuoteVerifyError::MissingReceiptUserData);
        }
        _ => {} // match
    }

    // Cross-check 2 (mandatory): quote measurement must match receipt measurement
    match receipt_measurement {
        Some(receipt_m) if verified.fields.measurement != receipt_m => {
            return Err(QuoteVerifyError::MeasurementMismatch);
        }
        None => {
            return Err(QuoteVerifyError::MissingReceiptMeasurement);
        }
        _ => {} // match
    }

    // Both cross-checks passed. Map verification level to status.
    Ok(match verified.level {
        VerificationLevel::ChainVerified => AttestationStatus::QuoteVerified,
        VerificationLevel::Parsed => AttestationStatus::QuoteParsed,
        VerificationLevel::Simulated => AttestationStatus::QuoteSimulated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SimulatedQuoteVerifier
    // -----------------------------------------------------------------------

    #[test]
    fn valid_simulated_quote() {
        let mut quote = Vec::from(&b"simulated-quote:"[..]);
        quote.extend_from_slice(&[0x42; 64]);

        let result = SimulatedQuoteVerifier.verify_quote(&quote).unwrap();
        assert_eq!(result.fields.user_data, [0x42; 64]);
        assert_eq!(result.level, VerificationLevel::Simulated);
    }

    #[test]
    fn simulated_wrong_length_rejected() {
        let quote = vec![0u8; 79];
        let err = SimulatedQuoteVerifier.verify_quote(&quote).unwrap_err();
        assert_eq!(
            err,
            QuoteVerifyError::WrongLength {
                got: 79,
                expected: 80
            }
        );

        let quote = vec![0u8; 81];
        let err = SimulatedQuoteVerifier.verify_quote(&quote).unwrap_err();
        assert_eq!(
            err,
            QuoteVerifyError::WrongLength {
                got: 81,
                expected: 80
            }
        );
    }

    #[test]
    fn simulated_wrong_prefix_rejected() {
        let mut quote = Vec::from(&b"tampered-quote:X"[..]);
        quote.extend_from_slice(&[0u8; 64]);
        let err = SimulatedQuoteVerifier.verify_quote(&quote).unwrap_err();
        assert_eq!(err, QuoteVerifyError::InvalidPrefix);
    }

    #[test]
    fn simulated_measurement_is_deterministic() {
        let mut quote = Vec::from(&b"simulated-quote:"[..]);
        quote.extend_from_slice(&[0u8; 64]);

        let result = SimulatedQuoteVerifier.verify_quote(&quote).unwrap();
        let expected = hex::encode(Sha256::digest(b"av-tee-simulated-v1"));
        assert_eq!(result.fields.measurement, expected);
    }

    // -----------------------------------------------------------------------
    // SevSnpQuoteVerifier
    // -----------------------------------------------------------------------

    /// Build a synthetic 1184-byte SNP report with known fields at known offsets.
    fn build_synthetic_snp_report(
        version: u32,
        report_data: &[u8; 64],
        measurement: &[u8; 48],
    ) -> Vec<u8> {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_VERSION_OFFSET..SNP_VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(report_data);
        report[SNP_MEASUREMENT_OFFSET..SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN]
            .copy_from_slice(measurement);
        report
    }

    #[test]
    fn snp_parse_valid_report() {
        let report_data = [0xAA; 64];
        let measurement = [0xBB; 48];
        let report = build_synthetic_snp_report(2, &report_data, &measurement);

        let result = SevSnpQuoteVerifier::parsing_only()
            .verify_quote(&report)
            .unwrap();
        assert_eq!(result.fields.user_data, report_data);
        assert_eq!(result.fields.measurement, hex::encode(measurement));
        assert_eq!(result.level, VerificationLevel::Parsed);
    }

    #[test]
    fn snp_wrong_size_rejected() {
        let report = vec![0u8; 1000];
        let err = SevSnpQuoteVerifier::parsing_only()
            .verify_quote(&report)
            .unwrap_err();
        assert_eq!(
            err,
            QuoteVerifyError::WrongLength {
                got: 1000,
                expected: 1184
            }
        );
    }

    #[test]
    fn snp_wrong_version_rejected() {
        let report = build_synthetic_snp_report(1, &[0; 64], &[0; 48]);
        let err = SevSnpQuoteVerifier::parsing_only()
            .verify_quote(&report)
            .unwrap_err();
        assert!(matches!(err, QuoteVerifyError::SnpParseFailed(_)));
    }

    #[test]
    fn snp_report_versions_3_and_5_are_parsed() {
        for version in [3, 5] {
            let report = build_synthetic_snp_report(version, &[0x11; 64], &[0x22; 48]);
            let result = SevSnpQuoteVerifier::parsing_only()
                .verify_quote(&report)
                .unwrap();
            assert_eq!(result.fields.user_data, [0x11; 64]);
        }
    }

    #[test]
    fn snp_extracted_fields_match() {
        let report_data = [0xCC; 64];
        let measurement = [0xDD; 48];
        let report = build_synthetic_snp_report(2, &report_data, &measurement);

        let result = SevSnpQuoteVerifier::parsing_only()
            .verify_quote(&report)
            .unwrap();
        assert_eq!(result.fields.user_data, report_data);
        assert_eq!(result.fields.measurement, hex::encode(measurement));
    }

    // -----------------------------------------------------------------------
    // cross_check_and_map
    // -----------------------------------------------------------------------

    #[test]
    fn cross_check_passes_when_fields_match() {
        let user_data = [0x42; 64];
        let measurement = "abc123".to_string();
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement: measurement.clone(),
            },
            level: VerificationLevel::ChainVerified,
        };
        let result =
            cross_check_and_map(&verified, Some(&hex::encode(user_data)), Some(&measurement))
                .unwrap();
        assert_eq!(result, AttestationStatus::QuoteVerified);
    }

    #[test]
    fn cross_check_simulated_level_never_maps_to_verified() {
        let user_data = [0x42; 64];
        let measurement = "abc123".to_string();
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement: measurement.clone(),
            },
            level: VerificationLevel::Simulated,
        };
        let result =
            cross_check_and_map(&verified, Some(&hex::encode(user_data)), Some(&measurement))
                .unwrap();
        assert_eq!(result, AttestationStatus::QuoteSimulated);
    }

    #[test]
    fn verifiers_report_their_platform() {
        assert_eq!(SimulatedQuoteVerifier.tee_type(), TeeType::Simulated);
        assert_eq!(
            SevSnpQuoteVerifier::parsing_only().tee_type(),
            TeeType::SevSnp
        );
    }

    #[test]
    fn cross_check_parsed_level_maps_to_parsed() {
        let user_data = [0x42; 64];
        let measurement = "abc123".to_string();
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement: measurement.clone(),
            },
            level: VerificationLevel::Parsed,
        };
        let result =
            cross_check_and_map(&verified, Some(&hex::encode(user_data)), Some(&measurement))
                .unwrap();
        assert_eq!(result, AttestationStatus::QuoteParsed);
    }

    #[test]
    fn cross_check_user_data_mismatch() {
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data: [0x42; 64],
                measurement: "abc".into(),
            },
            level: VerificationLevel::ChainVerified,
        };
        let err = cross_check_and_map(&verified, Some("wrong_hex"), Some("abc")).unwrap_err();
        assert_eq!(err, QuoteVerifyError::UserDataMismatch);
    }

    #[test]
    fn cross_check_measurement_mismatch() {
        let user_data = [0x42; 64];
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement: "abc".into(),
            },
            level: VerificationLevel::ChainVerified,
        };
        let err =
            cross_check_and_map(&verified, Some(&hex::encode(user_data)), Some("xyz")).unwrap_err();
        assert_eq!(err, QuoteVerifyError::MeasurementMismatch);
    }

    #[test]
    fn cross_check_missing_receipt_user_data() {
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data: [0; 64],
                measurement: "abc".into(),
            },
            level: VerificationLevel::ChainVerified,
        };
        let err = cross_check_and_map(&verified, None, Some("abc")).unwrap_err();
        assert_eq!(err, QuoteVerifyError::MissingReceiptUserData);
    }

    #[test]
    fn cross_check_missing_receipt_measurement() {
        let user_data = [0; 64];
        let verified = VerifiedQuote {
            fields: QuoteFields {
                user_data,
                measurement: "abc".into(),
            },
            level: VerificationLevel::ChainVerified,
        };
        let err = cross_check_and_map(&verified, Some(&hex::encode(user_data)), None).unwrap_err();
        assert_eq!(err, QuoteVerifyError::MissingReceiptMeasurement);
    }
}
