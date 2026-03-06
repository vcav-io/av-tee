use crate::MeasurementEntry;
use crate::quote::QuoteVerifyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationStatus {
    /// No quote verification was attempted.
    QuoteUnverified,
    /// Quote parsed and fields extracted, but platform signature not checked.
    /// The extracted fields were cross-checked against receipt claims.
    QuoteParsed,
    /// Full platform cryptographic verification passed.
    /// Quote fields cross-checked against receipt claims.
    QuoteVerified,
    /// Quote verification failed.
    QuoteInvalid(QuoteVerifyError),
}

#[derive(Debug, Clone)]
pub struct TeeVerificationResult {
    pub measurement_match: Option<MeasurementEntry>,
    pub attestation_status: AttestationStatus,
    pub signature_status: SignatureStatus,
    pub attestation_hash_status: AttestationHashStatus,
    pub transcript_hash_valid: bool,
    pub transcript_binding: TranscriptBinding,
    pub submission_hashes_present: bool,
}

/// Status of the receipt signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    MissingKey,
    MalformedKey(String),
}

/// Status of the attestation hash check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationHashStatus {
    Valid,
    Mismatch,
    MissingFields,
    DecodeFailed,
}

/// Which field the transcript hash was verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptBinding {
    /// Verified against platform `user_data_hex` (attestation-bound).
    UserData,
    /// Fell back to relay-asserted `transcript_hash_hex`.
    TranscriptHashFallback,
    /// Neither field present.
    None,
}

impl TeeVerificationResult {
    /// Returns `true` only when all cryptographic checks pass including
    /// full platform chain verification (`QuoteVerified`).
    pub fn is_valid(&self) -> bool {
        self.attestation_status == AttestationStatus::QuoteVerified && self.is_valid_sans_quote()
    }

    /// Returns `true` when all checks pass and the quote has been at minimum
    /// parsed and cross-checked against receipt claims. Accepts both
    /// `QuoteParsed` and `QuoteVerified`. Use [`is_valid`] when full
    /// cryptographic chain verification is required.
    pub fn is_valid_parsed(&self) -> bool {
        matches!(
            self.attestation_status,
            AttestationStatus::QuoteParsed | AttestationStatus::QuoteVerified
        ) && self.is_valid_sans_quote()
    }

    /// Returns `true` when all receipt-level checks pass, regardless of
    /// quote verification status. Use when quote verification is unavailable
    /// or when `QuoteParsed` assurance is sufficient.
    ///
    /// Does NOT guarantee that the execution environment has been
    /// platform-verified.
    pub fn is_valid_sans_quote(&self) -> bool {
        self.measurement_match.is_some()
            && self.signature_status == SignatureStatus::Valid
            && self.attestation_hash_status == AttestationHashStatus::Valid
            && self.transcript_hash_valid
            && self.submission_hashes_present
    }
}
