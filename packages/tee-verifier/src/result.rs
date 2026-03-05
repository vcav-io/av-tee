use crate::MeasurementEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationStatus {
    QuoteUnverified,
    QuoteVerified,
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
    /// Returns `true` only when all cryptographic checks pass and the
    /// attestation quote has been verified. Until quote verification is
    /// implemented, callers should use [`is_valid_sans_quote`] and check
    /// `attestation_status` separately.
    pub fn is_valid(&self) -> bool {
        self.attestation_status == AttestationStatus::QuoteVerified && self.is_valid_sans_quote()
    }

    /// Returns `true` when all checks except quote verification pass.
    /// Use this during Phase 1 where `attestation_status` is always
    /// `QuoteUnverified`.
    pub fn is_valid_sans_quote(&self) -> bool {
        self.measurement_match.is_some()
            && self.signature_status == SignatureStatus::Valid
            && self.attestation_hash_status == AttestationHashStatus::Valid
            && self.transcript_hash_valid
            && self.submission_hashes_present
    }
}
