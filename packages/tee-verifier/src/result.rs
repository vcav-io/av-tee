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
    pub attestation_hash_valid: bool,
    pub transcript_hash_valid: bool,
    pub submission_hashes_present: bool,
    pub receipt_signature_valid: bool,
}

impl TeeVerificationResult {
    pub fn is_valid(&self) -> bool {
        self.measurement_match.is_some()
            && self.attestation_hash_valid
            && self.transcript_hash_valid
            && self.submission_hashes_present
            && self.receipt_signature_valid
    }
}
