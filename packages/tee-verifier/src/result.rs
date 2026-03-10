use crate::MeasurementEntry;
use crate::quote::QuoteVerifyError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestationStatus {
    /// Quote parsed and fields extracted, but platform signature not checked.
    /// The extracted fields were cross-checked against receipt claims.
    QuoteParsed,
    /// Full platform cryptographic verification passed.
    /// Quote fields cross-checked against receipt claims.
    QuoteVerified,
    /// Quote verification failed.
    QuoteInvalid(QuoteVerifyError),
}

/// Which transcript hash schema was used for verification.
///
/// | Variant | Model identity bound? |
/// |---------|-----------------------|
/// | `V2` | Yes — `model_identity_asserted` is part of the attested transcript hash |
/// | `V1` | No — legacy receipt; model identity is a relay-asserted claim only |
///
/// `None` in `TeeVerificationResult::transcript_schema` means neither schema
/// matched (transcript hash invalid).
///
/// **Caller guidance:** `transcript_hash_valid == true` with
/// `transcript_schema == Some(V1)` means the transcript matched but model
/// identity was NOT hardware-bound — it is only a relay-asserted claim.
/// Callers that require model-identity binding MUST check for `Some(V2)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptSchema {
    /// Transcript v2: `model_identity_asserted` is included in the hash.
    V2,
    /// Transcript v1 (legacy): `model_identity_asserted` is NOT in the hash.
    /// Model identity is only a relay-asserted claim.
    V1,
}

#[derive(Debug, Clone)]
pub struct TeeVerificationResult {
    pub measurement_match: Option<MeasurementEntry>,
    pub attestation_status: AttestationStatus,
    pub signature_status: SignatureStatus,
    pub attestation_hash_status: AttestationHashStatus,
    pub transcript_hash_valid: bool,
    pub transcript_binding: TranscriptBinding,
    /// Which transcript schema was used to verify the hash.
    /// `Some(V2)` means model identity is hardware-bound.
    /// `Some(V1)` means legacy — model identity is NOT in the transcript.
    /// `None` means neither schema matched (transcript hash invalid).
    pub transcript_schema: Option<TranscriptSchema>,
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
///
/// The binding level determines the assurance that the transcript (the ordered
/// set of commitments) was produced inside a genuine CVM:
///
/// | Variant | Assurance | What it means |
/// |---------|-----------|---------------|
/// | `UserData` | **Hardware-bound** | Transcript hash is in the SEV-SNP `user_data` field, which is included in the platform attestation report. A valid quote proves the hash was set by code running inside the measured CVM. |
/// | `TranscriptHashFallback` | **Relay-asserted** | Transcript hash matches `transcript_hash_hex` in `tee_attestation`, but that field is set by the relay, not bound into the platform attestation. A compromised relay could substitute a different hash. |
/// | `None` | **Unverifiable** | Neither `user_data_hex` nor `transcript_hash_hex` is present. The transcript cannot be verified against anything. |
///
/// Callers that check only `transcript_hash_valid == true` should also inspect
/// `transcript_binding` — a valid hash with `TranscriptHashFallback` binding
/// provides weaker assurance than one with `UserData` binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptBinding {
    /// Transcript hash verified against the platform attestation `user_data`
    /// field. This is the strongest binding: the hash was committed by code
    /// running inside a measured CVM and is covered by the SEV-SNP signature.
    UserData,
    /// Transcript hash verified against the relay-asserted `transcript_hash_hex`
    /// field. The hash itself is correct, but it is not bound into the platform
    /// attestation — a compromised relay could have substituted it.
    TranscriptHashFallback,
    /// Neither `user_data_hex` nor `transcript_hash_hex` was present in the
    /// attestation. Transcript integrity cannot be verified.
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
    /// `QuoteParsed` and `QuoteVerified`. Use [`Self::is_valid`] when full
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
