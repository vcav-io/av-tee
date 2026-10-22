use crate::MeasurementEntry;
use crate::quote::QuoteVerifyError;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestationStatus {
    /// Simulated quote: format and cross-checks passed, but a simulated quote
    /// has no platform signature and shows nothing about the platform.
    /// Never counts as verified; see [`TeeVerificationResult::is_valid_simulated`].
    QuoteSimulated,
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
/// | Variant | Encoding | Model identity bound? | Relay config bound? |
/// |---------|----------|-----------------------|---------------------|
/// | `V3` | length-prefixed | Yes (provider-reported) | Yes — `relay_config_hash` (relay-asserted, not code-attested) |
/// | `V2` | legacy, interpolated | Yes (provider-reported) | No: code/config unbound |
/// | `V1` | legacy, interpolated | No — relay-asserted claim only | No: code/config unbound |
///
/// No schema binds the relay *code*: that depends on what the platform
/// measurement covers (see the measurement allowlist).
///
/// `None` in `TeeVerificationResult::transcript_schema` means neither schema
/// matched (transcript hash invalid).
///
/// **Caller guidance:** `transcript_hash_valid == true` with
/// `transcript_schema == Some(V1)` means the transcript matched but model
/// identity was NOT hardware-bound — it is only a relay-asserted claim.
/// Callers that require model-identity binding MUST check for `Some(V2)` or
/// `Some(V3)`; callers that require relay-config binding MUST check for
/// `Some(V3)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptSchema {
    /// Transcript v3: length-prefixed encoding of every field, including
    /// `model_identity_asserted` and the relay configuration hash.
    V3,
    /// Transcript v2 (legacy): `model_identity_asserted` is included in the
    /// hash; relay code and configuration are not bound.
    V2,
    /// Transcript v1 (legacy): `model_identity_asserted` is NOT in the hash.
    /// Model identity is only a relay-asserted claim.
    V1,
}

impl TranscriptSchema {
    /// Whether the transcript binds a relay configuration hash. The
    /// configuration is asserted by the relay: it is attested only when the
    /// platform measurement covers the relay code that computed it.
    pub fn binds_relay_config(&self) -> bool {
        matches!(self, TranscriptSchema::V3)
    }

    /// Short label for display.
    pub fn label(&self) -> &'static str {
        match self {
            TranscriptSchema::V3 => "relay config asserted (not code-attested)",
            TranscriptSchema::V2 | TranscriptSchema::V1 => "code/config unbound",
        }
    }
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
    /// `Some(V3)` means model identity and a relay configuration hash are
    /// bound (the configuration is relay-asserted, not code-attested, unless
    /// the measurement covers the relay code).
    /// `Some(V2)` means model identity is bound; code/config unbound. With a
    /// relay config supplied (or v3 required), v1/v2 matches are reported
    /// here but `transcript_hash_valid` is false.
    /// `Some(V1)` means legacy — model identity is NOT in the transcript.
    /// `None` means neither schema matched (transcript hash invalid).
    pub transcript_schema: Option<TranscriptSchema>,
    /// The relay configuration the v3 transcript was verified against
    /// (`Some` only when `transcript_schema == Some(V3)`). Callers apply
    /// their own policy to it, e.g. the provider base URL.
    pub relay_config: Option<tee_transcript::RelayConfig>,
    pub submission_hashes_present: bool,
}

/// Status of the receipt signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The signature verifies under the caller's pinned relay key.
    Valid,
    /// The signature verifies under the key named in
    /// `tee_attestation.receipt_signing_pubkey_hex`, but no pinned key was
    /// supplied. The receipt names its own key, so this shows only internal
    /// consistency; it does not count as valid.
    ValidUnpinned,
    /// `tee_attestation.receipt_signing_pubkey_hex` differs from the pinned key.
    KeyMismatch,
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
    /// What the result supports about the relay configuration and code.
    ///
    /// - v3 transcript, chain-verified quote and an allowlist entry whose
    ///   platform covers the relay code: "relay config bound to measured
    ///   relay code";
    /// - other valid v3 transcripts: "relay config asserted (not
    ///   code-attested)";
    /// - valid v1/v2 transcripts: "code/config unbound";
    /// - no valid transcript: `None`.
    ///
    /// Returns `None` unless all receipt-level checks pass
    /// ([`Self::is_valid_sans_quote`]): a claim is never made for a receipt
    /// with a bad signature, an unpinned key or an unknown measurement.
    pub fn relay_config_claim(&self) -> Option<&'static str> {
        if !self.is_valid_sans_quote() {
            return None;
        }
        match self.transcript_schema {
            Some(TranscriptSchema::V3) => {
                let code_measured = self.attestation_status == AttestationStatus::QuoteVerified
                    && self
                        .measurement_match
                        .as_ref()
                        .is_some_and(|m| m.platform.covers_relay_code());
                Some(if code_measured {
                    "relay config bound to measured relay code"
                } else {
                    "relay config asserted (not code-attested)"
                })
            }
            Some(_) => Some("code/config unbound"),
            None => None,
        }
    }

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

    /// Returns `true` for a simulated quote (`QuoteSimulated`) when all
    /// receipt-level checks pass. For development and tests only: a simulated
    /// quote shows nothing about the platform.
    pub fn is_valid_simulated(&self) -> bool {
        self.attestation_status == AttestationStatus::QuoteSimulated && self.is_valid_sans_quote()
    }

    /// Returns `true` when all receipt-level checks pass, regardless of
    /// quote verification status. Use when quote verification is unavailable
    /// or when `QuoteParsed` assurance is sufficient.
    ///
    /// Does NOT guarantee that the execution environment has been
    /// platform-verified. Requires a pinned key
    /// (`SignatureStatus::Valid`).
    pub fn is_valid_sans_quote(&self) -> bool {
        self.measurement_match.is_some()
            && self.signature_status == SignatureStatus::Valid
            && self.attestation_hash_status == AttestationHashStatus::Valid
            && self.transcript_hash_valid
            && self.submission_hashes_present
    }
}
