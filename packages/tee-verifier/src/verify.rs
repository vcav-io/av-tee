use base64::Engine;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use receipt_core::{ReceiptV2, ReceiptV3, TeeAttestation};
use tee_transcript::{
    RelayConfig, TranscriptInputs, TranscriptInputsV2, TranscriptInputsV3, compute_transcript_hash,
    compute_transcript_hash_v2, compute_transcript_hash_v3,
};

use crate::allowlist::TransparencySource;
use crate::quote::{QuoteVerifier, QuoteVerifyError, cross_check_and_map};
use crate::result::{
    AttestationHashStatus, AttestationStatus, SignatureStatus, TeeVerificationResult,
    TranscriptBinding, TranscriptSchema,
};
use crate::snp_chain::{self, VerificationConfig};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("receipt has no tee_attestation")]
    MissingTeeAttestation,
    #[error("receipt signature verification failed: {0}")]
    SignatureError(String),
}

/// A TEE receipt to verify: v3 (current) or v2 (issued before receipt v3).
#[derive(Debug, Clone, Copy)]
pub enum TeeReceipt<'a> {
    V2(&'a ReceiptV2),
    V3(&'a ReceiptV3),
}

impl<'a> From<&'a ReceiptV2> for TeeReceipt<'a> {
    fn from(receipt: &'a ReceiptV2) -> Self {
        TeeReceipt::V2(receipt)
    }
}

impl<'a> From<&'a ReceiptV3> for TeeReceipt<'a> {
    fn from(receipt: &'a ReceiptV3) -> Self {
        TeeReceipt::V3(receipt)
    }
}

/// The receipt fields that TEE verification reads, common to v2 and v3.
struct TeeFields<'a> {
    tee_attestation: Option<&'a TeeAttestation>,
    contract_hash: &'a str,
    prompt_template_hash: Option<&'a str>,
    initiator_submission_hash: Option<&'a str>,
    responder_submission_hash: Option<&'a str>,
    output_hash: &'a str,
    model_identity_asserted: Option<&'a str>,
}

impl<'a> TeeReceipt<'a> {
    fn fields(&self) -> TeeFields<'a> {
        match *self {
            TeeReceipt::V2(r) => TeeFields {
                tee_attestation: r.tee_attestation.as_ref(),
                contract_hash: &r.commitments.contract_hash,
                prompt_template_hash: r.commitments.prompt_template_hash.as_deref(),
                initiator_submission_hash: r.commitments.initiator_submission_hash.as_deref(),
                responder_submission_hash: r.commitments.responder_submission_hash.as_deref(),
                output_hash: &r.commitments.output_hash,
                model_identity_asserted: r.claims.model_identity_asserted.as_deref(),
            },
            TeeReceipt::V3(r) => TeeFields {
                tee_attestation: r.tee_attestation.as_ref(),
                contract_hash: &r.commitments.contract_hash,
                prompt_template_hash: r.commitments.prompt_template_hash.as_deref(),
                initiator_submission_hash: r.commitments.initiator_submission_hash.as_deref(),
                responder_submission_hash: r.commitments.responder_submission_hash.as_deref(),
                output_hash: &r.commitments.output_hash,
                model_identity_asserted: r.claims.model_identity_asserted.as_deref(),
            },
        }
    }

    /// Check the receipt signature with the version's own rules.
    fn signature_valid(&self, vk: &VerifyingKey) -> bool {
        match *self {
            TeeReceipt::V2(r) => {
                let (unsigned, sig) = r.clone().split();
                receipt_core::verify_receipt_v2(&unsigned, &sig, vk).is_ok()
            }
            TeeReceipt::V3(r) => {
                let (unsigned, sig) = r.clone().split();
                receipt_core::verify_receipt_v3(&unsigned, &sig, vk).is_ok()
            }
        }
    }
}

/// Verification inputs beyond the receipt itself.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// SEV-SNP platform checks.
    pub snp: VerificationConfig,
    /// Relay configuration to check a v3 transcript against.
    ///
    /// Transcript v3 binds `relay_config_hash`, which the receipt does not
    /// carry, so a v3 transcript verifies only when the caller supplies the
    /// configuration (for example the `relay_config` published at the relay's
    /// `/tee/info`, or one the caller expects). On a match the configuration
    /// is returned in [`TeeVerificationResult::relay_config`], so the caller
    /// can apply its own policy to it.
    ///
    /// Supplying a relay config also requires transcript v3: a v1 or v2
    /// transcript match is then reported as invalid, so a receipt cannot
    /// avoid the configuration check by carrying a legacy transcript.
    pub relay_config: Option<RelayConfig>,
    /// Require a v3 transcript even without a relay config (in which case
    /// no transcript can verify). Implied when `relay_config` is set.
    pub require_transcript_v3: bool,
}

pub fn verify_tee_receipt<'a>(
    receipt: impl Into<TeeReceipt<'a>>,
    allowlist: &dyn TransparencySource,
    quote_verifier: &dyn QuoteVerifier,
) -> Result<TeeVerificationResult, VerifyError> {
    verify_tee_receipt_with_config(
        receipt,
        allowlist,
        quote_verifier,
        &VerificationConfig::default(),
    )
}

pub fn verify_tee_receipt_with_config<'a>(
    receipt: impl Into<TeeReceipt<'a>>,
    allowlist: &dyn TransparencySource,
    quote_verifier: &dyn QuoteVerifier,
    config: &VerificationConfig,
) -> Result<TeeVerificationResult, VerifyError> {
    verify_tee_receipt_with_options(
        receipt,
        allowlist,
        quote_verifier,
        &VerifyOptions {
            snp: config.clone(),
            ..VerifyOptions::default()
        },
    )
}

pub fn verify_tee_receipt_with_options<'a>(
    receipt: impl Into<TeeReceipt<'a>>,
    allowlist: &dyn TransparencySource,
    quote_verifier: &dyn QuoteVerifier,
    options: &VerifyOptions,
) -> Result<TeeVerificationResult, VerifyError> {
    let config = &options.snp;
    let receipt = receipt.into();
    let fields = receipt.fields();
    let tee_att = fields
        .tee_attestation
        .ok_or(VerifyError::MissingTeeAttestation)?;

    // 1. Verify receipt signature using pubkey from tee_attestation
    let signature_status = match tee_att.receipt_signing_pubkey_hex.as_deref() {
        None | Some("") => SignatureStatus::MissingKey,
        Some(pubkey_hex) => match verifying_key_from_hex(pubkey_hex) {
            Ok(vk) => {
                if receipt.signature_valid(&vk) {
                    SignatureStatus::Valid
                } else {
                    SignatureStatus::Invalid
                }
            }
            Err(e) => SignatureStatus::MalformedKey(e),
        },
    };

    // 2. Verify attestation_hash == sha256(base64_decode(quote))
    // attestation_hash is hex(sha256(raw_quote_bytes)) where raw_quote_bytes
    // are the exact bytes base64-encoded in tee_attestation.quote. No canonical
    // wrapper, no certificate bundle — just the raw attestation report bytes.
    let attestation_hash_status = match (&tee_att.quote, &tee_att.attestation_hash) {
        (Some(quote_b64), Some(expected_hash)) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            match b64.decode(quote_b64) {
                Ok(quote_bytes) => {
                    let computed = hex::encode(Sha256::digest(&quote_bytes));
                    if computed == *expected_hash {
                        AttestationHashStatus::Valid
                    } else {
                        AttestationHashStatus::Mismatch
                    }
                }
                Err(_) => AttestationHashStatus::DecodeFailed,
            }
        }
        _ => AttestationHashStatus::MissingFields,
    };

    // 2b. Verify quote and cross-check extracted fields against receipt claims.
    // Cross-checks are mandatory when a quote is present — a quote that parses
    // but binds different state than the receipt claims is a verification failure.
    let attestation_status = match &tee_att.quote {
        Some(quote_b64) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            match b64.decode(quote_b64) {
                Ok(quote_bytes) => match quote_verifier.verify_quote(&quote_bytes) {
                    Ok(verified) => match cross_check_and_map(
                        &verified,
                        tee_att.user_data_hex.as_deref(),
                        tee_att.measurement.as_deref(),
                    ) {
                        Ok(status) => status,
                        Err(e) => AttestationStatus::QuoteInvalid(e),
                    },
                    Err(e) => AttestationStatus::QuoteInvalid(e),
                },
                Err(_) => AttestationStatus::QuoteInvalid(QuoteVerifyError::Base64DecodeFailed),
            }
        }
        None => AttestationStatus::QuoteInvalid(QuoteVerifyError::MissingQuote),
    };

    // 2c. Chain verification: upgrade Parsed → ChainVerified when VCEK cert
    // is present. "Present but malformed" is QuoteInvalid, not silent fallback.
    // "Absent" stays at Parsed.
    let attestation_status = match (&attestation_status, &tee_att.snp_vcek_cert) {
        (AttestationStatus::QuoteParsed, Some(vcek_b64)) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            match b64.decode(vcek_b64) {
                Err(_) => AttestationStatus::QuoteInvalid(QuoteVerifyError::ChainInvalid(
                    "snp_vcek_cert base64 decode failed".into(),
                )),
                Ok(vcek_der) => {
                    // quote_bytes: re-decode from tee_att.quote (already validated above)
                    let quote_bytes = tee_att
                        .quote
                        .as_ref()
                        .and_then(|q| b64.decode(q).ok())
                        .unwrap_or_default();
                    match snp_chain::verify_snp_attestation(&quote_bytes, &vcek_der, config) {
                        Ok(()) => AttestationStatus::QuoteVerified,
                        Err(e) => AttestationStatus::QuoteInvalid(e),
                    }
                }
            }
        }
        (AttestationStatus::QuoteParsed, None) => attestation_status,
        _ => attestation_status,
    };

    // 3. Measurement allowlist (exact match)
    let measurement_match = allowlist.is_allowed(tee_att.measurement.as_deref().unwrap_or(""));

    // 4. Recompute transcript hash, compare to user_data_hex
    //
    // Try v3 (relay config bound; needs the caller-supplied relay config),
    // then v2 (model identity bound), then v1. v1 and v2 are legacy
    // encodings kept so receipts issued before v3 still verify; they bind
    // neither relay code nor relay configuration, and they do not count as
    // valid when the caller supplied a relay config or required v3.
    // `transcript_schema` still reports which encoding matched.
    let (transcript_hash_valid, transcript_binding, transcript_schema) = {
        let contract_hash = fields.contract_hash;
        let prompt_template_hash = fields.prompt_template_hash.unwrap_or("");
        let initiator_sub = fields.initiator_submission_hash.unwrap_or("");
        let responder_sub = fields.responder_submission_hash.unwrap_or("");
        let output_hash = fields.output_hash;
        let pubkey_hex = tee_att.receipt_signing_pubkey_hex.as_deref().unwrap_or("");
        let model_id = fields.model_identity_asserted.unwrap_or("");

        let v3_hex = options.relay_config.as_ref().map(|relay_config| {
            let relay_config_hash = relay_config.hash_hex();
            hex::encode(compute_transcript_hash_v3(&TranscriptInputsV3 {
                contract_hash,
                prompt_template_hash,
                initiator_submission_hash: initiator_sub,
                responder_submission_hash: responder_sub,
                output_hash,
                receipt_signing_pubkey_hex: pubkey_hex,
                model_identity_asserted: model_id,
                relay_config_hash: &relay_config_hash,
            }))
        });

        let v2_hex = hex::encode(compute_transcript_hash_v2(&TranscriptInputsV2 {
            contract_hash,
            prompt_template_hash,
            initiator_submission_hash: initiator_sub,
            responder_submission_hash: responder_sub,
            output_hash,
            receipt_signing_pubkey_hex: pubkey_hex,
            model_identity_asserted: model_id,
        }));

        let v1_hex = hex::encode(compute_transcript_hash(&TranscriptInputs {
            contract_hash,
            prompt_template_hash,
            initiator_submission_hash: initiator_sub,
            responder_submission_hash: responder_sub,
            output_hash,
            receipt_signing_pubkey_hex: pubkey_hex,
        }));

        let schema_for = |target: &str| {
            if v3_hex.as_deref() == Some(target) {
                Some(TranscriptSchema::V3)
            } else if v2_hex == target {
                Some(TranscriptSchema::V2)
            } else if v1_hex == target {
                Some(TranscriptSchema::V1)
            } else {
                None
            }
        };

        // Compare against user_data_hex (the platform attestation binding),
        // falling back to transcript_hash_hex with explicit tracking of which
        // field was used so callers can distinguish assurance levels.
        let (binding, schema) = match (&tee_att.user_data_hex, &tee_att.transcript_hash_hex) {
            (Some(user_data), _) => (TranscriptBinding::UserData, schema_for(user_data)),
            (None, Some(th)) => (TranscriptBinding::TranscriptHashFallback, schema_for(th)),
            (None, None) => (TranscriptBinding::None, None),
        };
        // With a relay config (or an explicit requirement), only v3 counts:
        // a legacy transcript would skip the configuration check.
        let v3_required = options.require_transcript_v3 || options.relay_config.is_some();
        let valid = match schema {
            Some(TranscriptSchema::V3) => true,
            Some(_) => !v3_required,
            None => false,
        };
        (valid, binding, schema)
    };
    let relay_config = match transcript_schema {
        Some(TranscriptSchema::V3) => options.relay_config.clone(),
        _ => None,
    };

    // 5. Check submission hashes present
    let submission_hashes_present =
        fields.initiator_submission_hash.is_some() && fields.responder_submission_hash.is_some();

    Ok(TeeVerificationResult {
        measurement_match,
        attestation_status,
        signature_status,
        attestation_hash_status,
        transcript_hash_valid,
        transcript_binding,
        transcript_schema,
        relay_config,
        submission_hashes_present,
    })
}

fn verifying_key_from_hex(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("invalid ed25519 pubkey: {e}"))
}
