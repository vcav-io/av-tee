use base64::Engine;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use receipt_core::ReceiptV2;
use tee_transcript::{TranscriptInputs, compute_transcript_hash};

use crate::allowlist::TransparencySource;
use crate::result::{
    AttestationHashStatus, AttestationStatus, SignatureStatus, TeeVerificationResult,
    TranscriptBinding,
};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("receipt has no tee_attestation")]
    MissingTeeAttestation,
    #[error("receipt signature verification failed: {0}")]
    SignatureError(String),
}

pub fn verify_tee_receipt(
    receipt: &ReceiptV2,
    allowlist: &dyn TransparencySource,
) -> Result<TeeVerificationResult, VerifyError> {
    let tee_att = receipt
        .tee_attestation
        .as_ref()
        .ok_or(VerifyError::MissingTeeAttestation)?;

    // 1. Verify receipt signature using pubkey from tee_attestation
    let signature_status = match tee_att.receipt_signing_pubkey_hex.as_deref() {
        None | Some("") => SignatureStatus::MissingKey,
        Some(pubkey_hex) => match verifying_key_from_hex(pubkey_hex) {
            Ok(vk) => {
                let (unsigned, sig) = receipt.clone().split();
                if receipt_core::verify_receipt_v2(&unsigned, &sig, &vk).is_ok() {
                    SignatureStatus::Valid
                } else {
                    SignatureStatus::Invalid
                }
            }
            Err(e) => SignatureStatus::MalformedKey(e),
        },
    };

    // 2. Verify attestation_hash == sha256(base64_decode(quote))
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

    // 3. Measurement allowlist (exact match)
    let measurement_match = allowlist.is_allowed(tee_att.measurement.as_deref().unwrap_or(""));

    // 4. Recompute transcript hash, compare to user_data_hex
    let (transcript_hash_valid, transcript_binding) = {
        let commitments = &receipt.commitments;
        let contract_hash = commitments.contract_hash.as_str();
        let prompt_template_hash = commitments.prompt_template_hash.as_deref().unwrap_or("");
        let initiator_sub = commitments
            .initiator_submission_hash
            .as_deref()
            .unwrap_or("");
        let responder_sub = commitments
            .responder_submission_hash
            .as_deref()
            .unwrap_or("");
        let output_hash = commitments.output_hash.as_str();
        let pubkey_hex = tee_att.receipt_signing_pubkey_hex.as_deref().unwrap_or("");

        let inputs = TranscriptInputs {
            contract_hash,
            prompt_template_hash,
            initiator_submission_hash: initiator_sub,
            responder_submission_hash: responder_sub,
            output_hash,
            receipt_signing_pubkey_hex: pubkey_hex,
        };
        let computed = compute_transcript_hash(&inputs);
        let computed_hex = hex::encode(computed);

        // Compare against user_data_hex (the platform attestation binding),
        // falling back to transcript_hash_hex with explicit tracking of which
        // field was used so callers can distinguish assurance levels.
        let (hash_valid, binding) = match &tee_att.user_data_hex {
            Some(user_data) => (computed_hex == *user_data, TranscriptBinding::UserData),
            None => match &tee_att.transcript_hash_hex {
                Some(th) => (
                    computed_hex == *th,
                    TranscriptBinding::TranscriptHashFallback,
                ),
                None => (false, TranscriptBinding::None),
            },
        };
        (hash_valid, binding)
    };

    // 5. Check submission hashes present
    let submission_hashes_present = receipt.commitments.initiator_submission_hash.is_some()
        && receipt.commitments.responder_submission_hash.is_some();

    Ok(TeeVerificationResult {
        measurement_match,
        attestation_status: AttestationStatus::QuoteUnverified,
        signature_status,
        attestation_hash_status,
        transcript_hash_valid,
        transcript_binding,
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
