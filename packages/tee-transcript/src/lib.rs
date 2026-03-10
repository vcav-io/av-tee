#![forbid(unsafe_code)]

use sha2::{Digest, Sha512};

pub const TRANSCRIPT_VERSION: &str = "av-tee-transcript-v1";
pub const TRANSCRIPT_VERSION_V2: &str = "av-tee-transcript-v2";

/// Structured input for transcript hashing.
///
/// Uses a struct rather than positional parameters to prevent ordering
/// mistakes and to make adding fields a non-breaking change.
pub struct TranscriptInputs<'a> {
    pub contract_hash: &'a str,
    pub prompt_template_hash: &'a str,
    pub initiator_submission_hash: &'a str,
    pub responder_submission_hash: &'a str,
    pub output_hash: &'a str,
    pub receipt_signing_pubkey_hex: &'a str,
    // provider_id and model_id are intentionally excluded from transcript
    // binding in v1. They are attested via existing receipt claims fields.
    // Use TranscriptInputsV2 for model identity binding.
}

/// V2 transcript inputs — adds model identity binding to the attestation.
///
/// `model_identity_asserted` is the composite provider/model string
/// (e.g. `"anthropic/claude-sonnet-4-5-20250929"`). Pass `""` when no
/// model was invoked (failure receipts, echo mode).
pub struct TranscriptInputsV2<'a> {
    pub contract_hash: &'a str,
    pub prompt_template_hash: &'a str,
    pub initiator_submission_hash: &'a str,
    pub responder_submission_hash: &'a str,
    pub output_hash: &'a str,
    pub receipt_signing_pubkey_hex: &'a str,
    pub model_identity_asserted: &'a str,
}

/// Compute the 64-byte transcript hash for SEV-SNP `user_data` binding.
///
/// SHA-512 of canonical JSON with sorted keys. The `version` field is
/// prepended to enable versioned upgrades.
///
/// Returns the full 64 bytes — maps directly to SEV-SNP's `user_data` field.
pub fn compute_transcript_hash(inputs: &TranscriptInputs) -> [u8; 64] {
    // Canonical JSON with sorted keys — constructed manually to avoid
    // serde_json key ordering ambiguity. Keys are ASCII-sorted.
    let canonical = format!(
        concat!(
            "{{",
            "\"contract_hash\":\"{}\",",
            "\"initiator_submission_hash\":\"{}\",",
            "\"output_hash\":\"{}\",",
            "\"prompt_template_hash\":\"{}\",",
            "\"receipt_signing_pubkey_hex\":\"{}\",",
            "\"responder_submission_hash\":\"{}\",",
            "\"version\":\"{}\"",
            "}}"
        ),
        inputs.contract_hash,
        inputs.initiator_submission_hash,
        inputs.output_hash,
        inputs.prompt_template_hash,
        inputs.receipt_signing_pubkey_hex,
        inputs.responder_submission_hash,
        TRANSCRIPT_VERSION,
    );

    let mut hasher = Sha512::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

/// V2 transcript hash — includes `model_identity_asserted` in the binding.
///
/// Same algorithm as v1 (SHA-512 of canonical JSON with sorted keys) but
/// with an additional field and `TRANSCRIPT_VERSION_V2`.
pub fn compute_transcript_hash_v2(inputs: &TranscriptInputsV2) -> [u8; 64] {
    let canonical = format!(
        concat!(
            "{{",
            "\"contract_hash\":\"{}\",",
            "\"initiator_submission_hash\":\"{}\",",
            "\"model_identity_asserted\":\"{}\",",
            "\"output_hash\":\"{}\",",
            "\"prompt_template_hash\":\"{}\",",
            "\"receipt_signing_pubkey_hex\":\"{}\",",
            "\"responder_submission_hash\":\"{}\",",
            "\"version\":\"{}\"",
            "}}"
        ),
        inputs.contract_hash,
        inputs.initiator_submission_hash,
        inputs.model_identity_asserted,
        inputs.output_hash,
        inputs.prompt_template_hash,
        inputs.receipt_signing_pubkey_hex,
        inputs.responder_submission_hash,
        TRANSCRIPT_VERSION_V2,
    );

    let mut hasher = Sha512::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> TranscriptInputs<'static> {
        TranscriptInputs {
            contract_hash: "aaaa",
            prompt_template_hash: "bbbb",
            initiator_submission_hash: "cccc",
            responder_submission_hash: "dddd",
            output_hash: "eeee",
            receipt_signing_pubkey_hex: "ffff",
        }
    }

    #[test]
    fn deterministic_same_inputs_same_hash() {
        let h1 = compute_transcript_hash(&sample_inputs());
        let h2 = compute_transcript_hash(&sample_inputs());
        assert_eq!(h1, h2);
    }

    #[test]
    fn sensitive_to_contract_hash_change() {
        let base = compute_transcript_hash(&sample_inputs());
        let changed = compute_transcript_hash(&TranscriptInputs {
            contract_hash: "xxxx",
            ..sample_inputs()
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn sensitive_to_prompt_template_hash_change() {
        let base = compute_transcript_hash(&sample_inputs());
        let changed = compute_transcript_hash(&TranscriptInputs {
            prompt_template_hash: "xxxx",
            ..sample_inputs()
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn sensitive_to_initiator_submission_hash_change() {
        let base = compute_transcript_hash(&sample_inputs());
        let changed = compute_transcript_hash(&TranscriptInputs {
            initiator_submission_hash: "xxxx",
            ..sample_inputs()
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn sensitive_to_responder_submission_hash_change() {
        let base = compute_transcript_hash(&sample_inputs());
        let changed = compute_transcript_hash(&TranscriptInputs {
            responder_submission_hash: "xxxx",
            ..sample_inputs()
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn sensitive_to_output_hash_change() {
        let base = compute_transcript_hash(&sample_inputs());
        let changed = compute_transcript_hash(&TranscriptInputs {
            output_hash: "xxxx",
            ..sample_inputs()
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn sensitive_to_receipt_signing_pubkey_change() {
        let base = compute_transcript_hash(&sample_inputs());
        let changed = compute_transcript_hash(&TranscriptInputs {
            receipt_signing_pubkey_hex: "xxxx",
            ..sample_inputs()
        });
        assert_ne!(base, changed);
    }

    #[test]
    #[ignore] // Run manually: cargo test -p tee-transcript golden_bootstrap -- --ignored --nocapture
    fn golden_bootstrap() {
        let hash = compute_transcript_hash(&sample_inputs());
        println!("GOLDEN_HASH={}", hex::encode(hash)); // SAFETY: no plaintext
    }

    #[test]
    fn golden_fixture_parity() {
        let hash = compute_transcript_hash(&sample_inputs());
        assert_eq!(
            hex::encode(hash),
            "b0fceb1f1dfd40fab87a529883810443dabde5416f0d06fbc57026a8bff0989c233781c7beeca30d85154ea3896eba00e21d99a8aac2dbd05ae85bb1e806a256",
            "golden fixture changed — update TS verifier if this changes"
        );
    }

    #[test]
    fn hash_is_64_bytes() {
        let h = compute_transcript_hash(&sample_inputs());
        assert_eq!(h.len(), 64);
    }

    // ── V2 tests ──────────────────────────────────────────────────────

    fn sample_inputs_v2() -> TranscriptInputsV2<'static> {
        TranscriptInputsV2 {
            contract_hash: "aaaa",
            prompt_template_hash: "bbbb",
            initiator_submission_hash: "cccc",
            responder_submission_hash: "dddd",
            output_hash: "eeee",
            receipt_signing_pubkey_hex: "ffff",
            model_identity_asserted: "anthropic/test-model",
        }
    }

    #[test]
    fn deterministic_v2_same_inputs_same_hash() {
        let h1 = compute_transcript_hash_v2(&sample_inputs_v2());
        let h2 = compute_transcript_hash_v2(&sample_inputs_v2());
        assert_eq!(h1, h2);
    }

    #[test]
    fn sensitive_to_model_identity_asserted_change() {
        let base = compute_transcript_hash_v2(&sample_inputs_v2());
        let changed = compute_transcript_hash_v2(&TranscriptInputsV2 {
            model_identity_asserted: "anthropic/different-model",
            ..sample_inputs_v2()
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn v1_and_v2_differ_for_same_base_inputs() {
        let v1 = compute_transcript_hash(&sample_inputs());
        let v2 = compute_transcript_hash_v2(&TranscriptInputsV2 {
            contract_hash: "aaaa",
            prompt_template_hash: "bbbb",
            initiator_submission_hash: "cccc",
            responder_submission_hash: "dddd",
            output_hash: "eeee",
            receipt_signing_pubkey_hex: "ffff",
            model_identity_asserted: "",
        });
        assert_ne!(
            v1, v2,
            "v1 and v2 must differ even with empty model_identity_asserted"
        );
    }

    #[test]
    fn v2_hash_is_64_bytes() {
        let h = compute_transcript_hash_v2(&sample_inputs_v2());
        assert_eq!(h.len(), 64);
    }

    #[test]
    #[ignore] // Run manually: cargo test -p tee-transcript golden_bootstrap_v2 -- --ignored --nocapture
    fn golden_bootstrap_v2() {
        let hash = compute_transcript_hash_v2(&sample_inputs_v2());
        println!("GOLDEN_HASH_V2={}", hex::encode(hash)); // SAFETY: no plaintext
    }

    #[test]
    fn golden_fixture_parity_v2() {
        let hash = compute_transcript_hash_v2(&sample_inputs_v2());
        // Bootstrap: run golden_bootstrap_v2 to generate, then paste here
        assert_eq!(
            hex::encode(hash),
            "2731b2be1576ab14e1f94543ccbd60ae8185591f9d097aec6536fd1fe5a281783933c46970696dd02891c7ca123adf0afcd7bb10bf2589fd76c3350a49c3dc65",
            "golden v2 fixture changed — update TS verifier if this changes"
        );
    }
}
