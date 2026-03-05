#![forbid(unsafe_code)]

use sha2::{Digest, Sha512};

pub const TRANSCRIPT_VERSION: &str = "av-tee-transcript-v1";

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
    // If future verification requires binding provider identity to the
    // attestation, add them here and bump TRANSCRIPT_VERSION.
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
}
