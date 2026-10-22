//! Transcript v3 and the relay configuration binding.
//!
//! # Encoding
//!
//! Both hashes use the same length-prefixed encoding. `LP(x)` is the length of
//! `x` in bytes as a big-endian u64, followed by the bytes of `x` (UTF-8 for
//! strings). The encoding is
//!
//! ```text
//! LP(version) || LP(name_1) || LP(value_1) || ... || LP(name_n) || LP(value_n)
//! ```
//!
//! with the fields in the fixed order listed on each struct. Field names are
//! part of the encoding, so a value can never be read as a different field,
//! and no value is escaped or interpreted.
//!
//! - Relay configuration hash: `SHA-256` of the encoding with version
//!   [`RELAY_CONFIG_VERSION`], hex-encoded (64 lowercase characters).
//! - Transcript hash: `SHA-512` of the encoding with version
//!   [`TRANSCRIPT_VERSION_V3`]: 64 bytes, used as SEV-SNP `REPORT_DATA`.
//!
//! Golden vectors: `tests/fixtures/transcript_v3_golden.json`.

use serde::{Deserialize, Serialize};

use crate::{push_length_prefixed, sha256, sha512};

pub const TRANSCRIPT_VERSION_V3: &str = "av-tee-transcript-v3";
pub const RELAY_CONFIG_VERSION: &str = "av-tee-relay-config-v1";

/// Configuration the relay ran with, bound into transcript v3 through
/// [`compute_relay_config_hash`].
///
/// A verifier that has the plaintext configuration recomputes the hash, and
/// can then apply its own policy to the values (for example, require
/// `provider_base_url == "https://api.anthropic.com"` and `simulated == false`).
///
/// The binding shows which configuration the attested transcript was
/// computed with. On platforms where the attestation measurement does not
/// cover the relay binary, it does not show which code computed it.
///
/// Encoded fields, in this order: `provider_id`, `provider_base_url`,
/// `model_id_requested`, `policy_lockfile_hash`,
/// `model_profile_allowlist_hash`, `relay_git_rev`, `echo_mode`, `simulated`,
/// `env`. Booleans are encoded as the strings `"true"` / `"false"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Model provider, e.g. `"anthropic"`.
    pub provider_id: String,
    /// Base URL the relay sends provider requests to.
    pub provider_base_url: String,
    /// Model id the relay requests from the provider (the provider reports
    /// the model it used separately, in `model_identity_asserted`).
    pub model_id_requested: String,
    /// Hash of the policy lockfile the relay enforces, or `""` if none.
    pub policy_lockfile_hash: String,
    /// Hash of the model profile allowlist, or `""` if none.
    pub model_profile_allowlist_hash: String,
    /// Source revision the relay was built from (`"unknown"` if the build
    /// did not record it).
    pub relay_git_rev: String,
    /// The relay runs in echo mode (no model call).
    pub echo_mode: bool,
    /// The relay runs on a simulated CVM, not a hardware TEE.
    pub simulated: bool,
    /// Deployment environment label, or `""` if unset.
    pub env: String,
}

fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

impl RelayConfig {
    /// The length-prefixed encoding that [`compute_relay_config_hash`] hashes.
    pub fn encode(&self) -> Vec<u8> {
        let fields: [(&str, &str); 9] = [
            ("provider_id", &self.provider_id),
            ("provider_base_url", &self.provider_base_url),
            ("model_id_requested", &self.model_id_requested),
            ("policy_lockfile_hash", &self.policy_lockfile_hash),
            (
                "model_profile_allowlist_hash",
                &self.model_profile_allowlist_hash,
            ),
            ("relay_git_rev", &self.relay_git_rev),
            ("echo_mode", bool_str(self.echo_mode)),
            ("simulated", bool_str(self.simulated)),
            ("env", &self.env),
        ];
        encode_fields(RELAY_CONFIG_VERSION, &fields)
    }

    /// `hex(SHA-256(encode()))`.
    pub fn hash_hex(&self) -> String {
        hex::encode(compute_relay_config_hash(self))
    }
}

/// SHA-256 of the length-prefixed relay configuration encoding.
pub fn compute_relay_config_hash(config: &RelayConfig) -> [u8; 32] {
    sha256(&config.encode())
}

/// V3 transcript inputs: the v2 fields plus the relay configuration hash.
///
/// Encoded fields, in this order: `contract_hash`, `prompt_template_hash`,
/// `initiator_submission_hash`, `responder_submission_hash`, `output_hash`,
/// `receipt_signing_pubkey_hex`, `model_identity_asserted`,
/// `relay_config_hash`. A field absent from the receipt is encoded as `""`.
pub struct TranscriptInputsV3<'a> {
    pub contract_hash: &'a str,
    pub prompt_template_hash: &'a str,
    pub initiator_submission_hash: &'a str,
    pub responder_submission_hash: &'a str,
    pub output_hash: &'a str,
    pub receipt_signing_pubkey_hex: &'a str,
    /// Provider-reported model identity (`"provider/model"`), or `""` when no
    /// model was invoked.
    pub model_identity_asserted: &'a str,
    /// `RelayConfig::hash_hex()` of the relay's configuration.
    pub relay_config_hash: &'a str,
}

impl TranscriptInputsV3<'_> {
    /// The length-prefixed encoding that [`compute_transcript_hash_v3`] hashes.
    pub fn encode(&self) -> Vec<u8> {
        let fields: [(&str, &str); 8] = [
            ("contract_hash", self.contract_hash),
            ("prompt_template_hash", self.prompt_template_hash),
            ("initiator_submission_hash", self.initiator_submission_hash),
            ("responder_submission_hash", self.responder_submission_hash),
            ("output_hash", self.output_hash),
            (
                "receipt_signing_pubkey_hex",
                self.receipt_signing_pubkey_hex,
            ),
            ("model_identity_asserted", self.model_identity_asserted),
            ("relay_config_hash", self.relay_config_hash),
        ];
        encode_fields(TRANSCRIPT_VERSION_V3, &fields)
    }
}

/// 64-byte v3 transcript hash for SEV-SNP `REPORT_DATA` binding.
pub fn compute_transcript_hash_v3(inputs: &TranscriptInputsV3) -> [u8; 64] {
    sha512(&inputs.encode())
}

fn encode_fields(version: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let capacity = 8
        + version.len()
        + fields
            .iter()
            .map(|(name, value)| 16 + name.len() + value.len())
            .sum::<usize>();
    let mut out = Vec::with_capacity(capacity);
    push_length_prefixed(&mut out, version.as_bytes());
    for (name, value) in fields {
        push_length_prefixed(&mut out, name.as_bytes());
        push_length_prefixed(&mut out, value.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TranscriptInputsV2, compute_transcript_hash_v2};
    use serde_json::Value;

    const GOLDEN: &str = include_str!("../../../tests/fixtures/transcript_v3_golden.json");

    fn golden() -> Value {
        serde_json::from_str(GOLDEN).expect("golden fixture parses")
    }

    fn config_from(v: &Value) -> RelayConfig {
        serde_json::from_value(v.clone()).expect("relay_config parses")
    }

    fn s<'a>(v: &'a Value, key: &str) -> &'a str {
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing string {key}"))
    }

    fn v3_inputs(v: &Value) -> TranscriptInputsV3<'_> {
        TranscriptInputsV3 {
            contract_hash: s(v, "contract_hash"),
            prompt_template_hash: s(v, "prompt_template_hash"),
            initiator_submission_hash: s(v, "initiator_submission_hash"),
            responder_submission_hash: s(v, "responder_submission_hash"),
            output_hash: s(v, "output_hash"),
            receipt_signing_pubkey_hex: s(v, "receipt_signing_pubkey_hex"),
            model_identity_asserted: s(v, "model_identity_asserted"),
            relay_config_hash: s(v, "relay_config_hash"),
        }
    }

    fn v2_inputs(v: &Value) -> TranscriptInputsV2<'_> {
        TranscriptInputsV2 {
            contract_hash: s(v, "contract_hash"),
            prompt_template_hash: s(v, "prompt_template_hash"),
            initiator_submission_hash: s(v, "initiator_submission_hash"),
            responder_submission_hash: s(v, "responder_submission_hash"),
            output_hash: s(v, "output_hash"),
            receipt_signing_pubkey_hex: s(v, "receipt_signing_pubkey_hex"),
            model_identity_asserted: s(v, "model_identity_asserted"),
        }
    }

    /// The interpolated (unescaped) encoding style of transcripts v1/v2,
    /// applied to the relay configuration. Used only to show that the
    /// negative vectors would be ambiguous under that style.
    fn interpolated_config_encoding(c: &RelayConfig) -> String {
        format!(
            "{{\"echo_mode\":\"{}\",\"env\":\"{}\",\"model_id_requested\":\"{}\",\"model_profile_allowlist_hash\":\"{}\",\"policy_lockfile_hash\":\"{}\",\"provider_base_url\":\"{}\",\"provider_id\":\"{}\",\"relay_git_rev\":\"{}\",\"simulated\":\"{}\"}}",
            c.echo_mode,
            c.env,
            c.model_id_requested,
            c.model_profile_allowlist_hash,
            c.policy_lockfile_hash,
            c.provider_base_url,
            c.provider_id,
            c.relay_git_rev,
            c.simulated,
        )
    }

    #[test]
    fn length_prefix_is_big_endian_u64() {
        let mut out = Vec::new();
        push_length_prefixed(&mut out, b"abc");
        assert_eq!(out, [0, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn golden_relay_config_vectors() {
        let g = golden();
        let vectors = g["relay_config_vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let config = config_from(&v["relay_config"]);
            assert_eq!(
                config.hash_hex(),
                s(v, "expected_hash_hex"),
                "relay config vector {}",
                s(v, "name")
            );
            assert_eq!(
                hex::encode(config.encode()),
                s(v, "expected_encoding_hex"),
                "relay config vector {}",
                s(v, "name")
            );
        }
    }

    #[test]
    fn golden_transcript_v3_vectors() {
        let g = golden();
        let vectors = g["transcript_vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let inputs = v3_inputs(&v["inputs"]);
            assert_eq!(
                hex::encode(compute_transcript_hash_v3(&inputs)),
                s(v, "expected_hash_hex"),
                "transcript vector {}",
                s(v, "name")
            );
        }
    }

    #[test]
    fn golden_transcript_vector_uses_golden_relay_config_hash() {
        let g = golden();
        let config = config_from(&g["relay_config_vectors"][0]["relay_config"]);
        let inputs = &g["transcript_vectors"][0]["inputs"];
        assert_eq!(s(inputs, "relay_config_hash"), config.hash_hex());
    }

    /// Pairs of distinct inputs containing quote and delimiter characters.
    /// The v2 / interpolated encodings give both members of a pair the same
    /// bytes; the v3 encoding gives them different hashes.
    #[test]
    fn golden_negative_vectors_distinct_under_v3() {
        let g = golden();
        let vectors = g["negative_vectors"].as_array().unwrap();
        assert!(vectors.len() >= 3);
        for v in vectors {
            let name = s(v, "name");
            match s(v, "kind") {
                "transcript" => {
                    let (a, b) = (v3_inputs(&v["a"]), v3_inputs(&v["b"]));
                    let (ha, hb) = (
                        hex::encode(compute_transcript_hash_v3(&a)),
                        hex::encode(compute_transcript_hash_v3(&b)),
                    );
                    assert_ne!(ha, hb, "{name}: v3 must distinguish the pair");
                    assert_eq!(ha, s(v, "expected_hash_hex_a"), "{name}");
                    assert_eq!(hb, s(v, "expected_hash_hex_b"), "{name}");
                    assert_eq!(
                        compute_transcript_hash_v2(&v2_inputs(&v["a"])),
                        compute_transcript_hash_v2(&v2_inputs(&v["b"])),
                        "{name}: the pair is expected to be ambiguous under v2"
                    );
                }
                "relay_config" => {
                    let (a, b) = (config_from(&v["a"]), config_from(&v["b"]));
                    assert_ne!(a, b, "{name}: pair must differ");
                    assert_ne!(a.hash_hex(), b.hash_hex(), "{name}");
                    assert_eq!(a.hash_hex(), s(v, "expected_hash_hex_a"), "{name}");
                    assert_eq!(b.hash_hex(), s(v, "expected_hash_hex_b"), "{name}");
                    assert_eq!(
                        interpolated_config_encoding(&a),
                        interpolated_config_encoding(&b),
                        "{name}: the pair is expected to be ambiguous when interpolated"
                    );
                }
                other => panic!("unknown negative vector kind {other}"),
            }
        }
    }

    fn sample_config() -> RelayConfig {
        RelayConfig {
            provider_id: "anthropic".into(),
            provider_base_url: "https://api.anthropic.com".into(),
            model_id_requested: "claude-sonnet-4-5-20250929".into(),
            policy_lockfile_hash: String::new(),
            model_profile_allowlist_hash: String::new(),
            relay_git_rev: "0123abc".into(),
            echo_mode: false,
            simulated: false,
            env: String::new(),
        }
    }

    #[test]
    fn relay_config_hash_changes_with_every_field() {
        let base = sample_config().hash_hex();
        let variants: Vec<RelayConfig> = vec![
            RelayConfig {
                provider_id: "other".into(),
                ..sample_config()
            },
            RelayConfig {
                provider_base_url: "https://example.test".into(),
                ..sample_config()
            },
            RelayConfig {
                model_id_requested: "other-model".into(),
                ..sample_config()
            },
            RelayConfig {
                policy_lockfile_hash: "aa".into(),
                ..sample_config()
            },
            RelayConfig {
                model_profile_allowlist_hash: "bb".into(),
                ..sample_config()
            },
            RelayConfig {
                relay_git_rev: "fff".into(),
                ..sample_config()
            },
            RelayConfig {
                echo_mode: true,
                ..sample_config()
            },
            RelayConfig {
                simulated: true,
                ..sample_config()
            },
            RelayConfig {
                env: "dev".into(),
                ..sample_config()
            },
        ];
        for v in variants {
            assert_ne!(v.hash_hex(), base, "{v:?}");
        }
    }

    #[test]
    fn moving_bytes_between_adjacent_fields_changes_the_hash() {
        let a = RelayConfig {
            provider_base_url: "https://api.anthropic.com/".into(),
            model_id_requested: "m".into(),
            ..sample_config()
        };
        let b = RelayConfig {
            provider_base_url: "https://api.anthropic.com".into(),
            model_id_requested: "/m".into(),
            ..sample_config()
        };
        assert_ne!(a.hash_hex(), b.hash_hex());
    }

    #[test]
    fn relay_config_rejects_unknown_members() {
        let mut v = serde_json::to_value(sample_config()).unwrap();
        v["extra"] = Value::Bool(true);
        assert!(serde_json::from_value::<RelayConfig>(v).is_err());
    }

    #[test]
    fn v3_differs_from_v2_for_same_inputs() {
        let g = golden();
        let inputs = &g["transcript_vectors"][0]["inputs"];
        assert_ne!(
            compute_transcript_hash_v3(&v3_inputs(inputs)),
            compute_transcript_hash_v2(&v2_inputs(inputs))
        );
    }

    #[test]
    #[ignore] // Run manually: cargo test -p tee-transcript golden_bootstrap_v3 -- --ignored --nocapture
    fn golden_bootstrap_v3() {
        let g = golden();
        for v in g["relay_config_vectors"].as_array().unwrap() {
            let c = config_from(&v["relay_config"]);
            let line = format!(
                "{} {} {}",
                s(v, "name"),
                c.hash_hex(),
                hex::encode(c.encode())
            );
            println!("CONFIG {line}"); // SAFETY: no plaintext
        }
        for v in g["transcript_vectors"].as_array().unwrap() {
            let h = compute_transcript_hash_v3(&v3_inputs(&v["inputs"]));
            println!("TRANSCRIPT {} {}", s(v, "name"), hex::encode(h)); // SAFETY: no plaintext
        }
        for v in g["negative_vectors"].as_array().unwrap() {
            let (a, b) = match s(v, "kind") {
                "transcript" => (
                    hex::encode(compute_transcript_hash_v3(&v3_inputs(&v["a"]))),
                    hex::encode(compute_transcript_hash_v3(&v3_inputs(&v["b"]))),
                ),
                _ => (
                    config_from(&v["a"]).hash_hex(),
                    config_from(&v["b"]).hash_hex(),
                ),
            };
            println!("NEGATIVE {} {} {}", s(v, "name"), a, b); // SAFETY: no plaintext
        }
    }
}
