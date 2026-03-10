use base64::Engine;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use receipt_core::{
    AssuranceLevel, BudgetEnforcementMode, BudgetUsageV2, CANONICALIZATION_V2,
    CHANNEL_CAPACITY_MEASUREMENT_VERSION, Claims, Commitments, ExecutionLaneV2, HashAlgorithm,
    InputCommitment, Operator, ReceiptV2, SCHEMA_VERSION_V2, SessionStatus, TeeAttestation,
    TeeType, TokenUsage, UnsignedReceiptV2, sign_and_assemble_receipt_v2,
};
use tee_transcript::{
    TranscriptInputs, TranscriptInputsV2, compute_transcript_hash, compute_transcript_hash_v2,
};
use tee_verifier::{
    AttestationHashStatus, AttestationStatus, MeasurementEntry, QuoteVerifyError,
    SevSnpQuoteVerifier, SimulatedQuoteVerifier, StaticAllowlist, TranscriptSchema,
    verify_tee_receipt,
};

// ---------------------------------------------------------------------------
// Fixture builder
// ---------------------------------------------------------------------------

fn simulated_measurement() -> String {
    hex::encode(Sha256::digest(b"av-tee-simulated-v1"))
}

/// Builds a quote given the transcript hash.
type QuoteBuilder = Box<dyn FnOnce(&[u8; 64]) -> (Vec<u8>, String)>;

fn simulated_quote_builder() -> QuoteBuilder {
    Box::new(|transcript_hash: &[u8; 64]| {
        let mut qb = Vec::from(&b"simulated-quote:"[..]);
        qb.extend_from_slice(transcript_hash);
        (qb, simulated_measurement())
    })
}

fn snp_quote_builder(measurement: [u8; 48]) -> QuoteBuilder {
    Box::new(move |transcript_hash: &[u8; 64]| {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&2u32.to_le_bytes());
        report[80..144].copy_from_slice(transcript_hash);
        report[144..192].copy_from_slice(&measurement);
        (report, hex::encode(measurement))
    })
}

fn build_receipt(quote_builder: QuoteBuilder) -> (ReceiptV2, SigningKey) {
    build_receipt_with_vcek(quote_builder, None)
}

fn build_receipt_with_vcek(
    quote_builder: QuoteBuilder,
    snp_vcek_cert: Option<String>,
) -> (ReceiptV2, SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let pubkey_hex = receipt_core::public_key_to_hex(&signing_key.verifying_key());

    let contract_hash = hex::encode(Sha256::digest(b"test-contract"));
    let schema_hash = hex::encode(Sha256::digest(b"test-schema"));
    let output_hash = hex::encode(Sha256::digest(b"test-output"));
    let prompt_template_hash = hex::encode(Sha256::digest(b"test-prompt-template"));
    let initiator_sub_hash = hex::encode(Sha256::digest(b"test-initiator-input"));
    let responder_sub_hash = hex::encode(Sha256::digest(b"test-responder-input"));

    let model_identity_asserted = "test-model";
    let inputs = TranscriptInputsV2 {
        contract_hash: &contract_hash,
        prompt_template_hash: &prompt_template_hash,
        initiator_submission_hash: &initiator_sub_hash,
        responder_submission_hash: &responder_sub_hash,
        output_hash: &output_hash,
        receipt_signing_pubkey_hex: &pubkey_hex,
        model_identity_asserted,
    };
    let transcript_hash = compute_transcript_hash_v2(&inputs);

    let (quote_bytes, measurement) = quote_builder(&transcript_hash);

    let b64 = base64::engine::general_purpose::STANDARD;
    let quote_b64 = b64.encode(&quote_bytes);
    let attestation_hash = hex::encode(Sha256::digest(&quote_bytes));
    let user_data_hex = hex::encode(transcript_hash);
    let transcript_hash_hex = hex::encode(transcript_hash);
    let operator_key_fingerprint = hex::encode(Sha256::digest(hex::decode(&pubkey_hex).unwrap()));

    let unsigned = UnsignedReceiptV2 {
        receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
        receipt_canonicalization: CANONICALIZATION_V2.to_string(),
        receipt_id: "test-receipt-001".to_string(),
        session_id: "test-session-001".to_string(),
        issued_at: chrono::Utc::now(),
        assurance_level: AssuranceLevel::SelfAsserted,
        operator: Operator {
            operator_id: "test-relay".to_string(),
            operator_key_fingerprint,
            operator_key_discovery: None,
        },
        commitments: Commitments {
            contract_hash,
            schema_hash,
            output_hash,
            input_commitments: vec![InputCommitment {
                participant_id: "initiator".to_string(),
                input_hash: initiator_sub_hash.clone(),
                hash_alg: HashAlgorithm::Sha256,
                canonicalization: "CANONICAL_JSON_V1".to_string(),
            }],
            assembled_prompt_hash: hex::encode(Sha256::digest(b"test-assembled-prompt")),
            prompt_assembly_version: "1.0.0".to_string(),
            output: Some(serde_json::json!({"score": 4})),
            prompt_template_hash: Some(prompt_template_hash),
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            rejected_output_hash: None,
            initiator_submission_hash: Some(initiator_sub_hash),
            responder_submission_hash: Some(responder_sub_hash),
        },
        claims: Claims {
            model_identity_asserted: Some(model_identity_asserted.to_string()),
            model_identity_attested: None,
            model_profile_hash_asserted: None,
            runtime_hash_asserted: None,
            runtime_hash_attested: None,
            budget_enforcement_mode: Some(BudgetEnforcementMode::Enforced),
            provider_latency_ms: Some(100),
            token_usage: Some(TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 50,
                total_tokens: 150,
            }),
            relay_software_version: Some("0.1.0".to_string()),
            status: Some(SessionStatus::Success),
            signal_class: Some("SESSION_COMPLETED".to_string()),
            execution_lane: Some(ExecutionLaneV2::Tee),
            channel_capacity_bits_upper_bound: Some(3),
            channel_capacity_measurement_version: Some(
                CHANNEL_CAPACITY_MEASUREMENT_VERSION.to_string(),
            ),
            entropy_budget_bits: Some(128),
            schema_entropy_ceiling_bits: Some(3),
            budget_usage: Some(BudgetUsageV2 {
                bits_used_before: 0,
                bits_used_after: 3,
                budget_limit: 128,
            }),
        },
        provider_attestation: None,
        tee_attestation: Some(TeeAttestation {
            tee_type: Some(TeeType::Simulated),
            measurement: Some(measurement),
            quote: Some(quote_b64),
            attestation_hash: Some(attestation_hash),
            receipt_signing_pubkey_hex: Some(pubkey_hex),
            transcript_hash_hex: Some(transcript_hash_hex),
            user_data_hex: Some(user_data_hex),
            snp_vcek_cert,
        }),
    };

    let receipt = sign_and_assemble_receipt_v2(unsigned, &signing_key).unwrap();
    (receipt, signing_key)
}

/// Build a receipt using the v1 transcript hash (no model identity in hash).
/// Used to test verifier backward compatibility.
fn build_v1_receipt(quote_builder: QuoteBuilder) -> (ReceiptV2, SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let pubkey_hex = receipt_core::public_key_to_hex(&signing_key.verifying_key());

    let contract_hash = hex::encode(Sha256::digest(b"test-contract"));
    let schema_hash = hex::encode(Sha256::digest(b"test-schema"));
    let output_hash = hex::encode(Sha256::digest(b"test-output"));
    let prompt_template_hash = hex::encode(Sha256::digest(b"test-prompt-template"));
    let initiator_sub_hash = hex::encode(Sha256::digest(b"test-initiator-input"));
    let responder_sub_hash = hex::encode(Sha256::digest(b"test-responder-input"));

    // Use v1 transcript hash (no model_identity_asserted)
    let inputs = TranscriptInputs {
        contract_hash: &contract_hash,
        prompt_template_hash: &prompt_template_hash,
        initiator_submission_hash: &initiator_sub_hash,
        responder_submission_hash: &responder_sub_hash,
        output_hash: &output_hash,
        receipt_signing_pubkey_hex: &pubkey_hex,
    };
    let transcript_hash = compute_transcript_hash(&inputs);

    let (quote_bytes, measurement) = quote_builder(&transcript_hash);

    let b64 = base64::engine::general_purpose::STANDARD;
    let quote_b64 = b64.encode(&quote_bytes);
    let attestation_hash = hex::encode(Sha256::digest(&quote_bytes));
    let user_data_hex = hex::encode(transcript_hash);
    let transcript_hash_hex = hex::encode(transcript_hash);
    let operator_key_fingerprint = hex::encode(Sha256::digest(hex::decode(&pubkey_hex).unwrap()));

    let unsigned = UnsignedReceiptV2 {
        receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
        receipt_canonicalization: CANONICALIZATION_V2.to_string(),
        receipt_id: "test-receipt-v1-001".to_string(),
        session_id: "test-session-v1-001".to_string(),
        issued_at: chrono::Utc::now(),
        assurance_level: AssuranceLevel::SelfAsserted,
        operator: Operator {
            operator_id: "test-relay".to_string(),
            operator_key_fingerprint,
            operator_key_discovery: None,
        },
        commitments: Commitments {
            contract_hash,
            schema_hash,
            output_hash,
            input_commitments: vec![InputCommitment {
                participant_id: "initiator".to_string(),
                input_hash: initiator_sub_hash.clone(),
                hash_alg: HashAlgorithm::Sha256,
                canonicalization: "CANONICAL_JSON_V1".to_string(),
            }],
            assembled_prompt_hash: hex::encode(Sha256::digest(b"test-assembled-prompt")),
            prompt_assembly_version: "1.0.0".to_string(),
            output: Some(serde_json::json!({"score": 4})),
            prompt_template_hash: Some(prompt_template_hash),
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            rejected_output_hash: None,
            initiator_submission_hash: Some(initiator_sub_hash),
            responder_submission_hash: Some(responder_sub_hash),
        },
        claims: Claims {
            model_identity_asserted: Some("test-model".to_string()),
            model_identity_attested: None,
            model_profile_hash_asserted: None,
            runtime_hash_asserted: None,
            runtime_hash_attested: None,
            budget_enforcement_mode: Some(BudgetEnforcementMode::Enforced),
            provider_latency_ms: Some(100),
            token_usage: Some(TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 50,
                total_tokens: 150,
            }),
            relay_software_version: Some("0.1.0".to_string()),
            status: Some(SessionStatus::Success),
            signal_class: Some("SESSION_COMPLETED".to_string()),
            execution_lane: Some(ExecutionLaneV2::Tee),
            channel_capacity_bits_upper_bound: Some(3),
            channel_capacity_measurement_version: Some(
                CHANNEL_CAPACITY_MEASUREMENT_VERSION.to_string(),
            ),
            entropy_budget_bits: Some(128),
            schema_entropy_ceiling_bits: Some(3),
            budget_usage: Some(BudgetUsageV2 {
                bits_used_before: 0,
                bits_used_after: 3,
                budget_limit: 128,
            }),
        },
        provider_attestation: None,
        tee_attestation: Some(TeeAttestation {
            tee_type: Some(TeeType::Simulated),
            measurement: Some(measurement),
            quote: Some(quote_b64),
            attestation_hash: Some(attestation_hash),
            receipt_signing_pubkey_hex: Some(pubkey_hex),
            transcript_hash_hex: Some(transcript_hash_hex),
            user_data_hex: Some(user_data_hex),
            snp_vcek_cert: None,
        }),
    };

    let receipt = sign_and_assemble_receipt_v2(unsigned, &signing_key).unwrap();
    (receipt, signing_key)
}

fn allowlist_with(measurement: &str) -> StaticAllowlist {
    StaticAllowlist::from_entries(vec![MeasurementEntry {
        measurement: measurement.to_string(),
        build_id: "test-v0.1.0".to_string(),
        git_rev: "abc1234".to_string(),
        oci_digest: None,
        artifact_hash: None,
        toolchain: None,
        timestamp: None,
    }])
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn simulated_receipt_full_verification() {
    let (receipt, _key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;

    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert!(result.is_valid(), "is_valid() should return true");
    assert!(result.is_valid_parsed());
    assert!(result.is_valid_sans_quote());
    assert_eq!(result.attestation_status, AttestationStatus::QuoteVerified);
    assert_eq!(
        result.transcript_schema,
        Some(TranscriptSchema::V2),
        "v2 receipt should report TranscriptSchema::V2"
    );
}

#[test]
fn v1_receipt_verifies_with_fallback() {
    // Build a receipt using v1 transcript hash (no model_identity_asserted in hash).
    // Verifier should fall back to v1 and report TranscriptSchema::V1.
    let (receipt, _key) = build_v1_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;

    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert!(
        result.transcript_hash_valid,
        "v1 transcript hash should verify via fallback"
    );
    assert_eq!(
        result.transcript_schema,
        Some(TranscriptSchema::V1),
        "v1 receipt should report TranscriptSchema::V1"
    );
    assert!(result.is_valid(), "v1 receipt should still be fully valid");
}

// ---------------------------------------------------------------------------
// Adversarial: quote/receipt mismatch (the load-bearing tests)
// ---------------------------------------------------------------------------

#[test]
fn quote_user_data_mismatch() {
    let (mut receipt, _key) = build_receipt(simulated_quote_builder());

    // Tamper: set user_data_hex to a different value (after signing, breaks binding)
    if let Some(ref mut tee_att) = receipt.tee_attestation {
        tee_att.user_data_hex = Some("ff".repeat(64));
    }

    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;
    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::UserDataMismatch)
    );
    assert!(!result.is_valid());
    assert!(!result.is_valid_parsed());
}

#[test]
fn quote_measurement_mismatch() {
    let (mut receipt, _key) = build_receipt(simulated_quote_builder());

    // Tamper: set measurement to a different value
    if let Some(ref mut tee_att) = receipt.tee_attestation {
        tee_att.measurement = Some("aa".repeat(32));
    }

    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;
    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::MeasurementMismatch)
    );
    assert!(!result.is_valid());
}

// ---------------------------------------------------------------------------
// Structural failures
// ---------------------------------------------------------------------------

#[test]
fn tampered_quote_bytes() {
    let (mut receipt, _key) = build_receipt(simulated_quote_builder());

    // Tamper: modify the quote bytes (breaks attestation_hash check)
    if let Some(ref mut tee_att) = receipt.tee_attestation {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut quote_bytes = b64.decode(tee_att.quote.as_ref().unwrap()).unwrap();
        quote_bytes[20] ^= 0xFF;
        tee_att.quote = Some(b64.encode(&quote_bytes));
    }

    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;
    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(
        result.attestation_hash_status,
        AttestationHashStatus::Mismatch
    );
}

#[test]
fn wrong_verifier_for_format() {
    let (receipt, _key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());

    // Use SNP verifier on a simulated quote — wrong format
    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert!(matches!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::WrongLength { .. })
    ));
    assert!(!result.is_valid());
}

// ---------------------------------------------------------------------------
// Parse-only SNP
// ---------------------------------------------------------------------------

#[test]
fn snp_parse_only_returns_parsed_not_verified() {
    let snp_measurement = [0xBB_u8; 48];
    let (receipt, _key) = build_receipt(snp_quote_builder(snp_measurement));
    let allowlist = allowlist_with(&hex::encode(snp_measurement));
    let verifier = SevSnpQuoteVerifier::parsing_only();

    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteParsed);
    assert!(!result.is_valid(), "is_valid requires ChainVerified");
    assert!(result.is_valid_parsed(), "is_valid_parsed accepts Parsed");
}

// ---------------------------------------------------------------------------
// Allowlist interaction
// ---------------------------------------------------------------------------

#[test]
fn valid_quote_unknown_measurement() {
    let (receipt, _key) = build_receipt(simulated_quote_builder());
    let allowlist = StaticAllowlist::from_entries(vec![]); // empty
    let verifier = SimulatedQuoteVerifier;

    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteVerified);
    assert!(result.measurement_match.is_none());
    assert!(!result.is_valid());
    assert!(!result.is_valid_parsed());
    assert!(!result.is_valid_sans_quote());
}

// ---------------------------------------------------------------------------
// Three is_valid* modes (semantic coverage)
// ---------------------------------------------------------------------------

#[test]
fn is_valid_requires_chain_verified() {
    let snp_measurement = [0xCC_u8; 48];
    let (receipt, _key) = build_receipt(snp_quote_builder(snp_measurement));
    let allowlist = allowlist_with(&hex::encode(snp_measurement));
    let verifier = SevSnpQuoteVerifier::parsing_only();

    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteParsed);
    assert!(!result.is_valid(), "is_valid requires ChainVerified");
    assert!(result.is_valid_parsed(), "is_valid_parsed accepts Parsed");
    assert!(
        result.is_valid_sans_quote(),
        "is_valid_sans_quote ignores attestation"
    );
}

#[test]
fn is_valid_parsed_accepts_both() {
    let (receipt, _key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;

    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteVerified);
    assert!(result.is_valid());
    assert!(result.is_valid_parsed());
    assert!(result.is_valid_sans_quote());
}

#[test]
fn is_valid_sans_quote_ignores_attestation() {
    let (receipt, _key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());

    // Use wrong verifier to get QuoteInvalid
    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

    assert!(matches!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(_)
    ));
    assert!(!result.is_valid());
    assert!(!result.is_valid_parsed());
    assert!(result.is_valid_sans_quote());
}

// ---------------------------------------------------------------------------
// SNP chain verification through verify_tee_receipt (Wave 2 — receipt-level)
//
// These test the step 2c code path in verify.rs: when snp_vcek_cert is present,
// QuoteParsed should be upgraded to QuoteVerified (or QuoteInvalid on failure).
// The positive path (QuoteParsed → QuoteVerified) requires a real AMD-signed VCEK
// and is not testable with synthetic certs. The negative paths are all tested.
// ---------------------------------------------------------------------------

mod snp_vcek_receipt_tests {
    use super::*;
    use tee_verifier::{QuoteVerifyError, SevSnpQuoteVerifier};

    #[test]
    fn malformed_base64_vcek_cert_is_quote_invalid() {
        // snp_vcek_cert present but not valid base64 → hard failure, not silent fallback
        let snp_measurement = [0xBB_u8; 48];
        let (receipt, _key) = build_receipt_with_vcek(
            snp_quote_builder(snp_measurement),
            Some("!!!not-valid-base64!!!".to_string()),
        );
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

        assert!(
            matches!(
                result.attestation_status,
                AttestationStatus::QuoteInvalid(QuoteVerifyError::ChainInvalid(ref msg))
                    if msg.contains("base64 decode failed")
            ),
            "expected QuoteInvalid with base64 error, got: {:?}",
            result.attestation_status
        );
        assert!(!result.is_valid());
        assert!(!result.is_valid_parsed());
    }

    #[test]
    fn garbage_der_vcek_cert_is_quote_invalid() {
        // snp_vcek_cert decodes as base64 but is not valid DER → hard failure
        let snp_measurement = [0xBB_u8; 48];
        let b64 = base64::engine::general_purpose::STANDARD;
        let garbage_b64 = base64::Engine::encode(&b64, &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB]);
        let (receipt, _key) =
            build_receipt_with_vcek(snp_quote_builder(snp_measurement), Some(garbage_b64));
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

        assert!(
            matches!(
                result.attestation_status,
                AttestationStatus::QuoteInvalid(QuoteVerifyError::ChainInvalid(ref msg))
                    if msg.contains("failed to parse VCEK")
            ),
            "expected QuoteInvalid with VCEK parse error, got: {:?}",
            result.attestation_status
        );
        assert!(!result.is_valid());
        assert!(!result.is_valid_parsed());
    }

    #[test]
    fn self_signed_vcek_cert_unsupported_family() {
        // Valid P-384 cert but not signed by any bundled AMD ASK → unsupported family
        let snp_measurement = [0xBB_u8; 48];
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert_params = rcgen::CertificateParams::new(vec!["test-vcek".into()]).unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let vcek_b64 = base64::Engine::encode(&b64, cert.der());

        let (receipt, _key) =
            build_receipt_with_vcek(snp_quote_builder(snp_measurement), Some(vcek_b64));
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

        assert!(
            matches!(
                result.attestation_status,
                AttestationStatus::QuoteInvalid(QuoteVerifyError::ChainInvalid(ref msg))
                    if msg.contains("unsupported product family")
            ),
            "expected QuoteInvalid with unsupported family, got: {:?}",
            result.attestation_status
        );
        assert!(!result.is_valid());
        assert!(!result.is_valid_parsed());
    }

    #[test]
    fn absent_vcek_cert_stays_parsed() {
        // snp_vcek_cert: None → stays at QuoteParsed (no chain verification attempted)
        let snp_measurement = [0xBB_u8; 48];
        let (receipt, _key) = build_receipt_with_vcek(snp_quote_builder(snp_measurement), None);
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_tee_receipt(&receipt, &allowlist, &verifier).unwrap();

        assert_eq!(
            result.attestation_status,
            AttestationStatus::QuoteParsed,
            "absent vcek cert should leave status at QuoteParsed"
        );
        assert!(!result.is_valid());
        assert!(result.is_valid_parsed());
    }
}

// ---------------------------------------------------------------------------
// SNP chain verification (direct snp_chain tests)
//
// These test snp_chain::verify_snp_attestation directly. They prove the
// verification model works with synthetic cert hierarchies.
// ---------------------------------------------------------------------------

mod snp_chain_tests {
    use tee_verifier::snp_chain;
    use tee_verifier::{QuoteVerifyError, TcbPolicy, VerificationConfig};

    #[test]
    fn snp_unsupported_family_rejected() {
        // Self-signed VCEK not in any AMD chain → unsupported family
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert_params = rcgen::CertificateParams::new(vec!["test-vcek".into()]).unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let vcek_der = cert.der().to_vec();

        let report = vec![0u8; 1184];
        let config = VerificationConfig::default();

        let err = snp_chain::verify_snp_attestation(&report, &vcek_der, &config).unwrap_err();
        assert!(
            matches!(err, QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("unsupported product family")),
            "expected unsupported family, got: {err}"
        );
    }

    #[test]
    fn snp_malformed_vcek_cert_rejected() {
        // Garbage DER → parse failure (not silent fallback)
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        let report = vec![0u8; 1184];
        let config = VerificationConfig::default();

        let err = snp_chain::verify_snp_attestation(&report, &garbage, &config).unwrap_err();
        assert!(
            matches!(err, QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("failed to parse VCEK")),
            "expected parse failure, got: {err}"
        );
    }

    #[test]
    fn snp_chain_types_are_exported() {
        let _config = VerificationConfig::default();
        let _policy = TcbPolicy {
            boot_loader_min: 1,
            tee_min: 0,
            snp_min: 0,
            microcode_min: 0,
        };
        let _family = tee_verifier::ProductFamily::Milan;
        let _family2 = tee_verifier::ProductFamily::Genoa;
    }
}

// ---------------------------------------------------------------------------
// SNP report signature verification (snp_sig — direct tests)
//
// These exercise the actual policy and signature checks in snp_sig, not
// through the chain (which requires AMD-signed certs). The unit tests in
// snp_sig::tests cover the same paths, but these integration tests confirm
// the public module boundary works correctly.
// ---------------------------------------------------------------------------

mod snp_sig_tests {
    use ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use tee_verifier::{QuoteVerifyError, snp_sig};

    const SIG_ALGO_OFFSET: usize = 52;
    const SIG_R_OFFSET: usize = 672;
    const SIG_S_OFFSET: usize = 744;
    const SIG_COMPONENT_LEN: usize = 72;
    const POLICY_OFFSET: usize = 8;
    const FLAGS_OFFSET: usize = 72;
    const SIGNED_REGION_END: usize = 672;

    fn be_to_le_padded(be_bytes: &[u8], pad_len: usize) -> Vec<u8> {
        let mut le: Vec<u8> = be_bytes.iter().rev().copied().collect();
        le.resize(pad_len, 0);
        le
    }

    fn build_signed_report(signing_key: &SigningKey, debug: bool, vlek: bool) -> Vec<u8> {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&2u32.to_le_bytes());

        // Policy (offset 8): bit 19 = DEBUG
        let mut policy: u64 = 0;
        if debug {
            policy |= 1 << 19;
        }
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());

        // Signature algo (offset 52, inside signed region)
        report[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());

        // Flags (offset 72): bit 0 = SIGNING_KEY (0=VCEK, 1=VLEK)
        let mut flags: u32 = 0;
        if vlek {
            flags |= 1;
        }
        report[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());

        report[80..144].copy_from_slice(&[0xAA; 64]);
        report[144..192].copy_from_slice(&[0xBB; 48]);

        // Sign (all header fields set before signing)
        let signed_region = &report[..SIGNED_REGION_END];
        let signature: Signature = signing_key.sign(signed_region);
        let sig_bytes = signature.to_bytes();
        report[SIG_R_OFFSET..SIG_R_OFFSET + SIG_COMPONENT_LEN]
            .copy_from_slice(&be_to_le_padded(&sig_bytes[..48], SIG_COMPONENT_LEN));
        report[SIG_S_OFFSET..SIG_S_OFFSET + SIG_COMPONENT_LEN]
            .copy_from_slice(&be_to_le_padded(&sig_bytes[48..], SIG_COMPONENT_LEN));

        report
    }

    #[test]
    fn valid_report_passes() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let report = build_signed_report(&sk, false, false);
        snp_sig::verify_report_signature(&report, &vk).unwrap();
    }

    #[test]
    fn tampered_report_rejected() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let mut report = build_signed_report(&sk, false, false);
        report[100] ^= 0xFF;
        let err = snp_sig::verify_report_signature(&report, &vk).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("signature invalid")
        ));
    }

    #[test]
    fn debug_mode_rejected() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let report = build_signed_report(&sk, true, false);
        let err = snp_sig::verify_report_signature(&report, &vk).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("DEBUG")
        ));
    }

    #[test]
    fn vlek_signer_rejected() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let report = build_signed_report(&sk, false, true);
        let err = snp_sig::verify_report_signature(&report, &vk).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("VLEK")
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = SigningKey::random(&mut OsRng);
        let wrong_vk = VerifyingKey::from(&SigningKey::random(&mut OsRng));
        let report = build_signed_report(&sk, false, false);
        let err = snp_sig::verify_report_signature(&report, &wrong_vk).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("signature invalid")
        ));
    }
}
