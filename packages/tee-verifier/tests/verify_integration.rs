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
    RelayConfig, TranscriptInputs, TranscriptInputsV2, TranscriptInputsV3, compute_transcript_hash,
    compute_transcript_hash_v2, compute_transcript_hash_v3,
};
use tee_verifier::{
    AttestationHashStatus, AttestationStatus, MeasurementEntry, QuoteVerifyError,
    SevSnpQuoteVerifier, SimulatedQuoteVerifier, StaticAllowlist, TranscriptSchema, VerifyOptions,
    verify_tee_receipt, verify_tee_receipt_with_options,
};

// ---------------------------------------------------------------------------
// Fixture builder
// ---------------------------------------------------------------------------

fn simulated_measurement() -> String {
    hex::encode(Sha256::digest(b"av-tee-simulated-v1"))
}

/// Builds a quote given the transcript hash: (quote bytes, measurement, tee_type).
type QuoteBuilder = Box<dyn FnOnce(&[u8; 64]) -> (Vec<u8>, String, TeeType)>;

fn simulated_quote_builder() -> QuoteBuilder {
    Box::new(|transcript_hash: &[u8; 64]| {
        let mut qb = Vec::from(&b"simulated-quote:"[..]);
        qb.extend_from_slice(transcript_hash);
        (qb, simulated_measurement(), TeeType::Simulated)
    })
}

fn snp_quote_builder(measurement: [u8; 48]) -> QuoteBuilder {
    Box::new(move |transcript_hash: &[u8; 64]| {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&2u32.to_le_bytes());
        report[80..144].copy_from_slice(transcript_hash);
        report[144..192].copy_from_slice(&measurement);
        (report, hex::encode(measurement), TeeType::SevSnp)
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

    let (quote_bytes, measurement, tee_type) = quote_builder(&transcript_hash);

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
            tee_type: Some(tee_type),
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

    let (quote_bytes, measurement, tee_type) = quote_builder(&transcript_hash);

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
            tee_type: Some(tee_type),
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

/// Verify with the relay key pinned (the key that signed the fixture).
fn verify_pinned<'a>(
    receipt: impl Into<tee_verifier::TeeReceipt<'a>>,
    key: &SigningKey,
    allowlist: &StaticAllowlist,
    verifier: &dyn tee_verifier::QuoteVerifier,
) -> Result<tee_verifier::TeeVerificationResult, tee_verifier::VerifyError> {
    tee_verifier::verify_tee_receipt_pinned(
        receipt,
        &key.verifying_key(),
        allowlist,
        verifier,
        None,
    )
}

fn allowlist_with(measurement: &str) -> StaticAllowlist {
    StaticAllowlist::from_entries(vec![MeasurementEntry {
        measurement: measurement.to_string(),
        platform: tee_verifier::MeasurementPlatform::Unspecified,
        description: None,
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
    let (receipt, key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;

    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    // A simulated quote is never platform-verified.
    assert_eq!(result.attestation_status, AttestationStatus::QuoteSimulated);
    assert!(!result.is_valid());
    assert!(!result.is_valid_parsed());
    assert!(result.is_valid_simulated());
    assert!(result.is_valid_sans_quote());
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
    let (receipt, key) = build_v1_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;

    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert!(
        result.transcript_hash_valid,
        "v1 transcript hash should verify via fallback"
    );
    assert_eq!(
        result.transcript_schema,
        Some(TranscriptSchema::V1),
        "v1 receipt should report TranscriptSchema::V1"
    );
    assert_eq!(
        result.transcript_schema.as_ref().unwrap().label(),
        "code/config unbound"
    );
    assert!(
        result.is_valid_simulated(),
        "v1 receipt should still be valid (simulated)"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: quote/receipt mismatch (the load-bearing tests)
// ---------------------------------------------------------------------------

#[test]
fn quote_user_data_mismatch() {
    let (mut receipt, key) = build_receipt(simulated_quote_builder());

    // Tamper: set user_data_hex to a different value (after signing, breaks binding)
    if let Some(ref mut tee_att) = receipt.tee_attestation {
        tee_att.user_data_hex = Some("ff".repeat(64));
    }

    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;
    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert_eq!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::UserDataMismatch)
    );
    assert!(!result.is_valid());
    assert!(!result.is_valid_parsed());
}

#[test]
fn quote_measurement_mismatch() {
    let (mut receipt, key) = build_receipt(simulated_quote_builder());

    // Tamper: set measurement to a different value
    if let Some(ref mut tee_att) = receipt.tee_attestation {
        tee_att.measurement = Some("aa".repeat(32));
    }

    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;
    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

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
    let (mut receipt, key) = build_receipt(simulated_quote_builder());

    // Tamper: modify the quote bytes (breaks attestation_hash check)
    if let Some(ref mut tee_att) = receipt.tee_attestation {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut quote_bytes = b64.decode(tee_att.quote.as_ref().unwrap()).unwrap();
        quote_bytes[20] ^= 0xFF;
        tee_att.quote = Some(b64.encode(&quote_bytes));
    }

    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;
    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert_eq!(
        result.attestation_hash_status,
        AttestationHashStatus::Mismatch
    );
}

#[test]
fn wrong_verifier_for_format() {
    let (mut receipt, key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    // Claim SEV-SNP for a simulated quote, so the SNP parser sees it.
    receipt.tee_attestation.as_mut().unwrap().tee_type = Some(TeeType::SevSnp);

    // Use SNP verifier on a simulated quote — wrong format
    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert!(matches!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::WrongLength { .. })
    ));
    assert!(!result.is_valid());
}

#[test]
fn simulated_receipt_is_rejected_by_the_snp_verifier() {
    let (receipt, key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_pinned(
        &receipt,
        &key,
        &allowlist,
        &SevSnpQuoteVerifier::parsing_only(),
    )
    .unwrap();

    assert_eq!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::TeeTypeMismatch {
            receipt: Some(TeeType::Simulated),
            verifier: TeeType::SevSnp,
        })
    );
    assert!(!result.is_valid_parsed());
}

#[test]
fn snp_receipt_is_rejected_by_the_simulated_verifier() {
    let snp_measurement = [0xBB_u8; 48];
    let (receipt, key) = build_receipt(snp_quote_builder(snp_measurement));
    let allowlist = allowlist_with(&hex::encode(snp_measurement));

    let result = verify_pinned(&receipt, &key, &allowlist, &SimulatedQuoteVerifier).unwrap();

    assert!(matches!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::TeeTypeMismatch { .. })
    ));
    assert!(!result.is_valid_simulated());
}

#[test]
fn receipt_without_tee_type_is_rejected() {
    let (mut receipt, key) = build_receipt(simulated_quote_builder());
    receipt.tee_attestation.as_mut().unwrap().tee_type = None;
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_pinned(&receipt, &key, &allowlist, &SimulatedQuoteVerifier).unwrap();

    assert!(matches!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::TeeTypeMismatch { receipt: None, .. })
    ));
}

#[test]
fn simulated_quote_in_tee_attested_receipt_is_rejected() {
    let (mut receipt, key) = build_receipt(simulated_quote_builder());
    receipt.assurance_level = AssuranceLevel::TeeAttested;
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_pinned(&receipt, &key, &allowlist, &SimulatedQuoteVerifier).unwrap();

    assert_eq!(
        result.attestation_status,
        AttestationStatus::QuoteInvalid(QuoteVerifyError::SimulatedClaimsTeeAttested)
    );
    assert!(!result.is_valid_simulated());
}

// ---------------------------------------------------------------------------
// Parse-only SNP
// ---------------------------------------------------------------------------

#[test]
fn snp_parse_only_returns_parsed_not_verified() {
    let snp_measurement = [0xBB_u8; 48];
    let (receipt, key) = build_receipt(snp_quote_builder(snp_measurement));
    let allowlist = allowlist_with(&hex::encode(snp_measurement));
    let verifier = SevSnpQuoteVerifier::parsing_only();

    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteParsed);
    assert!(!result.is_valid(), "is_valid requires ChainVerified");
    assert!(result.is_valid_parsed(), "is_valid_parsed accepts Parsed");
}

// ---------------------------------------------------------------------------
// Allowlist interaction
// ---------------------------------------------------------------------------

#[test]
fn valid_quote_unknown_measurement() {
    let (receipt, key) = build_receipt(simulated_quote_builder());
    let allowlist = StaticAllowlist::from_entries(vec![]); // empty
    let verifier = SimulatedQuoteVerifier;

    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteSimulated);
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
    let (receipt, key) = build_receipt(snp_quote_builder(snp_measurement));
    let allowlist = allowlist_with(&hex::encode(snp_measurement));
    let verifier = SevSnpQuoteVerifier::parsing_only();

    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteParsed);
    assert!(!result.is_valid(), "is_valid requires ChainVerified");
    assert!(result.is_valid_parsed(), "is_valid_parsed accepts Parsed");
    assert!(
        result.is_valid_sans_quote(),
        "is_valid_sans_quote ignores attestation"
    );
}

#[test]
fn simulated_quote_is_never_platform_verified() {
    let (receipt, key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let verifier = SimulatedQuoteVerifier;

    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

    assert_eq!(result.attestation_status, AttestationStatus::QuoteSimulated);
    assert!(!result.is_valid());
    assert!(!result.is_valid_parsed());
    assert!(result.is_valid_simulated());
    assert!(result.is_valid_sans_quote());
}

// ---------------------------------------------------------------------------
// Pinned receipt key
// ---------------------------------------------------------------------------

#[test]
fn unpinned_verification_is_not_valid() {
    let (receipt, _key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_tee_receipt(&receipt, &allowlist, &SimulatedQuoteVerifier).unwrap();

    assert_eq!(
        result.signature_status,
        tee_verifier::SignatureStatus::ValidUnpinned
    );
    assert!(!result.is_valid_sans_quote());
    assert!(!result.is_valid_simulated());
}

#[test]
fn receipt_naming_a_different_key_than_the_pin_is_rejected() {
    // A self-consistent receipt: signed by, attested to and naming key B.
    let (receipt, _key_b) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());
    let pinned = SigningKey::from_bytes(&[0x11; 32]);

    let result = verify_pinned(&receipt, &pinned, &allowlist, &SimulatedQuoteVerifier).unwrap();

    assert_eq!(
        result.signature_status,
        tee_verifier::SignatureStatus::KeyMismatch
    );
    assert!(!result.is_valid_simulated());
    assert!(!result.is_valid_sans_quote());
}

#[test]
fn removing_the_embedded_key_after_signing_invalidates_the_receipt() {
    let (mut receipt, key) = build_receipt(simulated_quote_builder());
    // Removing the embedded key changes the signed content, so the signature
    // no longer verifies under the pinned key.
    receipt
        .tee_attestation
        .as_mut()
        .unwrap()
        .receipt_signing_pubkey_hex = None;
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_pinned(&receipt, &key, &allowlist, &SimulatedQuoteVerifier).unwrap();
    assert_eq!(
        result.signature_status,
        tee_verifier::SignatureStatus::Invalid
    );
}

#[test]
fn is_valid_sans_quote_ignores_attestation() {
    let (receipt, key) = build_receipt(simulated_quote_builder());
    let allowlist = allowlist_with(&simulated_measurement());

    // Use wrong verifier to get QuoteInvalid
    let verifier = SevSnpQuoteVerifier::parsing_only();
    let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

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
        let (receipt, key) = build_receipt_with_vcek(
            snp_quote_builder(snp_measurement),
            Some("!!!not-valid-base64!!!".to_string()),
        );
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

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
        let garbage_b64 = base64::Engine::encode(&b64, [0xFF, 0xFE, 0xFD, 0xFC, 0xFB]);
        let (receipt, key) =
            build_receipt_with_vcek(snp_quote_builder(snp_measurement), Some(garbage_b64));
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

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

        let (receipt, key) =
            build_receipt_with_vcek(snp_quote_builder(snp_measurement), Some(vcek_b64));
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

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
        let (receipt, key) = build_receipt_with_vcek(snp_quote_builder(snp_measurement), None);
        let allowlist = allowlist_with(&hex::encode(snp_measurement));
        let verifier = SevSnpQuoteVerifier::parsing_only();

        let result = verify_pinned(&receipt, &key, &allowlist, &verifier).unwrap();

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

// ---------------------------------------------------------------------------
// Receipt v3
// ---------------------------------------------------------------------------

fn test_relay_config() -> RelayConfig {
    RelayConfig {
        provider_id: "anthropic".to_string(),
        provider_base_url: "https://api.anthropic.com".to_string(),
        model_id_requested: "test-model".to_string(),
        policy_lockfile_hash: String::new(),
        model_profile_allowlist_hash: String::new(),
        relay_git_rev: "0123abc".to_string(),
        echo_mode: false,
        simulated: true,
        env: String::new(),
    }
}

/// Options with the v3 test relay key (seed 7) pinned and `relay_config`.
fn options_with(relay_config: RelayConfig) -> VerifyOptions {
    VerifyOptions {
        relay_config: Some(relay_config),
        pinned_receipt_key: Some(SigningKey::from_bytes(&[7u8; 32]).verifying_key()),
        ..VerifyOptions::default()
    }
}

/// Build a signed v3 TEE receipt with a v3 transcript bound to
/// [`test_relay_config`]. `attested_key` is the key named in
/// `tee_attestation` (and bound into the transcript); `signing_key` signs.
fn build_v3_receipt(
    quote_builder: QuoteBuilder,
    signing_key: &SigningKey,
    attested_key: &ed25519_dalek::VerifyingKey,
) -> receipt_core::ReceiptV3 {
    build_v3_receipt_with_transcript(
        quote_builder,
        signing_key,
        attested_key,
        Some(&test_relay_config()),
    )
}

/// Build a signed v3 TEE receipt. With `relay_config` the transcript is v3;
/// without, it is the legacy v2 transcript.
fn build_v3_receipt_with_transcript(
    quote_builder: QuoteBuilder,
    signing_key: &SigningKey,
    attested_key: &ed25519_dalek::VerifyingKey,
    relay_config: Option<&RelayConfig>,
) -> receipt_core::ReceiptV3 {
    use receipt_core::{
        BudgetScope, BudgetUsageV3, CANONICALIZATION_V3, ClaimsV3, CommitmentsV3, ContractHashAlg,
        InputCommitmentScheme, InputCommitmentV3, OperatorV3, SCHEMA_VERSION_V3, UnsignedReceiptV3,
    };

    let pubkey_hex = hex::encode(attested_key.as_bytes());
    let contract_hash = hex::encode(Sha256::digest(b"test-contract"));
    let output = serde_json::json!({"score": 4});
    let output_hash = hex::encode(Sha256::digest(
        receipt_core::canonicalize_v3(&output).unwrap().as_bytes(),
    ));
    let prompt_template_hash = hex::encode(Sha256::digest(b"test-prompt-template"));
    let initiator_sub_hash = hex::encode(Sha256::digest(b"test-initiator-ciphertext"));
    let responder_sub_hash = hex::encode(Sha256::digest(b"test-responder-ciphertext"));
    let model_identity_asserted = "anthropic/test-model";

    let transcript_hash = match relay_config {
        Some(relay_config) => compute_transcript_hash_v3(&TranscriptInputsV3 {
            contract_hash: &contract_hash,
            prompt_template_hash: &prompt_template_hash,
            initiator_submission_hash: &initiator_sub_hash,
            responder_submission_hash: &responder_sub_hash,
            output_hash: &output_hash,
            receipt_signing_pubkey_hex: &pubkey_hex,
            model_identity_asserted,
            relay_config_hash: &relay_config.hash_hex(),
        }),
        None => compute_transcript_hash_v2(&TranscriptInputsV2 {
            contract_hash: &contract_hash,
            prompt_template_hash: &prompt_template_hash,
            initiator_submission_hash: &initiator_sub_hash,
            responder_submission_hash: &responder_sub_hash,
            output_hash: &output_hash,
            receipt_signing_pubkey_hex: &pubkey_hex,
            model_identity_asserted,
        }),
    };
    let (quote_bytes, measurement, tee_type) = quote_builder(&transcript_hash);
    let b64 = base64::engine::general_purpose::STANDARD;

    let commitment = |nonce: u8, ctx: serde_json::Value| {
        receipt_core::compute_input_commitment_v3(&[nonce; 32], &ctx).unwrap()
    };

    let unsigned = UnsignedReceiptV3 {
        receipt_schema_version: SCHEMA_VERSION_V3.to_string(),
        receipt_canonicalization: CANONICALIZATION_V3.to_string(),
        receipt_id: "test-receipt-v3".to_string(),
        session_id: "test-session-v3".to_string(),
        issued_at: receipt_core::format_issued_at_v3(chrono::Utc::now()),
        assurance_level: AssuranceLevel::SelfAsserted,
        operator: OperatorV3 {
            operator_id: "test-relay".to_string(),
            operator_key_fingerprint: hex::encode(Sha256::digest(
                signing_key.verifying_key().as_bytes(),
            )),
            operator_key_discovery: None,
        },
        commitments: CommitmentsV3 {
            contract_hash,
            contract_hash_alg: ContractHashAlg::Sha256JcsV2,
            schema_hash: hex::encode(Sha256::digest(b"test-schema")),
            output_hash,
            input_commitments: vec![
                InputCommitmentV3 {
                    participant_id: "alice".to_string(),
                    input_commitment: commitment(1, serde_json::json!({"a": 1})),
                    scheme: InputCommitmentScheme::Sha256N32JcsV3,
                },
                InputCommitmentV3 {
                    participant_id: "bob".to_string(),
                    input_commitment: commitment(2, serde_json::json!({"b": 2})),
                    scheme: InputCommitmentScheme::Sha256N32JcsV3,
                },
            ],
            prompt_assembly_version: "1.0.0".to_string(),
            output: Some(output),
            prompt_template_hash: Some(prompt_template_hash),
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            initiator_submission_hash: Some(initiator_sub_hash),
            responder_submission_hash: Some(responder_sub_hash),
        },
        claims: ClaimsV3 {
            model_identity_asserted: Some(model_identity_asserted.to_string()),
            model_identity_attested: None,
            model_profile_hash_asserted: None,
            runtime_hash_asserted: None,
            runtime_hash_attested: None,
            budget_enforcement_mode: None,
            provider_latency_ms: Some(100),
            token_usage: None,
            relay_software_version: Some("0.1.0".to_string()),
            status: Some(SessionStatus::Success),
            signal_class: Some("SESSION_COMPLETED".to_string()),
            execution_lane: Some(ExecutionLaneV2::Tee),
            channel_capacity_bits_upper_bound: None,
            channel_capacity_measurement_version: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            budget_usage: Some(BudgetUsageV3 {
                scope: BudgetScope::Session,
                bits_used_before: 0,
                bits_used_after: 3,
                budget_limit: 128,
            }),
        },
        provider_attestation: None,
        tee_attestation: Some(TeeAttestation {
            tee_type: Some(tee_type),
            measurement: Some(measurement),
            quote: Some(b64.encode(&quote_bytes)),
            attestation_hash: Some(hex::encode(Sha256::digest(&quote_bytes))),
            receipt_signing_pubkey_hex: Some(pubkey_hex),
            transcript_hash_hex: Some(hex::encode(transcript_hash)),
            user_data_hex: Some(hex::encode(transcript_hash)),
            snp_vcek_cert: None,
        }),
    };

    receipt_core::sign_and_assemble_receipt_v3(unsigned, signing_key).unwrap()
}

#[test]
fn v3_receipt_full_verification() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = build_v3_receipt(
        simulated_quote_builder(),
        &signing_key,
        &signing_key.verifying_key(),
    );
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_tee_receipt_with_options(
        &receipt,
        &allowlist,
        &SimulatedQuoteVerifier,
        &options_with(test_relay_config()),
    )
    .unwrap();

    assert_eq!(
        result.signature_status,
        tee_verifier::SignatureStatus::Valid
    );
    assert!(result.transcript_hash_valid);
    assert_eq!(result.transcript_schema, Some(TranscriptSchema::V3));
    assert_eq!(result.relay_config, Some(test_relay_config()));
    assert!(result.submission_hashes_present);
    assert!(result.is_valid_simulated());
}

#[test]
fn v3_transcript_does_not_verify_without_the_relay_config() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = build_v3_receipt(
        simulated_quote_builder(),
        &signing_key,
        &signing_key.verifying_key(),
    );
    let allowlist = allowlist_with(&simulated_measurement());

    let result = verify_tee_receipt_with_options(
        &receipt,
        &allowlist,
        &SimulatedQuoteVerifier,
        &VerifyOptions {
            pinned_receipt_key: Some(signing_key.verifying_key()),
            ..VerifyOptions::default()
        },
    )
    .unwrap();

    assert!(!result.transcript_hash_valid);
    assert_eq!(result.transcript_schema, None);
    assert_eq!(result.relay_config, None);
    assert!(!result.is_valid());
}

#[test]
fn v3_transcript_does_not_verify_against_a_different_relay_config() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = build_v3_receipt(
        simulated_quote_builder(),
        &signing_key,
        &signing_key.verifying_key(),
    );
    let allowlist = allowlist_with(&simulated_measurement());

    for other in [
        RelayConfig {
            provider_base_url: "https://api.example.test".to_string(),
            ..test_relay_config()
        },
        RelayConfig {
            model_id_requested: "other-model".to_string(),
            ..test_relay_config()
        },
        RelayConfig {
            simulated: false,
            ..test_relay_config()
        },
    ] {
        let result = verify_tee_receipt_with_options(
            &receipt,
            &allowlist,
            &SimulatedQuoteVerifier,
            &options_with(other.clone()),
        )
        .unwrap();
        assert!(!result.transcript_hash_valid, "{other:?}");
        assert_eq!(result.relay_config, None);
        assert!(!result.is_valid());
    }
}

#[test]
fn v3_receipt_with_legacy_v2_transcript_verifies_labelled_unbound() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = build_v3_receipt_with_transcript(
        simulated_quote_builder(),
        &signing_key,
        &signing_key.verifying_key(),
        None,
    );
    let allowlist = allowlist_with(&simulated_measurement());

    // Without a relay config, a v2 transcript verifies as v2, labelled unbound.
    let result = verify_tee_receipt_with_options(
        &receipt,
        &allowlist,
        &SimulatedQuoteVerifier,
        &VerifyOptions {
            pinned_receipt_key: Some(signing_key.verifying_key()),
            ..VerifyOptions::default()
        },
    )
    .unwrap();
    assert!(result.transcript_hash_valid);
    let schema = result.transcript_schema.expect("schema");
    assert_eq!(schema, TranscriptSchema::V2);
    assert!(!schema.binds_relay_config());
    assert_eq!(schema.label(), "code/config unbound");
    assert_eq!(result.relay_config, None);
}

#[test]
fn legacy_transcript_does_not_verify_when_a_relay_config_is_supplied() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = build_v3_receipt_with_transcript(
        simulated_quote_builder(),
        &signing_key,
        &signing_key.verifying_key(),
        None,
    );
    let allowlist = allowlist_with(&simulated_measurement());

    let explicit = VerifyOptions {
        require_transcript_v3: true,
        pinned_receipt_key: Some(signing_key.verifying_key()),
        ..VerifyOptions::default()
    };
    for options in [options_with(test_relay_config()), explicit] {
        let result = verify_tee_receipt_with_options(
            &receipt,
            &allowlist,
            &SimulatedQuoteVerifier,
            &options,
        )
        .unwrap();
        // The v2 match is reported, but it is not a valid transcript here.
        assert_eq!(result.transcript_schema, Some(TranscriptSchema::V2));
        assert!(!result.transcript_hash_valid);
        assert!(!result.is_valid_sans_quote());
        assert_eq!(result.relay_config, None);
    }
}

#[test]
fn relay_config_claim_depends_on_what_the_measurement_covers() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = build_v3_receipt(
        simulated_quote_builder(),
        &signing_key,
        &signing_key.verifying_key(),
    );
    let result = verify_tee_receipt_with_options(
        &receipt,
        &allowlist_with(&simulated_measurement()),
        &SimulatedQuoteVerifier,
        &options_with(test_relay_config()),
    )
    .unwrap();
    assert!(result.transcript_hash_valid);
    assert_eq!(
        result.relay_config_claim(),
        Some("relay config asserted (not code-attested)")
    );
}

#[test]
fn v3_label_does_not_claim_code_attestation() {
    assert_eq!(
        TranscriptSchema::V3.label(),
        "relay config asserted (not code-attested)"
    );
}

#[test]
fn v3_receipt_signed_by_a_key_other_than_the_attested_key_is_invalid() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let attested_key = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
    let receipt = build_v3_receipt(simulated_quote_builder(), &signing_key, &attested_key);
    let allowlist = allowlist_with(&simulated_measurement());

    // Unpinned: the signature does not verify under the key the receipt names.
    let result = verify_tee_receipt(&receipt, &allowlist, &SimulatedQuoteVerifier).unwrap();
    assert_eq!(
        result.signature_status,
        tee_verifier::SignatureStatus::Invalid
    );
    assert!(!result.is_valid_simulated());

    // Pinned to the signing key: the receipt names a different key.
    let result = verify_tee_receipt_with_options(
        &receipt,
        &allowlist,
        &SimulatedQuoteVerifier,
        &options_with(test_relay_config()),
    )
    .unwrap();
    assert_eq!(
        result.signature_status,
        tee_verifier::SignatureStatus::KeyMismatch
    );
    assert!(!result.is_valid_simulated());
}
