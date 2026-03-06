use base64::Engine;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use receipt_core::{
    AssuranceLevel, BudgetEnforcementMode, BudgetUsageV2, CANONICALIZATION_V2,
    CHANNEL_CAPACITY_MEASUREMENT_VERSION, Claims, Commitments, ExecutionLaneV2, HashAlgorithm,
    InputCommitment, Operator, ReceiptV2, SCHEMA_VERSION_V2, SessionStatus, TeeAttestation,
    TeeType, TokenUsage, UnsignedReceiptV2, sign_and_assemble_receipt_v2,
};
use tee_transcript::{TranscriptInputs, compute_transcript_hash};
use tee_verifier::{
    AttestationHashStatus, AttestationStatus, MeasurementEntry, QuoteVerifyError,
    SevSnpQuoteVerifier, SimulatedQuoteVerifier, StaticAllowlist, verify_tee_receipt,
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
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let pubkey_hex = receipt_core::public_key_to_hex(&signing_key.verifying_key());

    let contract_hash = hex::encode(Sha256::digest(b"test-contract"));
    let schema_hash = hex::encode(Sha256::digest(b"test-schema"));
    let output_hash = hex::encode(Sha256::digest(b"test-output"));
    let prompt_template_hash = hex::encode(Sha256::digest(b"test-prompt-template"));
    let initiator_sub_hash = hex::encode(Sha256::digest(b"test-initiator-input"));
    let responder_sub_hash = hex::encode(Sha256::digest(b"test-responder-input"));

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
    let operator_key_fingerprint = hex::encode(Sha256::digest(&hex::decode(&pubkey_hex).unwrap()));

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
