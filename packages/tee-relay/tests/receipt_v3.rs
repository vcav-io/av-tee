//! Receipt v3 behaviour of the TEE relay: client-salted input commitments,
//! contract hash v2 and v3 receipts on success and failure.

mod support;

use sha2::{Digest, Sha256};
use tee_core::types::ParticipantRole;

use support::*;

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("output body is JSON")
}

fn receipt_json(output: &serde_json::Value) -> String {
    let receipt = output
        .get("receipt")
        .filter(|r| !r.is_null())
        .expect("output carries a `receipt`");
    serde_json::to_string(receipt).unwrap()
}

/// Verify with the VFC verifier against the pinned relay key and return the
/// typed v3 receipt.
fn verify_v3(receipt_json: &str) -> receipt_core::ReceiptV3 {
    let pinned = signing_key().verifying_key();
    match verifier_core::verify_receipt_json(receipt_json, &pinned).expect("receipt verifies") {
        verifier_core::VerifiedReceipt::V3(r) => *r,
        other => panic!("expected a v3 receipt, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// commitment_nonce validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submission_without_commitment_nonce_is_rejected() {
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"PROCEED"}"#).await).await;
    let client = reqwest::Client::new();
    let session = create_session(&client, &base, contract_json()).await;

    let plaintext = serde_json::json!({"role": "alice", "context": {"x": 1}});
    let (status, body) = submit_plaintext(
        &client,
        &base,
        &session,
        ParticipantRole::Initiator,
        &serde_json::to_vec(&plaintext).unwrap(),
    )
    .await;
    assert_eq!(status, 422);
    assert_eq!(parse(&body), serde_json::json!({"error": "input_rejected"}));
}

#[tokio::test]
async fn submission_with_malformed_commitment_nonce_is_rejected_without_echo() {
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"PROCEED"}"#).await).await;
    let client = reqwest::Client::new();

    let malformed: Vec<serde_json::Value> = vec![
        // uppercase hex
        serde_json::json!("C0FFEE".repeat(10) + "C0FF"),
        // 31 bytes
        serde_json::json!("ab".repeat(31)),
        // 33 bytes
        serde_json::json!("cd".repeat(33)),
        // non-hex characters
        serde_json::json!("zq".repeat(32)),
        // not a string
        serde_json::json!(12345),
        serde_json::Value::Null,
    ];

    for nonce in malformed {
        let session = create_session(&client, &base, contract_json()).await;
        let plaintext = serde_json::json!({
            "role": "alice",
            "context": {"x": 1},
            "commitment_nonce": nonce,
        });
        let (status, body) = submit_plaintext(
            &client,
            &base,
            &session,
            ParticipantRole::Initiator,
            &serde_json::to_vec(&plaintext).unwrap(),
        )
        .await;
        assert_eq!(status, 422, "nonce {nonce} must be rejected");
        assert_eq!(parse(&body), serde_json::json!({"error": "input_rejected"}));
        if let Some(s) = nonce.as_str() {
            assert!(!body.contains(s), "rejection must not echo the nonce");
        }
    }
}

#[tokio::test]
async fn context_with_out_of_range_integer_is_rejected() {
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"PROCEED"}"#).await).await;
    let client = reqwest::Client::new();
    let session = create_session(&client, &base, contract_json()).await;

    let (status, body) = submit_input(
        &client,
        &base,
        &session,
        ParticipantRole::Initiator,
        "alice",
        &serde_json::json!({"n": 9007199254740992u64}),
        ALICE_NONCE,
    )
    .await;
    assert_eq!(status, 422);
    assert_eq!(parse(&body), serde_json::json!({"error": "input_rejected"}));
}

// ---------------------------------------------------------------------------
// Success receipt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn success_receipt_is_v3_and_verifies_against_pinned_key() {
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"PROCEED"}"#).await).await;
    let client = reqwest::Client::new();
    let contract = contract_json();
    let session = create_session(&client, &base, contract.clone()).await;
    let alice_ctx = serde_json::json!({"preference": "morning", "n": 1});
    let bob_ctx = serde_json::json!({"preference": "evening", "n": 2});

    let body = run_session(&client, &base, &session, &alice_ctx, &bob_ctx).await;
    let output = parse(&body);
    assert_eq!(output["state"], "COMPLETED");
    assert!(
        output.get("receipt_v2").is_none(),
        "only a v3 `receipt` is returned"
    );
    assert!(output.get("receipt_signature").is_none());

    let raw = receipt_json(&output);
    let receipt = verify_v3(&raw);
    assert_eq!(receipt.receipt_schema_version, "3.0.0");
    assert_eq!(receipt.receipt_canonicalization, "JCS_RFC8785");
    assert_eq!(receipt.session_id, session["session_id"].as_str().unwrap());
    assert_eq!(
        receipt.claims.status,
        Some(receipt_core::SessionStatus::Success)
    );
    assert_eq!(
        receipt.claims.execution_lane,
        Some(receipt_core::ExecutionLaneV2::Tee)
    );
    assert!(receipt_core::receipt_v3::is_valid_issued_at_v3(
        &receipt.issued_at
    ));
    assert!(receipt.commitments.initiator_submission_hash.is_some());
    assert!(receipt.commitments.responder_submission_hash.is_some());

    // Participant checks (own input, received output, contract).
    let alice_nonce = nonce_bytes(ALICE_NONCE);
    let bob_nonce = nonce_bytes(BOB_NONCE);
    let received_output = output["output"].clone();
    for (id, nonce, ctx) in [
        ("alice", &alice_nonce, &alice_ctx),
        ("bob", &bob_nonce, &bob_ctx),
    ] {
        verifier_core::run_v3_checks(
            &receipt,
            &verifier_core::V3Checks {
                own_input: Some((id, nonce, ctx)),
                received_output: Some(&received_output),
                contract: Some(&contract),
            },
        )
        .expect("participant checks pass");
    }

    // A different nonce or context does not open the commitment.
    assert!(verifier_core::check_own_input_v3(&receipt, "alice", &bob_nonce, &alice_ctx).is_err());
    assert!(verifier_core::check_own_input_v3(&receipt, "alice", &alice_nonce, &bob_ctx).is_err());
}

#[tokio::test]
async fn input_commitments_are_salted_with_commitment_nonce() {
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"HALT"}"#).await).await;
    let client = reqwest::Client::new();
    let session = create_session(&client, &base, contract_json()).await;
    let alice_ctx = serde_json::json!({"budget": 3});
    let bob_ctx = serde_json::json!({"budget": 4});

    let body = run_session(&client, &base, &session, &alice_ctx, &bob_ctx).await;
    let output = parse(&body);
    let commitments = &output["receipt"]["commitments"]["input_commitments"];
    let entries = commitments.as_array().expect("input_commitments array");
    assert_eq!(entries.len(), 2);

    for (entry, (id, nonce, ctx)) in entries.iter().zip([
        ("alice", ALICE_NONCE, &alice_ctx),
        ("bob", BOB_NONCE, &bob_ctx),
    ]) {
        assert_eq!(entry["participant_id"], id);
        assert_eq!(entry["scheme"], "SHA256_N32_JCS_V3");
        let committed = entry["input_commitment"].as_str().unwrap();
        let expected = receipt_core::compute_input_commitment_v3(&nonce_bytes(nonce), ctx).unwrap();
        assert_eq!(committed, expected);
        assert_ne!(committed, unsalted_input_hash(ctx));
        assert_ne!(
            committed,
            receipt_core::compute_input_commitment_v3(&[0u8; 32], ctx).unwrap()
        );
        assert!(entry.get("input_hash").is_none());
    }

    // The nonce never appears in the session output.
    assert!(!body.contains(ALICE_NONCE));
    assert!(!body.contains(BOB_NONCE));
}

#[tokio::test]
async fn receipt_names_the_signing_key_in_tee_attestation() {
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"PROCEED"}"#).await).await;
    let client = reqwest::Client::new();
    let info: serde_json::Value = client
        .get(format!("{base}/tee/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = create_session(&client, &base, contract_json()).await;
    let body = run_session(
        &client,
        &base,
        &session,
        &serde_json::json!({}),
        &serde_json::json!({}),
    )
    .await;
    let output = parse(&body);
    let receipt = verify_v3(&receipt_json(&output));

    let key_hex = hex::encode(signing_key().verifying_key().as_bytes());
    let tee_att = receipt.tee_attestation.as_ref().expect("tee_attestation");
    assert_eq!(
        tee_att.receipt_signing_pubkey_hex.as_deref(),
        Some(key_hex.as_str())
    );
    assert_eq!(info["receipt_signing_pubkey_hex"], key_hex);
    assert_eq!(
        receipt.operator.operator_key_fingerprint,
        hex::encode(Sha256::digest(signing_key().verifying_key().as_bytes()))
    );

    // A verifier pinned to a different key rejects the receipt.
    let other = ed25519_dalek::SigningKey::from_bytes(&[0x01; 32]).verifying_key();
    assert!(verifier_core::verify_receipt_json(&receipt_json(&output), &other).is_err());
}

// ---------------------------------------------------------------------------
// Failure receipt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failure_receipt_is_v3_and_verifies_against_pinned_key() {
    let base = start_relay_server(&start_failing_mock_provider().await).await;
    let client = reqwest::Client::new();
    let contract = contract_json();
    let session = create_session(&client, &base, contract.clone()).await;
    let alice_ctx = serde_json::json!({"a": true});
    let bob_ctx = serde_json::json!({"b": false});

    let body = run_session(&client, &base, &session, &alice_ctx, &bob_ctx).await;
    let output = parse(&body);
    assert_eq!(output["state"], "ABORTED");
    assert!(output.get("receipt_v2").is_none());

    let receipt = verify_v3(&receipt_json(&output));
    assert_eq!(receipt.receipt_schema_version, "3.0.0");
    assert_eq!(
        receipt.claims.status,
        Some(receipt_core::SessionStatus::Error)
    );
    assert_eq!(
        receipt.commitments.output_hash,
        hex::encode(Sha256::digest(b""))
    );
    assert!(receipt.commitments.output.is_none());
    verifier_core::check_contract_v3(&receipt, &contract).expect("contract check passes");
    verifier_core::check_own_input_v3(&receipt, "alice", &nonce_bytes(ALICE_NONCE), &alice_ctx)
        .expect("alice's commitment opens");
    verifier_core::check_own_input_v3(&receipt, "bob", &nonce_bytes(BOB_NONCE), &bob_ctx)
        .expect("bob's commitment opens");
    assert!(!body.contains(ALICE_NONCE));
    assert!(!body.contains(BOB_NONCE));
}

// ---------------------------------------------------------------------------
// Contract hash v2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_contract_hash_is_contract_hash_v2() {
    let base = start_relay_server(&start_mock_provider("{}").await).await;
    let client = reqwest::Client::new();
    let contract = contract_json();
    let session = create_session(&client, &base, contract.clone()).await;

    let v2 = receipt_core::compute_contract_hash_v2(&contract).unwrap();
    assert_eq!(session["contract_hash"], v2);

    let typed: vault_family_types::Contract = serde_json::from_value(contract).unwrap();
    let legacy = hex::encode(Sha256::digest(
        receipt_core::canonicalize_serializable(&typed)
            .unwrap()
            .as_bytes(),
    ));
    assert_ne!(session["contract_hash"], legacy);
}

#[tokio::test]
async fn contract_with_unknown_member_is_rejected() {
    let base = start_relay_server(&start_mock_provider("{}").await).await;
    let client = reqwest::Client::new();

    let mut contract = contract_json();
    contract["unexpected_member"] = serde_json::json!("value");
    let (status, _) = create_session_raw(&client, &base, contract).await;
    assert!(
        (400..500).contains(&status),
        "unknown member must be rejected, got {status}"
    );

    let mut contract = contract_json();
    contract["model_constraints"] = serde_json::json!({"allowed_models": [], "extra": 1});
    let (status, _) = create_session_raw(&client, &base, contract).await;
    assert!((400..500).contains(&status), "got {status}");
}

#[tokio::test]
async fn contract_carrying_a_legacy_contract_hash_is_rejected() {
    let base = start_relay_server(&start_mock_provider("{}").await).await;
    let client = reqwest::Client::new();

    let typed: vault_family_types::Contract = serde_json::from_value(contract_json()).unwrap();
    let legacy = hex::encode(Sha256::digest(
        receipt_core::canonicalize_serializable(&typed)
            .unwrap()
            .as_bytes(),
    ));
    let mut contract = contract_json();
    contract["contract_hash"] = serde_json::json!(legacy);
    let (status, _) = create_session_raw(&client, &base, contract).await;
    assert!(
        (400..500).contains(&status),
        "contract_hash member must be rejected, got {status}"
    );
}
