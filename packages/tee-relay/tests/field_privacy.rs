//! No value a participant receives (receipt fields, TEE attestation and
//! transcript fields, response bodies) is an unsalted hash of input-derived
//! values or of output that was not released. Runs over receipts produced by
//! the TEE relay for a completed, a rejected and a failed session.

mod support;

use base64::Engine;
use sha2::{Digest, Sha256};
use tee_transcript::{TranscriptInputsV2, compute_transcript_hash_v2};

use support::*;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn alice_ctx() -> serde_json::Value {
    serde_json::json!({"salary_band": "B", "notes": "prefers mornings"})
}

fn bob_ctx() -> serde_json::Value {
    serde_json::json!({"salary_band": "C", "notes": "prefers evenings"})
}

/// The model output used for the rejected session: valid JSON that fails the
/// contract's output schema, so it is withheld.
const REJECTED_OUTPUT: &str = r#"{"decision":"MAYBE","detail":"salary_band C"}"#;

/// Hashes a participant could recompute from guesses of the other party's
/// input, or of output that was withheld.
fn input_derived_hashes() -> Vec<(String, String)> {
    let (a, b) = (alice_ctx(), bob_ctx());
    let ja = receipt_core::canonicalize_v3(&a).unwrap();
    let jb = receipt_core::canonicalize_v3(&b).unwrap();
    let la = receipt_core::canonicalize_serializable(&a).unwrap();
    let lb = receipt_core::canonicalize_serializable(&b).unwrap();

    // The prompt exactly as the relay assembles it.
    let contract: vault_family_types::Contract = serde_json::from_value(contract_json()).unwrap();
    let system = format!(
        "You are a structured data mediator for a {} session. \
         Respond with ONLY the JSON object matching the output schema. \
         No explanation, no markdown, no code fences.",
        contract.purpose_code,
    );
    let user_message = format!(
        "Contract purpose: {purpose}\n\
         Output schema: {schema_id}\n\n\
         --- Input from {role_a} ---\n\
         {context_a}\n\n\
         --- Input from {role_b} ---\n\
         {context_b}\n\n\
         Respond with ONLY the JSON object matching the output schema.",
        purpose = contract.purpose_code,
        schema_id = contract.output_schema_id,
        role_a = contract.participants[0],
        context_a = serde_json::to_string_pretty(&a).unwrap(),
        role_b = contract.participants[1],
        context_b = serde_json::to_string_pretty(&b).unwrap(),
    );
    let prompt = serde_json::json!({"system": system, "user_message": user_message});
    let rejected: serde_json::Value = serde_json::from_str(REJECTED_OUTPUT).unwrap();

    let plaintext = |label: &str, ctx: &serde_json::Value, nonce: &str| {
        serde_json::to_vec(&serde_json::json!({
            "role": label,
            "context": ctx,
            "commitment_nonce": nonce,
        }))
        .unwrap()
    };

    let preimages: Vec<(&str, Vec<u8>)> = vec![
        ("context_a", ja.clone().into_bytes()),
        ("context_b", jb.clone().into_bytes()),
        ("context_a_legacy", la.clone().into_bytes()),
        ("context_b_legacy", lb.clone().into_bytes()),
        ("context_a_pretty", serde_json::to_vec_pretty(&a).unwrap()),
        ("context_b_pretty", serde_json::to_vec_pretty(&b).unwrap()),
        ("contexts_concat", format!("{ja}{jb}").into_bytes()),
        ("contexts_concat_legacy", format!("{la}{lb}").into_bytes()),
        (
            "contexts_array",
            receipt_core::canonicalize_v3(&serde_json::json!([a, b]))
                .unwrap()
                .into_bytes(),
        ),
        ("plaintext_a", plaintext("alice", &a, ALICE_NONCE)),
        ("plaintext_b", plaintext("bob", &b, BOB_NONCE)),
        (
            "assembled_prompt",
            receipt_core::canonicalize_v3(&prompt).unwrap().into_bytes(),
        ),
        (
            "assembled_prompt_legacy",
            receipt_core::canonicalize(&prompt).into_bytes(),
        ),
        ("user_message", user_message.clone().into_bytes()),
        (
            "system_and_user",
            format!("{system}{user_message}").into_bytes(),
        ),
        (
            "rejected_output",
            receipt_core::canonicalize_v3(&rejected)
                .unwrap()
                .into_bytes(),
        ),
        (
            "rejected_output_legacy",
            receipt_core::canonicalize(&rejected).into_bytes(),
        ),
        ("rejected_output_raw", REJECTED_OUTPUT.as_bytes().to_vec()),
    ];
    preimages
        .into_iter()
        .map(|(name, bytes)| (name.to_string(), sha256_hex(&bytes)))
        .collect()
}

/// Every string (and member name) in `value`, lowercased. Base64 strings
/// (the attestation quote) are also decoded and added as hex.
fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            out.push(s.to_lowercase());
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
                out.push(hex::encode(bytes));
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        serde_json::Value::Object(map) => map.iter().for_each(|(k, v)| {
            out.push(k.to_lowercase());
            strings(v, out);
        }),
        _ => {}
    }
}

fn assert_no_input_derived_hash(label: &str, value: &serde_json::Value) {
    let mut values = Vec::new();
    strings(value, &mut values);
    for (name, hash) in input_derived_hashes() {
        assert!(
            !values.iter().any(|v| v.contains(hash.as_str())),
            "{label} contains the SHA-256 of {name}"
        );
    }
}

/// Recompute the transcript hash from the receipt and check it is the
/// attested one: every transcript input is then a receipt field the scan
/// covers.
fn assert_transcript_inputs_are_receipt_fields(receipt: &serde_json::Value) {
    let c = &receipt["commitments"];
    let att = &receipt["tee_attestation"];
    let s = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
    let recomputed = hex::encode(compute_transcript_hash_v2(&TranscriptInputsV2 {
        contract_hash: &s(&c["contract_hash"]),
        prompt_template_hash: &s(&c["prompt_template_hash"]),
        initiator_submission_hash: &s(&c["initiator_submission_hash"]),
        responder_submission_hash: &s(&c["responder_submission_hash"]),
        output_hash: &s(&c["output_hash"]),
        receipt_signing_pubkey_hex: &s(&att["receipt_signing_pubkey_hex"]),
        model_identity_asserted: &s(&receipt["claims"]["model_identity_asserted"]),
    }));
    assert_eq!(att["user_data_hex"], recomputed);
    assert_eq!(att["transcript_hash_hex"], recomputed);
}

/// Run a session; return the create-session response, the output body and
/// the status body.
async fn session_output(provider_url: &str) -> (serde_json::Value, String, serde_json::Value) {
    let base = start_relay_server(provider_url).await;
    let client = reqwest::Client::new();
    let session = create_session(&client, &base, contract_json()).await;
    let body = run_session(&client, &base, &session, &alice_ctx(), &bob_ctx()).await;
    let status: serde_json::Value = client
        .get(format!(
            "{base}/sessions/{}/status",
            session["session_id"].as_str().unwrap()
        ))
        .bearer_auth(session["read_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (session, body, status)
}

#[tokio::test]
async fn no_received_value_is_an_unsalted_hash_of_inputs_or_withheld_output() {
    let completed = start_mock_provider(r#"{"decision":"PROCEED"}"#).await;
    let rejected = start_mock_provider(REJECTED_OUTPUT).await;
    let failed = start_failing_mock_provider().await;

    for (label, url, expected_state) in [
        ("completed", completed, "COMPLETED"),
        ("rejected", rejected, "ABORTED"),
        ("failed", failed, "ABORTED"),
    ] {
        let (session, body, status) = session_output(&url).await;
        let output: serde_json::Value = serde_json::from_str(&body).unwrap();
        let receipt = &output["receipt"];
        assert!(receipt.is_object(), "{label} session has a receipt");

        assert_transcript_inputs_are_receipt_fields(receipt);
        assert_no_input_derived_hash(&format!("{label} session output"), &output);
        assert_no_input_derived_hash(&format!("{label} create-session response"), &session);
        assert_no_input_derived_hash(&format!("{label} status response"), &status);
        assert_eq!(output["state"], expected_state, "{label}");

        if expected_state == "ABORTED" {
            // Nothing was released: the output hash bound into the receipt,
            // the transcript and REPORT_DATA is SHA-256 of zero bytes.
            assert_eq!(receipt["commitments"]["output_hash"], sha256_hex(b""));
            assert!(receipt["commitments"].get("output").is_none());
            assert!(output.get("output").is_none());
        }
    }
}

#[tokio::test]
async fn scan_detects_a_planted_input_derived_hash() {
    // Guards the scan above against passing vacuously.
    let (_, body, _) = session_output(&start_mock_provider(r#"{"decision":"HALT"}"#).await).await;
    let output: serde_json::Value = serde_json::from_str(&body).unwrap();
    for (name, hash) in input_derived_hashes() {
        let mut planted = output.clone();
        planted["receipt"]["commitments"]["extra"] = serde_json::json!(hash);
        let mut values = Vec::new();
        strings(&planted, &mut values);
        assert!(
            values.iter().any(|v| v.contains(hash.as_str())),
            "planted {name} not detected"
        );

        // A quote binding the hash is detected too.
        let mut planted = output.clone();
        let quote = base64::engine::general_purpose::STANDARD
            .encode([b"quote:".as_slice(), &hex::decode(&hash).unwrap()].concat());
        planted["receipt"]["tee_attestation"]["quote"] = serde_json::json!(quote);
        let mut values = Vec::new();
        strings(&planted, &mut values);
        assert!(values.iter().any(|v| v.contains(hash.as_str())));
    }
}
