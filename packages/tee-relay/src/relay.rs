use chrono::Utc;
use receipt_core::{
    AssuranceLevel, CANONICALIZATION_V2, Claims, Commitments, ExecutionLaneV2, HashAlgorithm,
    InputCommitment, Operator, ReceiptV2, SCHEMA_VERSION_V2, SessionStatus, TeeAttestation,
    UnsignedReceiptV2,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use tee_core::attestation::CvmRuntime;
use tee_transcript::{TranscriptInputsV2, compute_transcript_hash_v2};

use crate::error::RelayError;
use crate::provider::ProviderRequest;
use crate::provider::anthropic::AnthropicProvider;

pub const INLINE_PROMPT_TEMPLATE_HASH: &str =
    "592ce8974206a5744aefacfdc5530dbe6972f43e20794714a00d3425fb7f54d1";

/// Shared application state for the TEE relay.
pub struct AppState {
    pub cvm: std::sync::Arc<dyn CvmRuntime>,
    pub signing_key: ed25519_dalek::SigningKey,
    pub anthropic_api_key: Option<String>,
    pub anthropic_model_id: String,
    pub anthropic_base_url: Option<String>,
    pub max_completion_tokens: u32,
    pub operator_id: String,
}

// Manual Debug to prevent signing key / API key leaking via panic/log.
impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("signing_key", &"[REDACTED]")
            .field("anthropic_api_key", &"[REDACTED]")
            .field("anthropic_model_id", &self.anthropic_model_id)
            .field("operator_id", &self.operator_id)
            .finish()
    }
}

/// Input from a single participant (decrypted inside the CVM).
#[derive(serde::Deserialize)]
pub struct DecryptedInput {
    pub role: String,
    pub context: serde_json::Value,
}

// Manual Debug to prevent plaintext leaking via panic/log.
impl std::fmt::Debug for DecryptedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedInput")
            .field("role", &self.role)
            .field("context", &"[REDACTED]")
            .finish()
    }
}

/// Result of relay_core execution.
pub struct RelayResult {
    pub output: serde_json::Value,
    pub receipt_v2: ReceiptV2,
}

/// Validate JSON output against a JSON Schema.
fn validate_output_schema(
    output: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), RelayError> {
    let validator = jsonschema::validator_for(schema)
        .map_err(|e| RelayError::OutputValidation(format!("schema compilation: {e}")))?;

    if !validator.is_valid(output) {
        let errors: Vec<String> = validator
            .iter_errors(output)
            .map(|e| e.to_string())
            .collect();
        return Err(RelayError::OutputValidation(errors.join("; ")));
    }
    Ok(())
}

/// Compute SHA-256 of canonical JSON for a serializable value.
fn canonical_sha256(value: &impl serde::Serialize) -> Result<String, RelayError> {
    let canonical = receipt_core::canonicalize_serializable(value)
        .map_err(|e| RelayError::Internal(format!("canonicalization: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

// Returns the canonical inline schema hash so validation and receipt binding
// share the same preflight result.
fn validate_contract_support(
    contract: &vault_family_types::Contract,
    state: &AppState,
) -> Result<String, RelayError> {
    if contract.participants.len() != 2 {
        return Err(RelayError::ContractValidation(
            "contract must have exactly 2 participants".to_string(),
        ));
    }

    if contract.prompt_template_hash != INLINE_PROMPT_TEMPLATE_HASH {
        return Err(RelayError::ContractValidation(
            "prompt_template_hash is not supported by tee-relay".to_string(),
        ));
    }

    if let Some(expected_key) = contract.relay_verifying_key_hex.as_deref() {
        let actual_key = receipt_core::public_key_to_hex(&state.signing_key.verifying_key());
        if expected_key != actual_key {
            return Err(RelayError::ContractValidation(
                "relay_verifying_key_hex does not match tee-relay signing key".to_string(),
            ));
        }
    }

    if contract.model_profile_id.is_some() || contract.model_profile_hash.is_some() {
        return Err(RelayError::ContractValidation(
            "model_profile_id/model_profile_hash are not supported by tee-relay".to_string(),
        ));
    }

    if contract.model_constraints.is_some() {
        return Err(RelayError::ContractValidation(
            "model_constraints are not supported by tee-relay".to_string(),
        ));
    }

    let inline_schema_hash = canonical_sha256(&contract.output_schema)?;
    if let Some(expected_schema_hash) = contract.output_schema_hash.as_deref()
        && expected_schema_hash != inline_schema_hash
    {
        return Err(RelayError::ContractValidation(
            "output_schema_hash does not match inline output_schema".to_string(),
        ));
    }

    Ok(inline_schema_hash)
}

/// Core TEE relay logic: validate → assemble → call provider → validate output → build receipt.
///
/// This runs entirely inside the CVM. Decrypted inputs arrive as `Zeroizing<Vec<u8>>`
/// and are parsed here. The parsed `DecryptedInput` values are dropped when this
/// function returns (serde_json::Value is not zeroized — see CLAUDE.md known limitations).
#[allow(clippy::too_many_arguments)]
pub async fn relay_core(
    session_id: &str,
    contract: &vault_family_types::Contract,
    initiator_plaintext: &Zeroizing<Vec<u8>>,
    responder_plaintext: &Zeroizing<Vec<u8>>,
    initiator_ciphertext_hash: &str,
    responder_ciphertext_hash: &str,
    contract_hash_hex: &str,
    state: &AppState,
) -> Result<RelayResult, RelayError> {
    // 1. Validate contract
    let schema_hash = validate_contract_support(contract, state)?;

    // 2. Parse decrypted inputs
    let input_a: DecryptedInput = serde_json::from_slice(initiator_plaintext.as_slice())
        .map_err(|_| RelayError::ContractValidation("invalid initiator input".to_string()))?;
    let input_b: DecryptedInput = serde_json::from_slice(responder_plaintext.as_slice())
        .map_err(|_| RelayError::ContractValidation("invalid responder input".to_string()))?;
    if input_a.role != contract.participants[0] {
        return Err(RelayError::ContractValidation(
            "initiator role label does not match contract participant".to_string(),
        ));
    }
    if input_b.role != contract.participants[1] {
        return Err(RelayError::ContractValidation(
            "responder role label does not match contract participant".to_string(),
        ));
    }

    // 3. Compute input commitments (hash of plaintext context, per participant)
    let input_commitments: Vec<InputCommitment> = {
        let inputs = [
            (&contract.participants[0], &input_a),
            (&contract.participants[1], &input_b),
        ];
        let mut commitments = Vec::with_capacity(2);
        for (participant_id, input) in &inputs {
            let hash = canonical_sha256(&input.context)?;
            commitments.push(InputCommitment {
                participant_id: (*participant_id).clone(),
                input_hash: hash,
                hash_alg: HashAlgorithm::Sha256,
                canonicalization: "CANONICAL_JSON_V1".to_string(),
            });
        }
        commitments
    };

    // 4. Assemble prompt
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
        context_a = serde_json::to_string_pretty(&input_a.context)
            .map_err(|e| RelayError::PromptAssembly(format!("serialize input_a: {e}")))?,
        role_b = contract.participants[1],
        context_b = serde_json::to_string_pretty(&input_b.context)
            .map_err(|e| RelayError::PromptAssembly(format!("serialize input_b: {e}")))?,
    );

    // 5. Compute assembled prompt hash
    let assembled_prompt_hash = {
        let prompt_json = serde_json::json!({
            "system": &system,
            "user_message": &user_message,
        });
        canonical_sha256(&prompt_json)?
    };

    // 6. Compute prompt template hash (inline prompt program for now)
    let prompt_template_hash = { INLINE_PROMPT_TEMPLATE_HASH.to_string() };

    // 7. Resolve effective max_tokens
    let effective_max_tokens = match contract.max_completion_tokens {
        Some(contract_max) => std::cmp::min(contract_max, state.max_completion_tokens),
        None => state.max_completion_tokens,
    };

    // 8. Call provider
    let inference_start = Utc::now();
    let api_key = state
        .anthropic_api_key
        .clone()
        .ok_or_else(|| RelayError::Provider("API key not configured".to_string()))?;

    let provider = AnthropicProvider::new(
        api_key,
        state.anthropic_model_id.clone(),
        state.anthropic_base_url.clone(),
    )?;

    let provider_response = provider
        .call(ProviderRequest {
            system,
            user_message,
            output_schema: Some(contract.output_schema.clone()),
            max_tokens: effective_max_tokens,
        })
        .await?;
    let inference_end = Utc::now();

    // 9. Parse and validate output
    let output: serde_json::Value = serde_json::from_str(&provider_response.text)
        .map_err(|e| RelayError::OutputValidation(format!("output is not valid JSON: {e}")))?;

    validate_output_schema(&output, &contract.output_schema)?;

    // 10. Build TEE receipt
    let output_hash = canonical_sha256(&output)?;
    let receipt_v2 = build_tee_receipt_v2(
        session_id,
        contract_hash_hex,
        &schema_hash,
        &output,
        &output_hash,
        input_commitments,
        assembled_prompt_hash,
        &prompt_template_hash,
        initiator_ciphertext_hash,
        responder_ciphertext_hash,
        &provider_response.model_id,
        state,
        inference_start,
        inference_end,
    )
    .await?;

    Ok(RelayResult { output, receipt_v2 })
}

#[cfg(test)]
mod tests {
    use super::INLINE_PROMPT_TEMPLATE_HASH;
    use sha2::{Digest, Sha256};

    #[test]
    fn inline_prompt_template_hash_constant_matches_v1_program_id() {
        let mut hasher = Sha256::new();
        hasher.update(b"av-tee-inline-prompt-v1");
        assert_eq!(INLINE_PROMPT_TEMPLATE_HASH, hex::encode(hasher.finalize()));
    }
}

/// Build and sign a TEE-mode v2 receipt with attestation binding.
#[allow(clippy::too_many_arguments)]
async fn build_tee_receipt_v2(
    session_id: &str,
    contract_hash: &str,
    schema_hash: &str,
    output: &serde_json::Value,
    output_hash: &str,
    input_commitments: Vec<InputCommitment>,
    assembled_prompt_hash: String,
    prompt_template_hash: &str,
    initiator_submission_hash: &str,
    responder_submission_hash: &str,
    model_id: &str,
    state: &AppState,
    inference_start: chrono::DateTime<chrono::Utc>,
    inference_end: chrono::DateTime<chrono::Utc>,
) -> Result<ReceiptV2, RelayError> {
    // Derive receipt signing pubkey from AppState (not from CVM identity)
    let receipt_signing_pubkey_hex =
        receipt_core::public_key_to_hex(&state.signing_key.verifying_key());

    // Compute model identity once — used for both transcript binding and claims
    let model_identity_asserted = format!("anthropic/{model_id}");

    // Build transcript hash for attestation binding (v2: includes model identity)
    let transcript_inputs = TranscriptInputsV2 {
        contract_hash,
        prompt_template_hash,
        initiator_submission_hash,
        responder_submission_hash,
        output_hash,
        receipt_signing_pubkey_hex: &receipt_signing_pubkey_hex,
        model_identity_asserted: &model_identity_asserted,
    };
    let transcript_hash = compute_transcript_hash_v2(&transcript_inputs);
    let transcript_hash_hex = hex::encode(transcript_hash);

    // Get CVM attestation bound to transcript hash
    let report = state
        .cvm
        .get_attestation(&transcript_hash)
        .await
        .map_err(|e| RelayError::Internal(format!("attestation failed: {e}")))?;

    let attestation_hash = {
        let mut h = Sha256::new();
        h.update(&report.quote);
        hex::encode(h.finalize())
    };

    // Compute operator key fingerprint
    let operator_key_fingerprint = {
        let key_bytes = hex::decode(&receipt_signing_pubkey_hex)
            .map_err(|e| RelayError::Internal(format!("own verifying key is invalid hex: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(&key_bytes);
        hex::encode(hasher.finalize())
    };

    let provider_latency_ms: Option<u64> = match (inference_end - inference_start)
        .num_milliseconds()
        .try_into()
    {
        Ok(ms) => Some(ms),
        Err(_) => {
            tracing::warn!("negative provider latency detected (clock skew?), omitting"); // SAFETY: no plaintext
            None
        }
    };

    // Assurance level: TeeAttested for real TEE, SelfAsserted for simulated
    let assurance_level = if state.cvm.is_real_tee() {
        AssuranceLevel::TeeAttested
    } else {
        AssuranceLevel::SelfAsserted
    };

    let unsigned = UnsignedReceiptV2 {
        receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
        receipt_canonicalization: CANONICALIZATION_V2.to_string(),
        receipt_id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        issued_at: Utc::now(),
        assurance_level,
        operator: Operator {
            operator_id: state.operator_id.clone(),
            operator_key_fingerprint,
            operator_key_discovery: None,
        },
        commitments: Commitments {
            contract_hash: contract_hash.to_string(),
            schema_hash: schema_hash.to_string(),
            output_hash: output_hash.to_string(),
            input_commitments,
            assembled_prompt_hash,
            prompt_assembly_version: "1.0.0".to_string(),
            output: Some(output.clone()),
            rejected_output_hash: None,
            prompt_template_hash: Some(prompt_template_hash.to_string()),
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            // TEE encrypted ingress commitments
            initiator_submission_hash: Some(initiator_submission_hash.to_string()),
            responder_submission_hash: Some(responder_submission_hash.to_string()),
        },
        claims: Claims {
            model_identity_asserted: Some(model_identity_asserted),
            model_identity_attested: None,
            model_profile_hash_asserted: None,
            runtime_hash_asserted: None,
            runtime_hash_attested: None,
            budget_enforcement_mode: None,
            provider_latency_ms,
            token_usage: None,
            relay_software_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            status: Some(SessionStatus::Success),
            signal_class: Some("SESSION_COMPLETED".to_string()),
            execution_lane: Some(ExecutionLaneV2::Tee),
            channel_capacity_bits_upper_bound: None,
            channel_capacity_measurement_version: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            budget_usage: None,
        },
        provider_attestation: None,
        tee_attestation: Some(TeeAttestation {
            tee_type: Some(report.tee_type),
            measurement: Some(report.measurement),
            quote: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &report.quote,
            )),
            attestation_hash: Some(attestation_hash),
            receipt_signing_pubkey_hex: Some(receipt_signing_pubkey_hex.clone()),
            transcript_hash_hex: Some(transcript_hash_hex.clone()),
            user_data_hex: Some(transcript_hash_hex),
            snp_vcek_cert: report
                .vcek_cert_der
                .map(|b| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b)),
        }),
    };

    receipt_core::sign_and_assemble_receipt_v2(unsigned, &state.signing_key)
        .map_err(|e| RelayError::ReceiptSigning(format!("v2 signing failed: {e}")))
}

/// Build a failure receipt for an aborted TEE session.
#[allow(clippy::too_many_arguments)]
pub async fn build_failure_receipt_v2(
    session_id: &str,
    contract_hash: &str,
    schema_hash: &str,
    initiator_submission_hash: Option<&str>,
    responder_submission_hash: Option<&str>,
    signal_class: &str,
    state: &AppState,
) -> Result<ReceiptV2, RelayError> {
    // Derive receipt signing pubkey from AppState (not from CVM identity)
    let receipt_signing_pubkey_hex =
        receipt_core::public_key_to_hex(&state.signing_key.verifying_key());

    // Transcript binding must reflect the fields actually emitted in the
    // receipt. Optional commitment fields omitted on the wire bind as "".
    let missing_field = "";
    let empty_hash = hex::encode(Sha256::digest(b""));

    let transcript_inputs = TranscriptInputsV2 {
        contract_hash,
        prompt_template_hash: missing_field,
        initiator_submission_hash: initiator_submission_hash.unwrap_or(missing_field),
        responder_submission_hash: responder_submission_hash.unwrap_or(missing_field),
        output_hash: &empty_hash,
        receipt_signing_pubkey_hex: &receipt_signing_pubkey_hex,
        model_identity_asserted: missing_field,
    };
    let transcript_hash = compute_transcript_hash_v2(&transcript_inputs);
    let transcript_hash_hex = hex::encode(transcript_hash);

    let report = state
        .cvm
        .get_attestation(&transcript_hash)
        .await
        .map_err(|e| RelayError::Internal(format!("attestation failed: {e}")))?;

    let attestation_hash = {
        let mut h = Sha256::new();
        h.update(&report.quote);
        hex::encode(h.finalize())
    };

    let verifying_key_hex = receipt_core::public_key_to_hex(&state.signing_key.verifying_key());
    let operator_key_fingerprint = {
        let key_bytes = hex::decode(&verifying_key_hex)
            .map_err(|e| RelayError::Internal(format!("own verifying key is invalid hex: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(&key_bytes);
        hex::encode(hasher.finalize())
    };

    let assurance_level = if state.cvm.is_real_tee() {
        AssuranceLevel::TeeAttested
    } else {
        AssuranceLevel::SelfAsserted
    };

    let unsigned = UnsignedReceiptV2 {
        receipt_schema_version: SCHEMA_VERSION_V2.to_string(),
        receipt_canonicalization: CANONICALIZATION_V2.to_string(),
        receipt_id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        issued_at: Utc::now(),
        assurance_level,
        operator: Operator {
            operator_id: state.operator_id.clone(),
            operator_key_fingerprint,
            operator_key_discovery: None,
        },
        commitments: Commitments {
            contract_hash: contract_hash.to_string(),
            schema_hash: schema_hash.to_string(),
            output_hash: empty_hash,
            input_commitments: vec![],
            assembled_prompt_hash: hex::encode(Sha256::digest(b"")),
            prompt_assembly_version: "1.0.0".to_string(),
            output: None,
            rejected_output_hash: None,
            prompt_template_hash: None,
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            initiator_submission_hash: initiator_submission_hash.map(str::to_string),
            responder_submission_hash: responder_submission_hash.map(str::to_string),
        },
        claims: Claims {
            model_identity_asserted: None,
            model_identity_attested: None,
            model_profile_hash_asserted: None,
            runtime_hash_asserted: None,
            runtime_hash_attested: None,
            budget_enforcement_mode: None,
            provider_latency_ms: None,
            token_usage: None,
            relay_software_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            status: Some(SessionStatus::Error),
            signal_class: Some(signal_class.to_string()),
            execution_lane: Some(ExecutionLaneV2::Tee),
            channel_capacity_bits_upper_bound: None,
            channel_capacity_measurement_version: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            budget_usage: None,
        },
        provider_attestation: None,
        tee_attestation: Some(TeeAttestation {
            tee_type: Some(report.tee_type),
            measurement: Some(report.measurement),
            quote: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &report.quote,
            )),
            attestation_hash: Some(attestation_hash),
            receipt_signing_pubkey_hex: Some(receipt_signing_pubkey_hex.clone()),
            transcript_hash_hex: Some(transcript_hash_hex.clone()),
            user_data_hex: Some(transcript_hash_hex),
            snp_vcek_cert: report
                .vcek_cert_der
                .map(|b| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b)),
        }),
    };

    receipt_core::sign_and_assemble_receipt_v2(unsigned, &state.signing_key)
        .map_err(|e| RelayError::ReceiptSigning(format!("v2 failure receipt signing failed: {e}")))
}
