use chrono::Utc;
use receipt_core::{
    AssuranceLevel, CANONICALIZATION_V3, ClaimsV3, CommitmentsV3, ContractHashAlg, ExecutionLaneV2,
    InputCommitmentScheme, InputCommitmentV3, OperatorV3, ReceiptV3, SCHEMA_VERSION_V3,
    SessionStatus, TeeAttestation, UnsignedReceiptV3,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use tee_core::attestation::CvmRuntime;
use tee_transcript::{RelayConfig, TranscriptInputsV3, compute_transcript_hash_v3};

use crate::error::RelayError;
use crate::provider::ProviderRequest;
use crate::provider::anthropic::AnthropicProvider;

pub const INLINE_PROMPT_TEMPLATE_HASH: &str =
    "592ce8974206a5744aefacfdc5530dbe6972f43e20794714a00d3425fb7f54d1";

/// Source revision recorded at build time (`SELKEY_TEE_GIT_REV`), bound into
/// the relay configuration hash.
pub const RELAY_GIT_REV: &str = match option_env!("SELKEY_TEE_GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

/// Provider id bound into the relay configuration.
pub const PROVIDER_ID: &str = "anthropic";

/// Shared application state for the TEE relay.
pub struct AppState {
    pub cvm: std::sync::Arc<dyn CvmRuntime>,
    pub signing_key: ed25519_dalek::SigningKey,
    pub anthropic_api_key: Option<String>,
    pub anthropic_model_id: String,
    pub anthropic_base_url: Option<String>,
    pub max_completion_tokens: u32,
    pub operator_id: String,
    /// Deployment environment label (`SELKEY_ENV`), bound into the relay
    /// configuration. Empty when unset.
    pub env: String,
}

impl AppState {
    /// The configuration this relay runs with, as bound into transcript v3.
    pub fn relay_config(&self) -> RelayConfig {
        RelayConfig {
            provider_id: PROVIDER_ID.to_string(),
            provider_base_url: crate::provider::anthropic::effective_base_url(
                self.anthropic_base_url.as_deref(),
            ),
            model_id_requested: self.anthropic_model_id.clone(),
            // tee-relay has no policy lockfile and does not accept model
            // profiles (contracts naming one are rejected).
            policy_lockfile_hash: String::new(),
            model_profile_allowlist_hash: String::new(),
            relay_git_rev: RELAY_GIT_REV.to_string(),
            echo_mode: false,
            simulated: !self.cvm.is_real_tee(),
            env: self.env.clone(),
        }
    }
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

/// Client-generated input commitment nonce (32 bytes).
///
/// Carried inside the encrypted submission plaintext as `commitment_nonce`:
/// exactly 64 lowercase hex characters. The relay uses it only to compute the
/// participant's input commitment; it is never written to receipts, logs or
/// responses, and its bytes are zeroed when the input is dropped.
pub struct CommitmentNonce([u8; receipt_core::commitment_v3::COMMITMENT_NONCE_LEN]);

impl CommitmentNonce {
    /// Parse the wire form (64 lowercase hex characters).
    pub fn parse(hex_nonce: &str) -> Result<Self, receipt_core::CommitmentError> {
        receipt_core::parse_commitment_nonce(hex_nonce).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; receipt_core::commitment_v3::COMMITMENT_NONCE_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for CommitmentNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommitmentNonce([REDACTED])")
    }
}

impl Drop for CommitmentNonce {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl<'de> serde::Deserialize<'de> for CommitmentNonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_nonce = Zeroizing::new(String::deserialize(deserializer)?);
        // The error message never includes the value.
        CommitmentNonce::parse(&hex_nonce).map_err(|_| {
            serde::de::Error::custom(
                "commitment_nonce must be 64 lowercase hex characters (32 bytes)",
            )
        })
    }
}

/// Input from a single participant (decrypted inside the CVM).
#[derive(serde::Deserialize)]
pub struct DecryptedInput {
    pub role: String,
    pub context: serde_json::Value,
    /// Required. Salts this participant's input commitment in the receipt.
    pub commitment_nonce: CommitmentNonce,
}

// Manual Debug to prevent plaintext leaking via panic/log.
impl std::fmt::Debug for DecryptedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedInput")
            .field("role", &self.role)
            .field("context", &"[REDACTED]")
            .field("commitment_nonce", &"[REDACTED]")
            .finish()
    }
}

/// Parse and validate a decrypted submission plaintext.
///
/// The plaintext must carry `role`, `context` and a well-formed
/// `commitment_nonce`, and the context must be committable under the receipt
/// v3 canonicalisation profile (numbers within +/-(2^53-1)). Errors never
/// include plaintext.
pub fn parse_decrypted_input(plaintext: &[u8]) -> Result<DecryptedInput, RelayError> {
    let input: DecryptedInput = serde_json::from_slice(plaintext)
        .map_err(|_| RelayError::ContractValidation("invalid submission".to_string()))?;
    receipt_core::canonicalize_v3(&input.context)
        .map_err(|_| RelayError::ContractValidation("invalid input context".to_string()))?;
    Ok(input)
}

/// Compute the v3 input commitments, in `contract.participants` order.
pub fn compute_input_commitments(
    contract: &vault_family_types::Contract,
    input_a: &DecryptedInput,
    input_b: &DecryptedInput,
) -> Result<Vec<InputCommitmentV3>, RelayError> {
    if contract.participants.len() != 2 {
        return Err(RelayError::ContractValidation(
            "contract must have exactly 2 participants".to_string(),
        ));
    }
    [
        (&contract.participants[0], input_a),
        (&contract.participants[1], input_b),
    ]
    .iter()
    .map(|(participant_id, input)| {
        let input_commitment = receipt_core::compute_input_commitment_v3(
            input.commitment_nonce.as_bytes(),
            &input.context,
        )
        .map_err(|_| RelayError::ContractValidation("input commitment failed".to_string()))?;
        Ok(InputCommitmentV3 {
            participant_id: (*participant_id).clone(),
            input_commitment,
            scheme: InputCommitmentScheme::Sha256N32JcsV3,
        })
    })
    .collect()
}

/// A contract accepted from a request, with its contract hash v2.
#[derive(Debug, Clone)]
pub struct AcceptedContract {
    /// Typed contract used by the relay.
    pub contract: vault_family_types::Contract,
    /// Contract hash v2 (`SHA256_JCS_V2`) of the contract as received.
    pub contract_hash: String,
}

/// Validate a contract as received and compute its contract hash v2.
///
/// The hash is computed from the received JSON (normalised per contract hash
/// v2), never from a re-serialised typed contract. Unknown members, including
/// a `contract_hash` member, are rejected.
pub fn accept_contract(contract_json: &serde_json::Value) -> Result<AcceptedContract, RelayError> {
    let normalized = receipt_core::normalize_contract_v2(contract_json)
        .map_err(|e| RelayError::ContractValidation(format!("contract: {e}")))?;
    let contract_hash = receipt_core::jcs::hash_v3(&normalized)
        .map_err(|e| RelayError::ContractValidation(format!("contract: {e}")))?;
    let contract: vault_family_types::Contract = serde_json::from_value(normalized)
        .map_err(|e| RelayError::ContractValidation(format!("contract: {e}")))?;
    if contract.participants.len() != 2 {
        return Err(RelayError::ContractValidation(
            "contract must have exactly 2 participants".to_string(),
        ));
    }
    if contract.participants.iter().any(|p| p.is_empty())
        || contract.participants[0] == contract.participants[1]
    {
        return Err(RelayError::ContractValidation(
            "contract participants must be distinct and non-empty".to_string(),
        ));
    }
    Ok(AcceptedContract {
        contract,
        contract_hash,
    })
}

/// Result of relay_core execution.
pub struct RelayResult {
    pub output: serde_json::Value,
    pub receipt: ReceiptV3,
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

/// `hex(SHA-256(JCS(value)))` with the receipt v3 canonicalisation profile
/// (RFC 8785, numbers limited to +/-(2^53-1)).
pub fn hash_json_v3(value: &serde_json::Value) -> Result<String, RelayError> {
    receipt_core::jcs::hash_v3(value)
        .map_err(|e| RelayError::Internal(format!("canonicalization: {e}")))
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

    let inline_schema_hash = hash_json_v3(&contract.output_schema)?;
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
/// This runs entirely inside the CVM. Inputs were decrypted and validated at
/// submission; `input_commitments` are their v3 commitments, computed by the
/// caller so that a failure receipt can carry them too. The caller drops the
/// inputs (and zeroes their commitment nonces) when this returns
/// (serde_json::Value is not zeroized — see CLAUDE.md known limitations).
#[allow(clippy::too_many_arguments)]
pub async fn relay_core(
    session_id: &str,
    contract: &vault_family_types::Contract,
    input_a: &DecryptedInput,
    input_b: &DecryptedInput,
    input_commitments: Vec<InputCommitmentV3>,
    initiator_ciphertext_hash: &str,
    responder_ciphertext_hash: &str,
    contract_hash_hex: &str,
    state: &AppState,
) -> Result<RelayResult, RelayError> {
    // 1. Validate contract
    let schema_hash = validate_contract_support(contract, state)?;

    // 2. Check plaintext role labels
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

    // 3. Assemble prompt
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

    // 4. Compute prompt template hash (inline prompt program for now)
    let prompt_template_hash = { INLINE_PROMPT_TEMPLATE_HASH.to_string() };

    // 5. Resolve effective max_tokens
    let effective_max_tokens = match contract.max_completion_tokens {
        Some(contract_max) => std::cmp::min(contract_max, state.max_completion_tokens),
        None => state.max_completion_tokens,
    };

    // 6. Call provider
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

    // 7. Parse and validate output
    let output: serde_json::Value = serde_json::from_str(&provider_response.text)
        .map_err(|e| RelayError::OutputValidation(format!("output is not valid JSON: {e}")))?;

    validate_output_schema(&output, &contract.output_schema)?;

    // 8. Build TEE receipt
    let output_hash = hash_json_v3(&output)?;
    let receipt = build_tee_receipt_v3(
        session_id,
        contract_hash_hex,
        &schema_hash,
        &output,
        &output_hash,
        input_commitments,
        &prompt_template_hash,
        initiator_ciphertext_hash,
        responder_ciphertext_hash,
        &provider_response.model_id,
        state,
        inference_start,
        inference_end,
    )
    .await?;

    Ok(RelayResult { output, receipt })
}

/// Receipt operator block: `operator_key_fingerprint = SHA-256(signing pubkey)`.
fn operator_v3(state: &AppState) -> OperatorV3 {
    OperatorV3 {
        operator_id: state.operator_id.clone(),
        operator_key_fingerprint: receipt_core::receipt_v3::operator_key_fingerprint(
            &state.signing_key.verifying_key(),
        ),
        operator_key_discovery: None,
    }
}

/// Build and sign a TEE-mode v3 receipt with attestation binding.
#[allow(clippy::too_many_arguments)]
async fn build_tee_receipt_v3(
    session_id: &str,
    contract_hash: &str,
    schema_hash: &str,
    output: &serde_json::Value,
    output_hash: &str,
    input_commitments: Vec<InputCommitmentV3>,
    prompt_template_hash: &str,
    initiator_submission_hash: &str,
    responder_submission_hash: &str,
    model_id: &str,
    state: &AppState,
    inference_start: chrono::DateTime<chrono::Utc>,
    inference_end: chrono::DateTime<chrono::Utc>,
) -> Result<ReceiptV3, RelayError> {
    // Derive receipt signing pubkey from AppState (not from CVM identity)
    let receipt_signing_pubkey_hex =
        receipt_core::public_key_to_hex(&state.signing_key.verifying_key());

    // Compute model identity once — used for both transcript binding and claims
    let model_identity_asserted = format!("anthropic/{model_id}");

    // Build transcript hash for attestation binding (v3: model identity and
    // relay configuration hash, length-prefixed encoding)
    let relay_config_hash = state.relay_config().hash_hex();
    let transcript_inputs = TranscriptInputsV3 {
        contract_hash,
        prompt_template_hash,
        initiator_submission_hash,
        responder_submission_hash,
        output_hash,
        receipt_signing_pubkey_hex: &receipt_signing_pubkey_hex,
        model_identity_asserted: &model_identity_asserted,
        relay_config_hash: &relay_config_hash,
    };
    let transcript_hash = compute_transcript_hash_v3(&transcript_inputs);
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

    let unsigned = UnsignedReceiptV3 {
        receipt_schema_version: SCHEMA_VERSION_V3.to_string(),
        receipt_canonicalization: CANONICALIZATION_V3.to_string(),
        receipt_id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        issued_at: receipt_core::format_issued_at_v3(Utc::now()),
        assurance_level,
        operator: operator_v3(state),
        commitments: CommitmentsV3 {
            contract_hash: contract_hash.to_string(),
            contract_hash_alg: ContractHashAlg::Sha256JcsV2,
            schema_hash: schema_hash.to_string(),
            output_hash: output_hash.to_string(),
            input_commitments,
            prompt_assembly_version: "1.0.0".to_string(),
            output: Some(output.clone()),
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
        claims: ClaimsV3 {
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
            // The TEE lane does not measure channel capacity, so it makes no
            // budget usage claim.
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

    receipt_core::sign_and_assemble_receipt_v3(unsigned, &state.signing_key)
        .map_err(|e| RelayError::ReceiptSigning(format!("v3 signing failed: {e}")))
}

/// Build a v3 failure receipt for an aborted TEE session.
#[allow(clippy::too_many_arguments)]
pub async fn build_failure_receipt_v3(
    session_id: &str,
    contract_hash: &str,
    schema_hash: &str,
    input_commitments: Vec<InputCommitmentV3>,
    initiator_submission_hash: Option<&str>,
    responder_submission_hash: Option<&str>,
    signal_class: &str,
    state: &AppState,
) -> Result<ReceiptV3, RelayError> {
    // Derive receipt signing pubkey from AppState (not from CVM identity)
    let receipt_signing_pubkey_hex =
        receipt_core::public_key_to_hex(&state.signing_key.verifying_key());

    // Transcript binding must reflect the fields actually emitted in the
    // receipt. Optional commitment fields omitted on the wire bind as "".
    let missing_field = "";
    let empty_hash = hex::encode(Sha256::digest(b""));

    let relay_config_hash = state.relay_config().hash_hex();
    let transcript_inputs = TranscriptInputsV3 {
        contract_hash,
        prompt_template_hash: missing_field,
        initiator_submission_hash: initiator_submission_hash.unwrap_or(missing_field),
        responder_submission_hash: responder_submission_hash.unwrap_or(missing_field),
        output_hash: &empty_hash,
        receipt_signing_pubkey_hex: &receipt_signing_pubkey_hex,
        model_identity_asserted: missing_field,
        relay_config_hash: &relay_config_hash,
    };
    let transcript_hash = compute_transcript_hash_v3(&transcript_inputs);
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

    let assurance_level = if state.cvm.is_real_tee() {
        AssuranceLevel::TeeAttested
    } else {
        AssuranceLevel::SelfAsserted
    };

    let unsigned = UnsignedReceiptV3 {
        receipt_schema_version: SCHEMA_VERSION_V3.to_string(),
        receipt_canonicalization: CANONICALIZATION_V3.to_string(),
        receipt_id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        issued_at: receipt_core::format_issued_at_v3(Utc::now()),
        assurance_level,
        operator: operator_v3(state),
        commitments: CommitmentsV3 {
            contract_hash: contract_hash.to_string(),
            contract_hash_alg: ContractHashAlg::Sha256JcsV2,
            schema_hash: schema_hash.to_string(),
            output_hash: empty_hash,
            input_commitments,
            prompt_assembly_version: "1.0.0".to_string(),
            output: None,
            prompt_template_hash: None,
            effective_config_hash: None,
            preflight_bundle: None,
            output_retrieval_uri: None,
            output_media_type: None,
            preflight_bundle_uri: None,
            initiator_submission_hash: initiator_submission_hash.map(str::to_string),
            responder_submission_hash: responder_submission_hash.map(str::to_string),
        },
        claims: ClaimsV3 {
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
            // The TEE lane does not measure channel capacity, so it makes no
            // budget usage claim.
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

    receipt_core::sign_and_assemble_receipt_v3(unsigned, &state.signing_key)
        .map_err(|e| RelayError::ReceiptSigning(format!("v3 failure receipt signing failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::INLINE_PROMPT_TEMPLATE_HASH;
    use sha2::{Digest, Sha256};

    #[test]
    fn decrypted_input_debug_redacts_commitment_nonce() {
        let nonce = "3c".repeat(32);
        let plaintext = serde_json::json!({
            "role": "alice",
            "context": {"secret": "value"},
            "commitment_nonce": nonce,
        });
        let input = super::parse_decrypted_input(&serde_json::to_vec(&plaintext).unwrap()).unwrap();
        let debug = format!("{input:?}");
        assert!(!debug.contains(&nonce));
        assert!(!debug.contains("value"));
    }

    #[test]
    fn parse_decrypted_input_errors_do_not_echo_the_nonce() {
        let nonce = "3C".repeat(32);
        let plaintext = serde_json::json!({
            "role": "alice",
            "context": {},
            "commitment_nonce": nonce,
        });
        let err = super::parse_decrypted_input(&serde_json::to_vec(&plaintext).unwrap())
            .expect_err("uppercase nonce is rejected");
        assert!(!err.to_string().contains(&nonce));
    }

    #[test]
    fn inline_prompt_template_hash_constant_matches_v1_program_id() {
        let mut hasher = Sha256::new();
        hasher.update(b"av-tee-inline-prompt-v1");
        assert_eq!(INLINE_PROMPT_TEMPLATE_HASH, hex::encode(hasher.finalize()));
    }
}
