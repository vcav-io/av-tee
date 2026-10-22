//! Output schema acceptance and the entropy budget for tee-relay.
//!
//! The output schema bounds what a session can release. tee-relay has no
//! schema registry, so it accepts only *strict* inline schemas (the same
//! rules as the Selkey relay applies to inline schemas), and computes their
//! entropy upper bound from the structure; schema-supplied bound annotations
//! are ignored. Any failure to compute a bound rejects the contract.
//!
//! The contract's entropy budget is enforced per session: with `Gate` (the
//! default) or `Strict` enforcement, a schema whose upper bound exceeds
//! `entropy_budget_bits` is rejected; `Advisory` only logs. There is no
//! cross-session ledger.

use serde_json::Value;
use vault_family_types::{Contract, EntropyEnforcementMode};

use crate::error::RelayError;

/// An output schema accepted for a contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedOutputSchema {
    /// SHA-256(JCS(schema)), the receipt `schema_hash`.
    pub hash: String,
    /// Entropy upper bound in bits.
    pub entropy_bits: u32,
}

/// Accept a contract's output schema and enforce its entropy budget.
pub fn accept_output_schema(contract: &Contract) -> Result<AcceptedOutputSchema, RelayError> {
    // A schema without `properties` refers to a registry entry by
    // `output_schema_hash`; tee-relay has no registry.
    let is_stub = contract
        .output_schema
        .as_object()
        .map(|obj| !obj.contains_key("properties"))
        .unwrap_or(true);
    if is_stub && contract.output_schema_hash.is_some() {
        return Err(RelayError::ContractValidation(
            "output_schema_hash refers to a schema registry; tee-relay accepts only inline strict schemas"
                .to_string(),
        ));
    }

    let hash = crate::relay::hash_json_v3(&contract.output_schema)?;
    if let Some(expected) = contract.output_schema_hash.as_deref()
        && expected != hash
    {
        return Err(RelayError::ContractValidation(
            "output_schema_hash does not match inline output_schema".to_string(),
        ));
    }

    let entropy_bits = strict_schema_upper_bound(&contract.output_schema).map_err(|reason| {
        RelayError::ContractValidation(format!("inline output schema rejected: {reason}"))
    })?;

    let mode = contract
        .entropy_enforcement
        .unwrap_or(EntropyEnforcementMode::Gate);
    if let Some(budget) = contract.entropy_budget_bits
        && entropy_bits > budget
    {
        match mode {
            EntropyEnforcementMode::Advisory => {
                tracing::warn!(
                    entropy_bits,
                    budget,
                    "schema entropy exceeds contract budget (advisory only)"
                ); // SAFETY: no plaintext
            }
            EntropyEnforcementMode::Gate | EntropyEnforcementMode::Strict => {
                return Err(RelayError::ContractValidation(format!(
                    "schema entropy upper bound ({entropy_bits} bits) exceeds contract budget ({budget} bits)"
                )));
            }
        }
    }

    Ok(AcceptedOutputSchema { hash, entropy_bits })
}

/// `ceil(log2(n))`: bits to choose one of `n` values (0 for `n <= 1`).
fn enum_entropy_bits(n: usize) -> u8 {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as u8
    }
}

/// Bits used to bound one Unicode scalar value in a length-bounded string.
const BITS_PER_CHAR: u64 = 21;

/// Maximum schema nesting depth accepted for inline schemas.
const MAX_DEPTH: usize = 32;

/// Keywords accepted in strict inline schemas. Keys starting with `x-` are
/// annotations and are ignored (including `x-vcav-entropy-bits-upper-bound`).
const ALLOWED_KEYWORDS: &[&str] = &[
    "$schema",
    "$comment",
    "title",
    "description",
    "default",
    "examples",
    "type",
    "enum",
    "const",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "minimum",
    "maximum",
];

/// Check that an inline schema is strict and compute its entropy upper bound.
///
/// A strict schema:
/// - is a JSON object at every node (no `true`/`false` schemas) and every node
///   declares a single `type`, an `enum`, or a `const`;
/// - uses only [`ALLOWED_KEYWORDS`] (no composition, references, pattern or
///   dynamic properties);
/// - sets `additionalProperties: false` on every object and lists every
///   property in `required`;
/// - bounds every string with `enum` or `maxLength`, every array with
///   `maxItems`, and every integer with `minimum` and `maximum`
///   (`number` must use `enum`).
///
/// The bound is computed from structure alone: enums contribute
/// `ceil(log2(n))` bits, strings `maxLength * 21` bits plus length, arrays
/// `maxItems * item_bits` plus length, integers `ceil(log2(range))`,
/// booleans 1 bit.
pub fn strict_schema_upper_bound(schema: &Value) -> Result<u32, String> {
    let bits = node_bound(schema, "$", 0)?;
    if bits > u64::from(u16::MAX) {
        return Err(format!(
            "entropy upper bound ({bits} bits) exceeds the supported maximum"
        ));
    }
    Ok(bits as u32)
}

fn length_bits(max_len: u64) -> u64 {
    u64::from(enum_entropy_bits(
        usize::try_from(max_len.saturating_add(1)).unwrap_or(usize::MAX),
    ))
}

fn overflow(path: &str) -> String {
    format!("{path}: entropy upper bound overflows")
}

fn node_bound(node: &Value, path: &str, depth: usize) -> Result<u64, String> {
    if depth > MAX_DEPTH {
        return Err(format!("{path}: schema nesting exceeds {MAX_DEPTH} levels"));
    }
    let obj = node
        .as_object()
        .ok_or_else(|| format!("{path}: schema must be a JSON object"))?;

    for key in obj.keys() {
        if !key.starts_with("x-") && !ALLOWED_KEYWORDS.contains(&key.as_str()) {
            return Err(format!("{path}: keyword '{key}' is not allowed"));
        }
    }

    if let Some(values) = obj.get("enum") {
        let values = values
            .as_array()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{path}: enum must be a non-empty array"))?;
        return Ok(u64::from(enum_entropy_bits(values.len())));
    }
    if obj.contains_key("const") {
        return Ok(0);
    }

    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}: must declare a single type, an enum or a const"))?;

    match ty {
        "object" => {
            if obj.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Err(format!(
                    "{path}: object must set additionalProperties: false"
                ));
            }
            let empty = serde_json::Map::new();
            let properties = match obj.get("properties") {
                None => &empty,
                Some(Value::Object(props)) => props,
                Some(_) => return Err(format!("{path}: properties must be an object")),
            };
            let required: Vec<&str> = match obj.get("required") {
                None => Vec::new(),
                Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
                Some(_) => return Err(format!("{path}: required must be an array")),
            };
            let mut total: u64 = 0;
            for (name, child) in properties {
                if !required.contains(&name.as_str()) {
                    return Err(format!(
                        "{path}: property '{name}' must be listed in required"
                    ));
                }
                let child_path = format!("{path}/properties/{name}");
                let bits = node_bound(child, &child_path, depth + 1)?;
                total = total
                    .checked_add(bits)
                    .ok_or_else(|| overflow(&child_path))?;
            }
            Ok(total)
        }
        "array" => {
            let max_items = obj
                .get("maxItems")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{path}: array must set maxItems"))?;
            let items = obj
                .get("items")
                .ok_or_else(|| format!("{path}: array must define items"))?;
            let item_bits = node_bound(items, &format!("{path}/items"), depth + 1)?;
            max_items
                .checked_mul(item_bits)
                .and_then(|b| b.checked_add(length_bits(max_items)))
                .ok_or_else(|| overflow(path))
        }
        "string" => {
            let max_len = obj
                .get("maxLength")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{path}: string must be bounded by enum or maxLength"))?;
            max_len
                .checked_mul(BITS_PER_CHAR)
                .and_then(|b| b.checked_add(length_bits(max_len)))
                .ok_or_else(|| overflow(path))
        }
        "integer" => {
            let min = obj.get("minimum").and_then(Value::as_i64);
            let max = obj.get("maximum").and_then(Value::as_i64);
            match (min, max) {
                (Some(min), Some(max)) if max >= min => {
                    let span = (i128::from(max) - i128::from(min)) as u64;
                    Ok(length_bits(span))
                }
                _ => Err(format!(
                    "{path}: integer must set integer minimum and maximum (minimum <= maximum)"
                )),
            }
        }
        "boolean" => Ok(1),
        "null" => Ok(0),
        other => Err(format!(
            "{path}: type '{other}' must be constrained by enum"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contract_with(schema: Value, hash: Option<String>) -> Contract {
        serde_json::from_value(json!({
            "purpose_code": "MEDIATION",
            "output_schema_id": "test",
            "output_schema": schema,
            "output_schema_hash": hash,
            "participants": ["alice", "bob"],
            "prompt_template_hash": "a".repeat(64)
        }))
        .unwrap()
    }

    fn enum_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "signal": { "type": "string", "enum": ["A", "B", "C", "D"] }
            },
            "required": ["signal"],
            "additionalProperties": false
        })
    }

    fn permissive_schemas() -> Vec<Value> {
        vec![
            json!({}),
            json!(true),
            json!({"type": "object"}),
            json!({"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "properties": {"a": {"type": "array", "items": {"type": "string", "enum": ["X"]}}}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "properties": {"a": {"type": "string", "enum": ["X"]}}, "required": ["a"]}),
            json!({"type": "object", "properties": {"a": {"type": "string", "enum": ["X"]}}, "required": ["a"], "additionalProperties": true}),
            json!({"type": "object", "properties": {"a": {}}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "properties": {"a": true}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "properties": {"a": {"type": "string", "pattern": "^.*$"}}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "properties": {"a": {"type": "number"}}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "properties": {"a": {"anyOf": [{"type": "string"}]}}, "required": ["a"], "additionalProperties": false}),
            json!({"type": "object", "patternProperties": {".*": {"type": "string"}}, "additionalProperties": false}),
        ]
    }

    #[test]
    fn permissive_schemas_are_rejected() {
        for schema in permissive_schemas() {
            let contract = contract_with(schema.clone(), None);
            let err = accept_output_schema(&contract)
                .expect_err(&format!("schema {schema} should be rejected"));
            assert!(matches!(err, RelayError::ContractValidation(_)));
        }
    }

    #[test]
    fn strict_schema_is_accepted_with_its_bound() {
        let accepted = accept_output_schema(&contract_with(enum_schema(), None)).unwrap();
        assert_eq!(accepted.entropy_bits, 2);
        assert_eq!(
            accepted.hash,
            crate::relay::hash_json_v3(&enum_schema()).unwrap()
        );
    }

    #[test]
    fn registry_reference_is_rejected() {
        let contract = contract_with(json!({}), Some("ab".repeat(32)));
        let err = accept_output_schema(&contract).unwrap_err();
        assert!(err.to_string().contains("schema registry"));
    }

    #[test]
    fn mismatched_schema_hash_is_rejected() {
        let contract = contract_with(enum_schema(), Some("ab".repeat(32)));
        let err = accept_output_schema(&contract).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn self_declared_bound_is_ignored() {
        let schema = json!({
            "type": "object",
            "properties": {
                "note": { "type": "string", "maxLength": 10, "x-vcav-entropy-bits-upper-bound": 0 }
            },
            "required": ["note"],
            "additionalProperties": false,
            "x-vcav-entropy-bits-upper-bound": 0
        });
        let accepted = accept_output_schema(&contract_with(schema, None)).unwrap();
        // 10 * 21 bits + 4 length bits
        assert_eq!(accepted.entropy_bits, 214);
    }

    fn with_budget(budget: u32, mode: Option<EntropyEnforcementMode>) -> Contract {
        let mut contract = contract_with(enum_schema(), None);
        contract.entropy_budget_bits = Some(budget);
        contract.entropy_enforcement = mode;
        contract
    }

    #[test]
    fn entropy_budget_is_enforced_by_default() {
        let err = accept_output_schema(&with_budget(1, None)).unwrap_err();
        assert!(err.to_string().contains("exceeds contract budget"));
        for mode in [EntropyEnforcementMode::Gate, EntropyEnforcementMode::Strict] {
            assert!(accept_output_schema(&with_budget(1, Some(mode))).is_err());
        }
        accept_output_schema(&with_budget(2, None)).unwrap();
    }

    #[test]
    fn advisory_budget_does_not_reject() {
        accept_output_schema(&with_budget(1, Some(EntropyEnforcementMode::Advisory))).unwrap();
    }

    #[test]
    fn enum_entropy_bits_is_ceil_log2() {
        for (n, bits) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (256, 8),
            (257, 9),
        ] {
            assert_eq!(enum_entropy_bits(n), bits, "n = {n}");
        }
    }

    #[test]
    fn strict_bounds_for_scalar_types() {
        let schema = json!({
            "type": "object",
            "properties": {
                "flag": { "type": "boolean" },
                "count": { "type": "integer", "minimum": 0, "maximum": 7 },
                "nothing": { "type": "null" },
                "fixed": { "const": "X" }
            },
            "required": ["flag", "count", "nothing", "fixed"],
            "additionalProperties": false
        });
        assert_eq!(strict_schema_upper_bound(&schema).unwrap(), 1 + 3);
    }

    #[test]
    fn strict_bound_overflow_rejected() {
        let schema = json!({
            "type": "array",
            "maxItems": u64::MAX,
            "items": { "type": "string", "maxLength": u64::MAX }
        });
        assert!(strict_schema_upper_bound(&schema).is_err());
    }
}
