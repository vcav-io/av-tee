use receipt_core::TeeType;
use serde::{Deserialize, Serialize};

/// Stable identity of a TEE relay instance.
///
/// | Event           | measurement | receipt_signing_pubkey_hex |
/// |-----------------|-------------|---------------------------|
/// | Key rotation    | same        | changes                   |
/// | Reimage         | changes     | changes                   |
/// | Enclave restart | same        | changes (new sealed key)  |
///
/// Clients pin on `measurement`. Accept any pubkey attested under that measurement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayIdentity {
    pub tee_type: TeeType,
    pub measurement: String,
    pub receipt_signing_pubkey_hex: String,
}
