#![forbid(unsafe_code)]

pub mod allowlist;
pub mod identity;
pub mod quote;
pub mod result;
pub mod snp_chain;
pub mod snp_sig;
pub mod verify;

pub use allowlist::{
    AllowlistError, MeasurementEntry, MeasurementPlatform, StaticAllowlist, TransparencySource,
};
pub use identity::RelayIdentity;
pub use quote::{
    QuoteFields, QuoteVerifier, QuoteVerifyError, SevSnpQuoteVerifier, SimulatedQuoteVerifier,
    VerificationLevel, VerifiedQuote,
};
pub use result::{
    AttestationHashStatus, AttestationStatus, SignatureStatus, TeeVerificationResult,
    TranscriptBinding, TranscriptSchema,
};
pub use snp_chain::{ProductFamily, TcbPolicy, VerificationConfig};
pub use tee_transcript::RelayConfig;
pub use verify::{
    TeeReceipt, VerifyError, VerifyOptions, verify_tee_receipt, verify_tee_receipt_pinned,
    verify_tee_receipt_with_config, verify_tee_receipt_with_options,
};
