#![forbid(unsafe_code)]

pub mod allowlist;
pub mod identity;
pub mod quote;
pub mod result;
pub mod snp_chain;
pub mod snp_sig;
pub mod verify;

pub use allowlist::{MeasurementEntry, StaticAllowlist, TransparencySource};
pub use identity::RelayIdentity;
pub use quote::{
    QuoteFields, QuoteVerifier, QuoteVerifyError, SevSnpQuoteVerifier, SimulatedQuoteVerifier,
    VerificationLevel, VerifiedQuote,
};
pub use result::{
    AttestationHashStatus, AttestationStatus, SignatureStatus, TeeVerificationResult,
    TranscriptBinding,
};
pub use snp_chain::{ProductFamily, TcbPolicy, VerificationConfig};
pub use verify::{VerifyError, verify_tee_receipt};
