use der::{Decode, Encode};
use p384::ecdsa::VerifyingKey as EcVerifyingKey;
use rsa::RsaPublicKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use sha2::Sha384;
use signature::Verifier;
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;

use crate::quote::QuoteVerifyError;
use crate::snp_sig;

// ---------------------------------------------------------------------------
// Bundled AMD root certificates (DER-encoded)
// Downloaded from AMD KDS: https://kdsintf.amd.com/vcek/v1/{product}/cert_chain
// ---------------------------------------------------------------------------

// Milan ARK — self-signed root, RSA-4096, SHA-384
// SHA-256 fingerprint: 69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD
const MILAN_ARK_DER: &[u8] = include_bytes!("certs/milan_ark.der");

// Milan ASK — signed by ARK, RSA-4096, SHA-384
// SHA-256 fingerprint: 67:D3:03:BD:39:05:FD:38:DB:8B:20:E0:79:36:99:87:0E:7F:A6:12:EA:AD:5D:EC:35:82:93:FD:8C:0B:AC:1B
const MILAN_ASK_DER: &[u8] = include_bytes!("certs/milan_ask.der");

// Genoa ARK — self-signed root, RSA-4096, SHA-384
// SHA-256 fingerprint: 4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1
const GENOA_ARK_DER: &[u8] = include_bytes!("certs/genoa_ark.der");

// Genoa ASK — signed by ARK, RSA-4096, SHA-384
// SHA-256 fingerprint: 54:64:73:8C:15:46:AE:D5:F2:CE:CF:1D:C9:8C:5C:96:0A:92:E8:91:32:38:A6:17:11:BC:90:EC:6E:82:85:21
const GENOA_ASK_DER: &[u8] = include_bytes!("certs/genoa_ask.der");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductFamily {
    Milan,
    Genoa,
}

#[derive(Debug, Clone)]
pub struct TcbPolicy {
    pub boot_loader_min: u8,
    pub tee_min: u8,
    pub snp_min: u8,
    pub microcode_min: u8,
}

impl TcbPolicy {
    /// Default policy: reject all-zero TCB components.
    /// An all-zero TCB usually indicates an uninitialized or debug platform.
    pub fn reject_all_zero() -> Self {
        Self {
            boot_loader_min: 0,
            tee_min: 0,
            snp_min: 0,
            microcode_min: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerificationConfig {
    pub tcb_policy: TcbPolicy,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            tcb_policy: TcbPolicy::reject_all_zero(),
        }
    }
}

// ---------------------------------------------------------------------------
// TCB extraction from report
// ---------------------------------------------------------------------------

/// TCB version fields from the SEV-SNP attestation report at offset 384.
/// Layout: boot_loader(1), tee(1), reserved(2), snp(1), microcode(1), reserved(2)
const TCB_OFFSET: usize = 384;

struct ReportTcb {
    boot_loader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

fn extract_tcb(report_bytes: &[u8]) -> Result<ReportTcb, QuoteVerifyError> {
    if report_bytes.len() < TCB_OFFSET + 8 {
        return Err(QuoteVerifyError::ChainInvalid(
            "report too short for TCB extraction".into(),
        ));
    }
    Ok(ReportTcb {
        boot_loader: report_bytes[TCB_OFFSET],
        tee: report_bytes[TCB_OFFSET + 1],
        snp: report_bytes[TCB_OFFSET + 4],
        microcode: report_bytes[TCB_OFFSET + 5],
    })
}

fn check_tcb(tcb: &ReportTcb, policy: &TcbPolicy) -> Result<(), QuoteVerifyError> {
    // Reject all-zero TCB (uninitialized/debug platforms)
    if tcb.boot_loader == 0 && tcb.tee == 0 && tcb.snp == 0 && tcb.microcode == 0 {
        return Err(QuoteVerifyError::ChainInvalid(
            "TCB version is all zeros (uninitialized or debug platform)".into(),
        ));
    }

    if tcb.boot_loader < policy.boot_loader_min {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "TCB boot_loader {} below minimum {}",
            tcb.boot_loader, policy.boot_loader_min
        )));
    }
    if tcb.tee < policy.tee_min {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "TCB tee {} below minimum {}",
            tcb.tee, policy.tee_min
        )));
    }
    if tcb.snp < policy.snp_min {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "TCB snp {} below minimum {}",
            tcb.snp, policy.snp_min
        )));
    }
    if tcb.microcode < policy.microcode_min {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "TCB microcode {} below minimum {}",
            tcb.microcode, policy.microcode_min
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate chain verification
// ---------------------------------------------------------------------------

struct BundledChain {
    family: ProductFamily,
    ark_der: &'static [u8],
    ask_der: &'static [u8],
}

const BUNDLED_CHAINS: &[BundledChain] = &[
    BundledChain {
        family: ProductFamily::Milan,
        ark_der: MILAN_ARK_DER,
        ask_der: MILAN_ASK_DER,
    },
    BundledChain {
        family: ProductFamily::Genoa,
        ark_der: GENOA_ARK_DER,
        ask_der: GENOA_ASK_DER,
    },
];

/// Verify the full VCEK → ASK → ARK certificate chain and report signature.
///
/// Called from `verify_tee_receipt()` when `snp_vcek_cert` is present.
///
/// Steps:
/// 1. Parse VCEK certificate from DER
/// 2. Try each bundled {ARK, ASK} pair; the matching family is whichever validates
/// 3. Extract VCEK public key and verify report signature
/// 4. Check TCB version against policy
pub fn verify_snp_attestation(
    report_bytes: &[u8],
    vcek_cert_der: &[u8],
    config: &VerificationConfig,
) -> Result<(), QuoteVerifyError> {
    // 1. Parse VCEK cert
    let vcek_cert = Certificate::from_der(vcek_cert_der).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!("failed to parse VCEK certificate: {e}"))
    })?;

    // 2. Try each bundled chain
    let mut last_err = String::new();
    let mut matched = false;

    for chain in BUNDLED_CHAINS {
        match verify_chain(chain, &vcek_cert) {
            Ok(()) => {
                matched = true;
                break;
            }
            Err(e) => {
                last_err = format!("{:?}: {e}", chain.family);
            }
        }
    }

    if !matched {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "no bundled chain validates this VCEK — unsupported product family (last error: {last_err})"
        )));
    }

    // 3. Extract VCEK public key (ECDSA P-384) and verify report signature
    let vcek_pubkey = extract_ec_pubkey(&vcek_cert)?;
    snp_sig::verify_report_signature(report_bytes, &vcek_pubkey)?;

    // 4. TCB version check
    let tcb = extract_tcb(report_bytes)?;
    check_tcb(&tcb, &config.tcb_policy)?;

    Ok(())
}

/// Verify a single bundled chain: ARK self-signed, ASK signed by ARK, VCEK signed by ASK.
fn verify_chain(chain: &BundledChain, vcek_cert: &Certificate) -> Result<(), QuoteVerifyError> {
    let ark_cert = Certificate::from_der(chain.ark_der)
        .map_err(|e| QuoteVerifyError::ChainInvalid(format!("failed to parse bundled ARK: {e}")))?;
    let ask_cert = Certificate::from_der(chain.ask_der)
        .map_err(|e| QuoteVerifyError::ChainInvalid(format!("failed to parse bundled ASK: {e}")))?;

    // ARK is self-signed
    verify_cert_signature(&ark_cert, &ark_cert)?;
    // ASK signed by ARK
    verify_cert_signature(&ask_cert, &ark_cert)?;
    // VCEK signed by ASK
    verify_cert_signature(vcek_cert, &ask_cert)?;

    Ok(())
}

/// Verify that `cert` was signed by `issuer` using RSA-PSS with SHA-384.
///
/// AMD SEV-SNP ARK/ASK/VCEK chain uses RSASSA-PSS with SHA-384 for the
/// certificate signatures (the ARK and ASK are RSA-4096 keys).
fn verify_cert_signature(cert: &Certificate, issuer: &Certificate) -> Result<(), QuoteVerifyError> {
    // Extract issuer's RSA public key
    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
    let issuer_rsa_key = extract_rsa_pubkey_from_spki(issuer_spki)?;

    // The TBS (to-be-signed) portion is what was signed
    let tbs_der = cert.tbs_certificate.to_der().map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!("failed to encode TBS certificate: {e}"))
    })?;

    // Extract signature bits from the cert
    let sig_bytes = cert.signature.raw_bytes();

    // AMD uses RSASSA-PSS with SHA-384
    let verifying_key = RsaPssVerifyingKey::<Sha384>::new(issuer_rsa_key);
    let signature = rsa::pss::Signature::try_from(sig_bytes).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!("invalid RSA-PSS signature encoding: {e}"))
    })?;

    verifying_key.verify(&tbs_der, &signature).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!("certificate signature verification failed: {e}"))
    })
}

fn extract_rsa_pubkey_from_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<RsaPublicKey, QuoteVerifyError> {
    let spki_der = spki
        .to_der()
        .map_err(|e| QuoteVerifyError::ChainInvalid(format!("failed to encode SPKI: {e}")))?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| QuoteVerifyError::ChainInvalid(format!("failed to parse SPKI ref: {e}")))?;

    let rsa_key = rsa::RsaPublicKey::try_from(spki_ref).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!("failed to extract RSA key from SPKI: {e}"))
    })?;
    Ok(rsa_key)
}

/// Extract the ECDSA P-384 public key from a VCEK certificate.
fn extract_ec_pubkey(cert: &Certificate) -> Result<EcVerifyingKey, QuoteVerifyError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    EcVerifyingKey::from_sec1_bytes(pk_bytes).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!(
            "failed to extract ECDSA P-384 key from VCEK cert: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_certs_parse_successfully() {
        for chain in BUNDLED_CHAINS {
            let ark = Certificate::from_der(chain.ark_der).unwrap();
            let ask = Certificate::from_der(chain.ask_der).unwrap();
            // ARK should be self-signed (subject == issuer)
            assert_eq!(
                ark.tbs_certificate.subject, ark.tbs_certificate.issuer,
                "{:?} ARK should be self-signed",
                chain.family
            );
            // ASK issuer should match ARK subject
            assert_eq!(
                ask.tbs_certificate.issuer, ark.tbs_certificate.subject,
                "{:?} ASK issuer should be ARK",
                chain.family
            );
        }
    }

    #[test]
    fn bundled_ark_self_signatures_valid() {
        for chain in BUNDLED_CHAINS {
            let ark = Certificate::from_der(chain.ark_der).unwrap();
            verify_cert_signature(&ark, &ark)
                .unwrap_or_else(|e| panic!("{:?} ARK self-signature failed: {e}", chain.family));
        }
    }

    #[test]
    fn bundled_ask_signed_by_ark() {
        for chain in BUNDLED_CHAINS {
            let ark = Certificate::from_der(chain.ark_der).unwrap();
            let ask = Certificate::from_der(chain.ask_der).unwrap();
            verify_cert_signature(&ask, &ark)
                .unwrap_or_else(|e| panic!("{:?} ASK not signed by ARK: {e}", chain.family));
        }
    }

    #[test]
    fn tcb_all_zero_rejected() {
        let mut report = vec![0u8; 1184];
        // All zeros at TCB offset
        let tcb = extract_tcb(&report).unwrap();
        let err = check_tcb(&tcb, &TcbPolicy::reject_all_zero()).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("all zeros")
        ));

        // Non-zero TCB should pass default policy
        report[TCB_OFFSET] = 3; // boot_loader
        report[TCB_OFFSET + 1] = 1; // tee
        report[TCB_OFFSET + 4] = 12; // snp
        report[TCB_OFFSET + 5] = 200; // microcode
        let tcb = extract_tcb(&report).unwrap();
        check_tcb(&tcb, &TcbPolicy::reject_all_zero()).unwrap();
    }

    #[test]
    fn tcb_below_minimum_rejected() {
        let mut report = vec![0u8; 1184];
        report[TCB_OFFSET] = 2; // boot_loader
        report[TCB_OFFSET + 1] = 1; // tee
        report[TCB_OFFSET + 4] = 5; // snp
        report[TCB_OFFSET + 5] = 100; // microcode

        let strict_policy = TcbPolicy {
            boot_loader_min: 3,
            tee_min: 0,
            snp_min: 0,
            microcode_min: 0,
        };

        let tcb = extract_tcb(&report).unwrap();
        let err = check_tcb(&tcb, &strict_policy).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("boot_loader")
        ));
    }

    #[test]
    fn unknown_vcek_family_rejected() {
        // Generate a self-signed P-384 cert that is NOT signed by any bundled ASK
        let cert_params = rcgen::CertificateParams::new(vec!["test".into()]).unwrap();
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let vcek_der = cert.der().to_vec();

        let report = vec![0u8; 1184];
        let config = VerificationConfig::default();

        let err = verify_snp_attestation(&report, &vcek_der, &config).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("unsupported product family")
        ));
    }

    #[test]
    fn malformed_vcek_der_rejected() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        let report = vec![0u8; 1184];
        let config = VerificationConfig::default();

        let err = verify_snp_attestation(&report, &garbage, &config).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("failed to parse VCEK")
        ));
    }
}
