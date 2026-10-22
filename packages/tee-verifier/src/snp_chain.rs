use std::sync::Arc;
use std::time::SystemTime;

use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use p384::ecdsa::VerifyingKey as EcVerifyingKey;
use rsa::RsaPublicKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use sha2::Sha384;
use signature::Verifier;
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;

use crate::quote::QuoteVerifyError;
use crate::snp_report::{
    PLATFORM_INFO_SMT_EN, POLICY_MIGRATE_MA, POLICY_SMT_ALLOWED, SnpReportFields, TcbVersion,
    parse_report_fields,
};
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

/// Minimum TCB component versions, checked against the report's
/// REPORTED_TCB (the TCB the VCEK certifies).
///
/// There is no default: callers choose a policy. Use [`TcbPolicy::minimums`]
/// with floors from AMD's current security bulletins for the product family
/// in use. [`TcbPolicy::reject_all_zero`] accepts any non-zero TCB and is not
/// a floor.
#[derive(Debug, Clone)]
pub struct TcbPolicy {
    pub boot_loader_min: u8,
    pub tee_min: u8,
    pub snp_min: u8,
    pub microcode_min: u8,
}

impl TcbPolicy {
    /// Floors for each TCB component.
    pub fn minimums(boot_loader_min: u8, tee_min: u8, snp_min: u8, microcode_min: u8) -> Self {
        Self {
            boot_loader_min,
            tee_min,
            snp_min,
            microcode_min,
        }
    }

    /// Reject only an all-zero TCB (an uninitialized or debug platform).
    /// Accepts any other TCB, however old: not a floor. For tests and for
    /// callers that check the TCB themselves.
    pub fn reject_all_zero() -> Self {
        Self {
            boot_loader_min: 0,
            tee_min: 0,
            snp_min: 0,
            microcode_min: 0,
        }
    }
}

/// Checks on the guest and platform state recorded in the report.
#[derive(Debug, Clone)]
pub struct ReportPolicy {
    /// The VMPL the report must come from (0: the most privileged level, as
    /// on GCP Confidential VMs without an SVSM).
    pub expected_vmpl: u32,
    /// Accept guests whose policy allows SMT and platforms with SMT enabled.
    /// GCP N2D runs with SMT; set `false` to require SMT to be off.
    pub allow_smt: bool,
    /// Accept guests whose policy allows a migration agent (MIGRATE_MA).
    pub allow_migrate_ma: bool,
    /// Require the report's CHIP_ID to be present (not masked) and equal to
    /// the VCEK's hwID extension.
    pub require_chip_id: bool,
}

impl Default for ReportPolicy {
    fn default() -> Self {
        Self {
            expected_vmpl: 0,
            allow_smt: true,
            allow_migrate_ma: false,
            require_chip_id: true,
        }
    }
}

/// Revocation check for the AMD certificate chain.
///
/// AMD publishes a CRL per product family (`https://kdsintf.amd.com/vcek/v1/{product}/crl`),
/// signed by the ARK. Implementations fetch and verify it out of band; the
/// verifier itself never fetches anything.
pub trait RevocationCheck: Send + Sync + std::fmt::Debug {
    /// Return `Err(reason)` if the ASK or VCEK is revoked.
    fn check(
        &self,
        family: ProductFamily,
        ask: &Certificate,
        vcek: &Certificate,
    ) -> Result<(), String>;
}

/// A revocation list of certificate serial numbers (big-endian bytes), for
/// example taken from a verified AMD CRL.
#[derive(Debug, Clone, Default)]
pub struct RevokedSerials {
    pub serials: Vec<Vec<u8>>,
}

impl RevocationCheck for RevokedSerials {
    fn check(
        &self,
        _family: ProductFamily,
        ask: &Certificate,
        vcek: &Certificate,
    ) -> Result<(), String> {
        for (name, cert) in [("ASK", ask), ("VCEK", vcek)] {
            let serial = cert.tbs_certificate.serial_number.as_bytes();
            if self.serials.iter().any(|s| s.as_slice() == serial) {
                return Err(format!("{name} certificate is revoked"));
            }
        }
        Ok(())
    }
}

/// SEV-SNP verification settings. There is no `Default`: build one with
/// [`VerificationConfig::new`] and an explicit [`TcbPolicy`].
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    pub tcb_policy: TcbPolicy,
    pub report_policy: ReportPolicy,
    /// Time at which the VCEK and ASK must be valid (default: now).
    pub verification_time: Option<SystemTime>,
    /// Optional revocation check for the ASK and VCEK.
    pub revocation: Option<Arc<dyn RevocationCheck>>,
}

impl VerificationConfig {
    /// Settings with `tcb_policy`, the default [`ReportPolicy`], the current
    /// time and no revocation check.
    pub fn new(tcb_policy: TcbPolicy) -> Self {
        Self {
            tcb_policy,
            report_policy: ReportPolicy::default(),
            verification_time: None,
            revocation: None,
        }
    }
}

// ---------------------------------------------------------------------------
// TCB and report policy checks
// ---------------------------------------------------------------------------

fn check_tcb(tcb: &TcbVersion, policy: &TcbPolicy) -> Result<(), QuoteVerifyError> {
    // Reject all-zero TCB (uninitialized/debug platforms)
    if tcb.boot_loader == 0 && tcb.tee == 0 && tcb.snp == 0 && tcb.microcode == 0 {
        return Err(QuoteVerifyError::ChainInvalid(
            "TCB version is all zeros (uninitialized or debug platform)".into(),
        ));
    }

    for (name, value, min) in [
        ("boot_loader", tcb.boot_loader, policy.boot_loader_min),
        ("tee", tcb.tee, policy.tee_min),
        ("snp", tcb.snp, policy.snp_min),
        ("microcode", tcb.microcode, policy.microcode_min),
    ] {
        if value < min {
            return Err(QuoteVerifyError::ChainInvalid(format!(
                "TCB {name} {value} below minimum {min}"
            )));
        }
    }
    Ok(())
}

fn check_report_policy(
    fields: &SnpReportFields,
    policy: &ReportPolicy,
) -> Result<(), QuoteVerifyError> {
    if fields.vmpl != policy.expected_vmpl {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "report VMPL {} is not the expected VMPL {}",
            fields.vmpl, policy.expected_vmpl
        )));
    }
    if fields.policy & POLICY_MIGRATE_MA != 0 && !policy.allow_migrate_ma {
        return Err(QuoteVerifyError::ChainInvalid(
            "guest policy allows a migration agent (MIGRATE_MA)".into(),
        ));
    }
    if !policy.allow_smt {
        if fields.policy & POLICY_SMT_ALLOWED != 0 {
            return Err(QuoteVerifyError::ChainInvalid(
                "guest policy allows SMT".into(),
            ));
        }
        if fields.platform_info & PLATFORM_INFO_SMT_EN != 0 {
            return Err(QuoteVerifyError::ChainInvalid(
                "SMT is enabled on the platform".into(),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VCEK extensions
// ---------------------------------------------------------------------------

const OID_BL_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.1");
const OID_TEE_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.2");
const OID_SNP_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.3");
const OID_UCODE_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.8");
const OID_HW_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");

fn extension_value(cert: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

fn extension_spl(
    cert: &Certificate,
    oid: ObjectIdentifier,
    name: &str,
) -> Result<u8, QuoteVerifyError> {
    let value = extension_value(cert, oid).ok_or_else(|| {
        QuoteVerifyError::ChainInvalid(format!("VCEK certificate has no {name} extension"))
    })?;
    u8::from_der(value).map_err(|e| {
        QuoteVerifyError::ChainInvalid(format!(
            "VCEK {name} extension is not an INTEGER 0-255: {e}"
        ))
    })
}

/// The VCEK's TCB (from its SPL extensions).
fn vcek_tcb(cert: &Certificate) -> Result<TcbVersion, QuoteVerifyError> {
    Ok(TcbVersion {
        boot_loader: extension_spl(cert, OID_BL_SPL, "blSPL")?,
        tee: extension_spl(cert, OID_TEE_SPL, "teeSPL")?,
        snp: extension_spl(cert, OID_SNP_SPL, "snpSPL")?,
        microcode: extension_spl(cert, OID_UCODE_SPL, "ucodeSPL")?,
    })
}

/// The VCEK's hwID extension (64 bytes on Milan and Genoa). Accepts the
/// value as a DER OCTET STRING or as the raw bytes.
fn vcek_hw_id(cert: &Certificate) -> Result<[u8; 64], QuoteVerifyError> {
    let value = extension_value(cert, OID_HW_ID).ok_or_else(|| {
        QuoteVerifyError::ChainInvalid("VCEK certificate has no hwID extension".into())
    })?;
    let bytes = match OctetString::from_der(value) {
        Ok(inner) if inner.as_bytes().len() == 64 => inner.as_bytes().to_vec(),
        _ => value.to_vec(),
    };
    bytes
        .try_into()
        .map_err(|_| QuoteVerifyError::ChainInvalid("VCEK hwID extension is not 64 bytes".into()))
}

fn check_validity(cert: &Certificate, name: &str, at: SystemTime) -> Result<(), QuoteVerifyError> {
    let validity = &cert.tbs_certificate.validity;
    if at < validity.not_before.to_system_time() {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "{name} certificate is not yet valid"
        )));
    }
    if at > validity.not_after.to_system_time() {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "{name} certificate has expired"
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

/// Verify the full VCEK → ASK → ARK certificate chain and the report.
///
/// Called from `verify_tee_receipt()` when `snp_vcek_cert` is present.
///
/// Steps:
/// 1. Parse VCEK certificate from DER
/// 2. Try each bundled {ARK, ASK} pair; the matching family is whichever validates
/// 3. [`check_report_against_vcek`]: validity, revocation, report
///    signature, report policy, TCB and chip id
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
    let mut matched = None;

    for chain in BUNDLED_CHAINS {
        match verify_chain(chain, &vcek_cert) {
            Ok(ask) => {
                matched = Some((chain.family, ask));
                break;
            }
            Err(e) => {
                last_err = format!("{:?}: {e}", chain.family);
            }
        }
    }

    let Some((family, ask_cert)) = matched else {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "no bundled chain validates this VCEK — unsupported product family (last error: {last_err})"
        )));
    };

    // 3. Report checks against the (chain-verified) VCEK
    check_report_against_vcek(report_bytes, &vcek_cert, family, &ask_cert, config)
}

/// Check a report against a VCEK whose chain has already been verified.
///
/// - the VCEK and ASK are valid at the verification time, and not revoked
///   (when a revocation check is configured);
/// - the report signature verifies under the VCEK (and the report is
///   VCEK-signed, not debug);
/// - VMPL, MIGRATE_MA and SMT match the report policy;
/// - REPORTED_TCB equals the TCB the VCEK certifies, and meets the minimum;
/// - CHIP_ID is present and equals the VCEK's hwID.
pub fn check_report_against_vcek(
    report_bytes: &[u8],
    vcek_cert: &Certificate,
    family: ProductFamily,
    ask_cert: &Certificate,
    config: &VerificationConfig,
) -> Result<(), QuoteVerifyError> {
    let at = config.verification_time.unwrap_or_else(SystemTime::now);
    check_validity(vcek_cert, "VCEK", at)?;
    check_validity(ask_cert, "ASK", at)?;
    if let Some(revocation) = &config.revocation {
        revocation
            .check(family, ask_cert, vcek_cert)
            .map_err(QuoteVerifyError::ChainInvalid)?;
    }

    let fields = parse_report_fields(report_bytes)?;

    // Report signature (also checks the algorithm, signing key and DEBUG)
    let vcek_pubkey = extract_ec_pubkey(vcek_cert)?;
    snp_sig::verify_report_signature(report_bytes, &vcek_pubkey)?;

    check_report_policy(&fields, &config.report_policy)?;

    // The VCEK is issued for one TCB: the report must claim that TCB.
    let certified = vcek_tcb(vcek_cert)?;
    if fields.reported_tcb != certified {
        return Err(QuoteVerifyError::ChainInvalid(format!(
            "report REPORTED_TCB {:?} does not match the VCEK's TCB {:?}",
            fields.reported_tcb, certified
        )));
    }
    check_tcb(&fields.reported_tcb, &config.tcb_policy)?;

    if config.report_policy.require_chip_id {
        if fields.chip_id.iter().all(|&b| b == 0) {
            return Err(QuoteVerifyError::ChainInvalid(
                "report CHIP_ID is masked (all zeros)".into(),
            ));
        }
        if fields.chip_id != vcek_hw_id(vcek_cert)? {
            return Err(QuoteVerifyError::ChainInvalid(
                "report CHIP_ID does not match the VCEK hwID".into(),
            ));
        }
    }

    Ok(())
}

/// Verify a single bundled chain: ARK self-signed, ASK signed by ARK, VCEK
/// signed by ASK. Returns the ASK.
fn verify_chain(
    chain: &BundledChain,
    vcek_cert: &Certificate,
) -> Result<Certificate, QuoteVerifyError> {
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

    Ok(ask_cert)
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

    fn tcb(bl: u8, tee: u8, snp: u8, ucode: u8) -> TcbVersion {
        TcbVersion {
            boot_loader: bl,
            tee,
            snp,
            microcode: ucode,
        }
    }

    #[test]
    fn tcb_all_zero_rejected() {
        let err = check_tcb(&tcb(0, 0, 0, 0), &TcbPolicy::reject_all_zero()).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("all zeros")
        ));
        check_tcb(&tcb(3, 1, 12, 200), &TcbPolicy::reject_all_zero()).unwrap();
    }

    #[test]
    fn tcb_below_minimum_rejected_per_component() {
        let policy = TcbPolicy {
            boot_loader_min: 3,
            tee_min: 0,
            snp_min: 22,
            microcode_min: 213,
        };
        check_tcb(&tcb(3, 0, 22, 213), &policy).unwrap();
        for (t, name) in [
            (tcb(2, 0, 22, 213), "boot_loader"),
            (tcb(3, 0, 21, 213), "snp"),
            (tcb(3, 0, 22, 212), "microcode"),
        ] {
            let err = check_tcb(&t, &policy).unwrap_err();
            assert!(
                matches!(err, QuoteVerifyError::ChainInvalid(ref msg) if msg.contains(name)),
                "{name}: {err}"
            );
        }
    }

    #[test]
    fn unknown_vcek_family_rejected() {
        // Generate a self-signed P-384 cert that is NOT signed by any bundled ASK
        let cert_params = rcgen::CertificateParams::new(vec!["test".into()]).unwrap();
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let vcek_der = cert.der().to_vec();

        let report = vec![0u8; 1184];
        let config = VerificationConfig::new(TcbPolicy::reject_all_zero());

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
        let config = VerificationConfig::new(TcbPolicy::reject_all_zero());

        let err = verify_snp_attestation(&report, &garbage, &config).unwrap_err();
        assert!(matches!(
            err,
            QuoteVerifyError::ChainInvalid(ref msg) if msg.contains("failed to parse VCEK")
        ));
    }
}

/// Checks on a report against a synthetic VCEK (the AMD chain itself cannot
/// be exercised without AMD-signed certificates).
#[cfg(test)]
mod report_vcek_tests {
    use super::*;
    use crate::snp_report::build::*;
    use ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey};
    use p384::pkcs8::DecodePrivateKey;

    const CHIP_ID: [u8; 64] = [0x5A; 64];
    const GOOD_TCB: TcbVersion = TcbVersion {
        boot_loader: 4,
        tee: 0,
        snp: 22,
        microcode: 213,
    };

    struct Vcek {
        key: SigningKey,
        cert: Certificate,
    }

    fn spl_ext(oid: &[u64], v: u8) -> rcgen::CustomExtension {
        rcgen::CustomExtension::from_oid_content(oid, v.to_der().unwrap())
    }

    /// Synthetic VCEK with TCB and hwID extensions.
    fn make_vcek(
        tcb: TcbVersion,
        hw_id: Option<Vec<u8>>,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> Vcek {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let key = SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["vcek".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.custom_extensions = vec![
            spl_ext(&[1, 3, 6, 1, 4, 1, 3704, 1, 3, 1], tcb.boot_loader),
            spl_ext(&[1, 3, 6, 1, 4, 1, 3704, 1, 3, 2], tcb.tee),
            spl_ext(&[1, 3, 6, 1, 4, 1, 3704, 1, 3, 3], tcb.snp),
            spl_ext(&[1, 3, 6, 1, 4, 1, 3704, 1, 3, 8], tcb.microcode),
        ];
        if let Some(hw_id) = hw_id {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 3704, 1, 4],
                    hw_id,
                ));
        }
        let cert = params.self_signed(&key_pair).unwrap();
        Vcek {
            key,
            cert: Certificate::from_der(cert.der()).unwrap(),
        }
    }

    fn hw_id_octet_string(id: &[u8; 64]) -> Vec<u8> {
        OctetString::new(id.to_vec()).unwrap().to_der().unwrap()
    }

    fn good_vcek() -> Vcek {
        make_vcek(
            GOOD_TCB,
            Some(hw_id_octet_string(&CHIP_ID)),
            (2020, 1, 1),
            (2040, 1, 1),
        )
    }

    fn ask() -> Certificate {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["ask".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2045, 1, 1);
        Certificate::from_der(params.self_signed(&key_pair).unwrap().der()).unwrap()
    }

    /// A GCP-like report: policy with SMT allowed and the reserved bit set,
    /// VMPL 0, VCEK-signed, REPORTED_TCB = `tcb`, CHIP_ID = [`CHIP_ID`].
    fn report_with(edit: impl FnOnce(&mut Vec<u8>), tcb: TcbVersion, key: &SigningKey) -> Vec<u8> {
        let mut r = vec![0u8; 1184];
        set_u32(&mut r, 0, 3);
        set_u64(&mut r, OFF_POLICY, (1 << 17) | (1 << 16));
        set_u32(&mut r, 0x34, 1); // ECDSA P-384 with SHA-384
        set_u64(&mut r, OFF_PLATFORM_INFO, 1); // SMT enabled
        set_u64(&mut r, OFF_REPORTED_TCB, tcb.to_raw());
        set_u64(&mut r, OFF_CURRENT_TCB, tcb.to_raw());
        set_u64(&mut r, OFF_COMMITTED_TCB, tcb.to_raw());
        r[OFF_CHIP_ID..OFF_CHIP_ID + 64].copy_from_slice(&CHIP_ID);
        edit(&mut r);
        sign(&mut r, key);
        r
    }

    fn sign(report: &mut [u8], key: &SigningKey) {
        let sig: Signature = key.sign(&report[..0x2A0]);
        let bytes = sig.to_bytes();
        for (half, offset) in [(&bytes[..48], 0x2A0), (&bytes[48..], 0x2A0 + 72)] {
            let le: Vec<u8> = half.iter().rev().copied().collect();
            report[offset..offset + 48].copy_from_slice(&le);
            report[offset + 48..offset + 72].fill(0);
        }
    }

    fn at(y: i32) -> VerificationConfig {
        VerificationConfig {
            verification_time: Some(
                std::time::UNIX_EPOCH
                    + std::time::Duration::from_secs(((y - 1970) as u64) * 365 * 86_400),
            ),
            ..VerificationConfig::new(TcbPolicy::reject_all_zero())
        }
    }

    fn check(report: &[u8], vcek: &Vcek, config: &VerificationConfig) -> Result<(), String> {
        check_report_against_vcek(report, &vcek.cert, ProductFamily::Milan, &ask(), config)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn matching_report_is_accepted() {
        let vcek = good_vcek();
        let report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        check(&report, &vcek, &at(2026)).unwrap();
    }

    #[test]
    fn raw_hw_id_extension_is_accepted() {
        let vcek = make_vcek(GOOD_TCB, Some(CHIP_ID.to_vec()), (2020, 1, 1), (2040, 1, 1));
        let report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        check(&report, &vcek, &at(2026)).unwrap();
    }

    #[test]
    fn reported_tcb_must_equal_the_vcek_tcb() {
        let vcek = good_vcek();
        let other = TcbVersion {
            microcode: 212,
            ..GOOD_TCB
        };
        let report = report_with(|_| {}, other, &vcek.key);
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("REPORTED_TCB"), "{err}");
    }

    #[test]
    fn minimum_tcb_is_enforced_on_the_reported_tcb() {
        let vcek = good_vcek();
        let report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        let mut config = at(2026);
        config.tcb_policy = TcbPolicy {
            boot_loader_min: 0,
            tee_min: 0,
            snp_min: 23,
            microcode_min: 0,
        };
        let err = check(&report, &vcek, &config).unwrap_err();
        assert!(err.contains("TCB snp 22 below minimum 23"), "{err}");

        config.tcb_policy.snp_min = 22;
        config.tcb_policy.microcode_min = 213;
        check(&report, &vcek, &config).unwrap();
    }

    #[test]
    fn non_zero_vmpl_is_rejected() {
        let vcek = good_vcek();
        let report = report_with(|r| set_u32(r, OFF_VMPL, 1), GOOD_TCB, &vcek.key);
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("VMPL"), "{err}");

        let mut config = at(2026);
        config.report_policy.expected_vmpl = 1;
        check(&report, &vcek, &config).unwrap();
    }

    #[test]
    fn migration_agent_policy_is_rejected_by_default() {
        let vcek = good_vcek();
        let report = report_with(
            |r| set_u64(r, OFF_POLICY, (1 << 17) | (1 << 16) | (1 << 18)),
            GOOD_TCB,
            &vcek.key,
        );
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("MIGRATE_MA"), "{err}");

        let mut config = at(2026);
        config.report_policy.allow_migrate_ma = true;
        check(&report, &vcek, &config).unwrap();
    }

    #[test]
    fn smt_is_rejected_when_not_allowed() {
        let vcek = good_vcek();
        let mut config = at(2026);
        config.report_policy.allow_smt = false;

        let smt_policy = report_with(|_| {}, GOOD_TCB, &vcek.key);
        let err = check(&smt_policy, &vcek, &config).unwrap_err();
        assert!(err.contains("SMT"), "{err}");

        let smt_platform = report_with(|r| set_u64(r, OFF_POLICY, 1 << 17), GOOD_TCB, &vcek.key);
        let err = check(&smt_platform, &vcek, &config).unwrap_err();
        assert!(err.contains("SMT is enabled on the platform"), "{err}");

        let no_smt = report_with(
            |r| {
                set_u64(r, OFF_POLICY, 1 << 17);
                set_u64(r, OFF_PLATFORM_INFO, 0);
            },
            GOOD_TCB,
            &vcek.key,
        );
        check(&no_smt, &vcek, &config).unwrap();
    }

    #[test]
    fn chip_id_must_match_the_vcek_hw_id() {
        let vcek = good_vcek();
        let report = report_with(
            |r| r[OFF_CHIP_ID..OFF_CHIP_ID + 64].copy_from_slice(&[0x11; 64]),
            GOOD_TCB,
            &vcek.key,
        );
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("CHIP_ID does not match"), "{err}");
    }

    #[test]
    fn masked_chip_id_is_rejected() {
        let vcek = good_vcek();
        let report = report_with(
            |r| r[OFF_CHIP_ID..OFF_CHIP_ID + 64].fill(0),
            GOOD_TCB,
            &vcek.key,
        );
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("masked"), "{err}");
    }

    #[test]
    fn missing_vcek_extensions_are_rejected() {
        let vcek = make_vcek(GOOD_TCB, None, (2020, 1, 1), (2040, 1, 1));
        let report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("hwID"), "{err}");
    }

    #[test]
    fn vcek_validity_window_is_enforced() {
        let vcek = make_vcek(
            GOOD_TCB,
            Some(hw_id_octet_string(&CHIP_ID)),
            (2022, 1, 1),
            (2025, 1, 1),
        );
        let report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        assert!(
            check(&report, &vcek, &at(2026))
                .unwrap_err()
                .contains("expired")
        );
        assert!(
            check(&report, &vcek, &at(2021))
                .unwrap_err()
                .contains("not yet valid")
        );
        check(&report, &vcek, &at(2023)).unwrap();
    }

    #[test]
    fn revocation_hook_is_consulted() {
        let vcek = good_vcek();
        let report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        let mut config = at(2026);
        config.revocation = Some(Arc::new(RevokedSerials {
            serials: vec![vcek.cert.tbs_certificate.serial_number.as_bytes().to_vec()],
        }));
        let err = check(&report, &vcek, &config).unwrap_err();
        assert!(err.contains("VCEK certificate is revoked"), "{err}");

        config.revocation = Some(Arc::new(RevokedSerials::default()));
        check(&report, &vcek, &config).unwrap();
    }

    #[test]
    fn report_signed_by_another_key_is_rejected() {
        let vcek = good_vcek();
        let other = good_vcek();
        let report = report_with(|_| {}, GOOD_TCB, &other.key);
        let err = check(&report, &vcek, &at(2026)).unwrap_err();
        assert!(err.contains("signature invalid"), "{err}");
    }

    #[test]
    fn report_fields_are_covered_by_the_signature() {
        let vcek = good_vcek();
        let mut report = report_with(|_| {}, GOOD_TCB, &vcek.key);
        // Change VMPL after signing.
        set_u32(&mut report, OFF_VMPL, 0);
        report[OFF_VMPL] = 0;
        set_u64(&mut report, OFF_POLICY, 1 << 17);
        assert!(check(&report, &vcek, &at(2026)).is_err());
    }
}
