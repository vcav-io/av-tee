#![cfg(feature = "snp-live")]

use tee_core::TeeType;
use tee_core::attestation::CvmRuntime;
use tee_snp::SevSnpCvm;

#[test]
fn device_opens() {
    let cvm = SevSnpCvm::new().expect("failed to open /dev/sev-guest");
    assert!(cvm.is_real_tee());
}

#[test]
fn identity_is_sev_snp() {
    let cvm = SevSnpCvm::new().unwrap();
    let id = cvm.identity();
    assert!(matches!(id.tee_type, TeeType::SevSnp));
    assert!(!id.measurement.is_empty());
    assert_eq!(id.measurement.len(), 96); // 48 bytes hex
}

#[tokio::test]
async fn attestation_report_binds_user_data() {
    let cvm = SevSnpCvm::new().unwrap();
    let user_data = [0xABu8; 64];
    let report = cvm.get_attestation(&user_data).await.unwrap();
    assert_eq!(report.tee_type, TeeType::SevSnp);
    assert_eq!(report.user_data, user_data);
    assert!(!report.quote.is_empty());
    assert!(!report.measurement.is_empty());
}

#[tokio::test]
async fn seal_unseal_roundtrip() {
    let cvm = SevSnpCvm::new().unwrap();
    let plaintext = b"live hardware seal test";
    let sealed = cvm.seal(plaintext).await.unwrap();
    let unsealed = cvm.unseal(&sealed).await.unwrap();
    assert_eq!(&unsealed[..], plaintext);
}

#[test]
fn session_keypair_generation() {
    let cvm = SevSnpCvm::new().unwrap();
    let (pub1, _sec1) = cvm.derive_session_keypair().unwrap();
    let (pub2, _sec2) = cvm.derive_session_keypair().unwrap();
    assert_ne!(pub1.as_bytes(), pub2.as_bytes());
}

#[tokio::test]
async fn vcek_cert_extracted_from_report() {
    let cvm = SevSnpCvm::new().unwrap();
    let user_data = [0xCCu8; 64];
    let report = cvm.get_attestation(&user_data).await.unwrap();

    let vcek_der = report
        .vcek_cert_der
        .as_ref()
        .expect("hypervisor should provide VCEK cert in extended report");
    assert!(
        vcek_der.len() > 100,
        "VCEK DER cert should be non-trivial, got {} bytes",
        vcek_der.len()
    );
}

#[tokio::test]
async fn vcek_chain_verification_passes() {
    use tee_verifier::{VerificationConfig, snp_chain};

    let cvm = SevSnpCvm::new().unwrap();
    let user_data = [0xDDu8; 64];
    let report = cvm.get_attestation(&user_data).await.unwrap();

    let vcek_der = report
        .vcek_cert_der
        .as_ref()
        .expect("VCEK cert required for chain verification");

    // Full chain: VCEK → ASK → ARK + report signature + TCB
    snp_chain::verify_snp_attestation(&report.quote, vcek_der, &VerificationConfig::default())
        .expect("VCEK chain verification should pass on real AMD hardware");
}
