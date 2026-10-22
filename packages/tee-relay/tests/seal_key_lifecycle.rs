use std::sync::Arc;

use tee_core::SimulatedCvm;

#[tokio::test]
async fn first_boot_generates_and_seals_key() {
    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    assert!(!sealed_path.exists());

    let cvm = Arc::new(SimulatedCvm::new());
    let signing_key =
        tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
            .await
            .unwrap();

    assert!(sealed_path.exists());
    let _vk = signing_key.verifying_key(); // key is valid
}

#[tokio::test]
async fn second_boot_recovers_sealed_key() {
    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    let cvm = Arc::new(SimulatedCvm::new());

    let key1 = tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
        .await
        .unwrap();
    let key2 = tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
        .await
        .unwrap();

    assert_eq!(key1.to_bytes(), key2.to_bytes());
}

#[tokio::test]
async fn rejected_sealed_key_is_moved_aside_and_regenerated() {
    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    // A blob this CVM cannot open (e.g. sealed under an older key policy).
    std::fs::write(&sealed_path, b"av-tee-seal-v1 not openable by this cvm").unwrap();
    let cvm = Arc::new(SimulatedCvm::new());

    let key = tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
        .await
        .expect("a rejected sealed key does not stop startup");

    // The old blob is kept, under a new name.
    let rejected: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("sealed_signing_key.rejected-"))
        .collect();
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert_eq!(
        std::fs::read(tmp.path().join(&rejected[0])).unwrap(),
        b"av-tee-seal-v1 not openable by this cvm"
    );

    // The new key is sealed and recovered on the next start.
    let again = tee_relay::key_lifecycle::load_or_generate_signing_key(cvm.as_ref(), &sealed_path)
        .await
        .unwrap();
    assert_eq!(key.to_bytes(), again.to_bytes());
}

#[tokio::test]
async fn regenerated_key_reports_its_source() {
    use tee_relay::key_lifecycle::{KeySource, UnsealFailurePolicy, load_signing_key};

    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    std::fs::write(&sealed_path, b"garbage").unwrap();
    let cvm = SimulatedCvm::new();

    let loaded = load_signing_key(&cvm, &sealed_path, UnsealFailurePolicy::Regenerate)
        .await
        .unwrap();
    match loaded.source {
        KeySource::Regenerated { rejected_blob } => assert!(rejected_blob.exists()),
        other => panic!("expected Regenerated, got {other:?}"),
    }
    let loaded = load_signing_key(&cvm, &sealed_path, UnsealFailurePolicy::Regenerate)
        .await
        .unwrap();
    assert_eq!(loaded.source, KeySource::Unsealed);
}

#[tokio::test]
async fn strict_policy_refuses_to_start_and_keeps_the_sealed_key() {
    use tee_relay::key_lifecycle::{KeyLifecycleError, UnsealFailurePolicy, load_signing_key};

    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    std::fs::write(&sealed_path, b"garbage").unwrap();
    let cvm = SimulatedCvm::new();

    let err = load_signing_key(&cvm, &sealed_path, UnsealFailurePolicy::Fail)
        .await
        .err()
        .expect("strict policy refuses");
    assert!(matches!(err, KeyLifecycleError::SealedKeyRejected { .. }));
    assert!(err.to_string().contains("Move it aside"));
    assert_eq!(std::fs::read(&sealed_path).unwrap(), b"garbage");
}

#[test]
fn strict_policy_is_selected_only_explicitly() {
    use tee_relay::key_lifecycle::UnsealFailurePolicy;
    assert_eq!(
        UnsealFailurePolicy::from_env_value(Some("1")),
        UnsealFailurePolicy::Fail
    );
    assert_eq!(
        UnsealFailurePolicy::from_env_value(None),
        UnsealFailurePolicy::Regenerate
    );
    assert_eq!(
        UnsealFailurePolicy::from_env_value(Some("0")),
        UnsealFailurePolicy::Regenerate
    );
}

/// A CVM whose platform fails to unseal (device or firmware error).
struct FailingPlatform(SimulatedCvm);

#[async_trait::async_trait]
impl tee_core::attestation::CvmRuntime for FailingPlatform {
    fn identity(&self) -> &tee_core::EnclaveIdentity {
        self.0.identity()
    }
    async fn get_attestation(
        &self,
        user_data: &[u8; 64],
    ) -> Result<tee_core::AttestationReport, tee_core::attestation::CvmError> {
        self.0.get_attestation(user_data).await
    }
    fn derive_session_keypair(
        &self,
    ) -> Result<
        (
            x25519_dalek::PublicKey,
            zeroize::Zeroizing<x25519_dalek::StaticSecret>,
        ),
        tee_core::attestation::CvmError,
    > {
        self.0.derive_session_keypair()
    }
    async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, tee_core::attestation::CvmError> {
        self.0.seal(data).await
    }
    async fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, tee_core::attestation::CvmError> {
        Err(tee_core::attestation::CvmError::SealError(
            "device busy".into(),
        ))
    }
    fn is_real_tee(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn platform_unseal_failure_is_not_treated_as_a_bad_blob() {
    use tee_relay::key_lifecycle::{KeyLifecycleError, UnsealFailurePolicy, load_signing_key};

    let tmp = tempfile::tempdir().unwrap();
    let sealed_path = tmp.path().join("sealed_signing_key");
    let cvm = SimulatedCvm::new();
    tee_relay::key_lifecycle::load_or_generate_signing_key(&cvm, &sealed_path)
        .await
        .unwrap();
    let original = std::fs::read(&sealed_path).unwrap();

    let err = load_signing_key(
        &FailingPlatform(cvm),
        &sealed_path,
        UnsealFailurePolicy::Regenerate,
    )
    .await
    .err()
    .expect("platform failure is an error");
    assert!(matches!(err, KeyLifecycleError::Platform(_)));
    // The sealed key is untouched: no regeneration on a platform failure.
    assert_eq!(std::fs::read(&sealed_path).unwrap(), original);
}
