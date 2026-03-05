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
