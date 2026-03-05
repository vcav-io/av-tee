use std::path::Path;

use ed25519_dalek::SigningKey;
use tee_core::attestation::CvmRuntime;

pub async fn load_or_generate_signing_key(
    cvm: &dyn CvmRuntime,
    sealed_path: &Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if sealed_path.exists() {
        let sealed_bytes = std::fs::read(sealed_path)?;
        let key_bytes = cvm
            .unseal(&sealed_bytes)
            .await
            .map_err(|e| format!("failed to unseal signing key: {e}"))?;
        let seed: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "sealed key is not 32 bytes")?;
        Ok(SigningKey::from_bytes(&seed))
    } else {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let seed = signing_key.to_bytes();
        let sealed = cvm
            .seal(&seed)
            .await
            .map_err(|e| format!("failed to seal signing key: {e}"))?;
        if let Some(parent) = sealed_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(sealed_path, sealed)?;
        Ok(signing_key)
    }
}
