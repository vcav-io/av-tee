use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use tee_core::TeeType;
use tee_core::attestation::{CvmError, CvmRuntime};

/// File name of the sealed signing key for a runtime.
///
/// Each runtime has its own file, so a relay that falls back to the
/// simulated runtime (`SELKEY_ALLOW_SIMULATED=1`) never reads, moves or
/// replaces the SEV-SNP sealed key, and the reverse. The simulated runtime
/// keeps the original name.
pub fn sealed_key_file_name(tee_type: TeeType) -> String {
    match tee_type {
        TeeType::Simulated => "sealed_signing_key".to_string(),
        other => {
            let label = serde_json::to_value(other)
                .ok()
                .and_then(|v| v.as_str().map(str::to_ascii_lowercase))
                .unwrap_or_else(|| format!("{other:?}").to_ascii_lowercase());
            format!("sealed_signing_key.{label}")
        }
    }
}

/// What to do when the sealed signing key exists but this CVM rejects it
/// (`CvmError::SealedBlobRejected`: sealed by an older key policy, another
/// platform or another launch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsealFailurePolicy {
    /// Move the rejected blob aside (it is never deleted) and generate a new
    /// key. The relay starts with a new receipt signing key, so clients that
    /// pin the old key must re-pin. Default.
    Regenerate,
    /// Refuse to start (`SELKEY_SEAL_STRICT=1`). An operator must move the
    /// blob aside before the relay will start.
    Fail,
}

impl UnsealFailurePolicy {
    /// `SELKEY_SEAL_STRICT=1` (or `true`) selects [`UnsealFailurePolicy::Fail`].
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("1") | Some("true") => UnsealFailurePolicy::Fail,
            _ => UnsealFailurePolicy::Regenerate,
        }
    }
}

/// How the signing key was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// No sealed key existed; a new one was generated and sealed.
    Generated,
    /// The sealed key was unsealed.
    Unsealed,
    /// The sealed key was rejected; it was moved to `rejected_blob` and a new
    /// key was generated and sealed.
    Regenerated { rejected_blob: PathBuf },
}

/// Errors from loading the signing key. Messages never include key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyLifecycleError {
    /// The sealed key was rejected and the policy is
    /// [`UnsealFailurePolicy::Fail`].
    #[error(
        "sealed signing key at {path} cannot be unsealed by this CVM ({reason}). Move it aside to \
         generate a new key (the receipt signing key, and any client pin of it, changes), or \
         unset SELKEY_SEAL_STRICT to do this automatically"
    )]
    SealedKeyRejected { path: PathBuf, reason: String },
    /// The platform could not seal or unseal (device or firmware failure, or
    /// a platform below the sealed key's TCB floor). Not retried by
    /// regenerating.
    #[error("sealing platform error: {0}")]
    Platform(String),
    #[error("sealed key file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sealed key is not 32 bytes")]
    BadKeyLength,
}

/// A loaded signing key and where it came from.
pub struct LoadedKey {
    pub signing_key: SigningKey,
    pub source: KeySource,
}

/// Load the sealed signing key, or generate and seal one.
///
/// Equivalent to [`load_signing_key`] with [`UnsealFailurePolicy::Regenerate`].
pub async fn load_or_generate_signing_key(
    cvm: &dyn CvmRuntime,
    sealed_path: &Path,
) -> Result<SigningKey, KeyLifecycleError> {
    load_signing_key(cvm, sealed_path, UnsealFailurePolicy::Regenerate)
        .await
        .map(|loaded| loaded.signing_key)
}

/// Load the sealed signing key, or generate and seal one.
///
/// A sealed key that this CVM rejects is handled by `policy`, so a relay
/// whose sealed key can no longer be opened (for example after the sealing
/// key policy changed) does not fail on every restart. Platform failures are
/// returned as errors.
pub async fn load_signing_key(
    cvm: &dyn CvmRuntime,
    sealed_path: &Path,
    policy: UnsealFailurePolicy,
) -> Result<LoadedKey, KeyLifecycleError> {
    if !sealed_path.exists() {
        let signing_key = generate_and_seal(cvm, sealed_path).await?;
        return Ok(LoadedKey {
            signing_key,
            source: KeySource::Generated,
        });
    }

    let sealed_bytes = std::fs::read(sealed_path)?;
    match cvm.unseal(&sealed_bytes).await {
        Ok(key_bytes) => {
            let seed: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| KeyLifecycleError::BadKeyLength)?;
            Ok(LoadedKey {
                signing_key: SigningKey::from_bytes(&seed),
                source: KeySource::Unsealed,
            })
        }
        Err(CvmError::SealedBlobRejected(reason)) => match policy {
            UnsealFailurePolicy::Fail => Err(KeyLifecycleError::SealedKeyRejected {
                path: sealed_path.to_path_buf(),
                reason,
            }),
            UnsealFailurePolicy::Regenerate => {
                let rejected_blob = quarantine_path(sealed_path);
                std::fs::rename(sealed_path, &rejected_blob)?;
                let signing_key = generate_and_seal(cvm, sealed_path).await?;
                Ok(LoadedKey {
                    signing_key,
                    source: KeySource::Regenerated { rejected_blob },
                })
            }
        },
        Err(e) => Err(KeyLifecycleError::Platform(e.to_string())),
    }
}

/// `<path>.rejected-<unix seconds>`, with a counter if that name is taken.
fn quarantine_path(sealed_path: &Path) -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = sealed_path.as_os_str().to_owned();
    let mut n = 0u32;
    loop {
        let mut name = base.clone();
        if n == 0 {
            name.push(format!(".rejected-{secs}"));
        } else {
            name.push(format!(".rejected-{secs}-{n}"));
        }
        let candidate = PathBuf::from(name);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

async fn generate_and_seal(
    cvm: &dyn CvmRuntime,
    sealed_path: &Path,
) -> Result<SigningKey, KeyLifecycleError> {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let seed = zeroize::Zeroizing::new(signing_key.to_bytes());
    let sealed = cvm
        .seal(seed.as_ref())
        .await
        .map_err(|e| KeyLifecycleError::Platform(e.to_string()))?;
    if let Some(parent) = sealed_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Write with 0600 permissions (owner-only) and O_CREAT|O_EXCL to
    // prevent TOCTOU race with concurrent relay starts.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(sealed_path)?;
        f.write_all(&sealed)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(sealed_path, &sealed)?;
    }
    Ok(signing_key)
}
