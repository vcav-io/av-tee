use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::types::ParticipantRole;

/// Errors from the crypto module.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ECDH key exchange failed")]
    KeyExchange,
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("AES-GCM decryption failed")]
    Decryption,
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid nonce length: expected 12 bytes, got {0}")]
    InvalidNonce(usize),
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPubkey(usize),
    #[error("AAD mismatch")]
    AadMismatch,
}

const AAD_PREFIX: &[u8] = b"av-tee:aad:v1:";
const HKDF_INFO_PREFIX: &[u8] = b"av-tee-session-v1:";

/// Build the AAD bytes for a given session, contract, and role.
///
/// Format: `b"av-tee:aad:v1:" || session_id_bytes || contract_hash_bytes || b":initiator"|b":responder"`
pub fn build_aad(
    session_id_bytes: &[u8; 16],
    contract_hash_bytes: &[u8],
    role: ParticipantRole,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 16 + contract_hash_bytes.len() + 10);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(session_id_bytes);
    aad.extend_from_slice(contract_hash_bytes);
    aad.extend_from_slice(role.as_bytes());
    aad
}

/// Derive the AES-256-GCM key from ECDH shared secret.
///
/// - `salt` = session_id as raw 16 bytes (UUID bytes, not UTF-8)
/// - `info` = `b"av-tee-session-v1:" || client_pub[32] || tee_pub[32]`
///
/// Both keys are fixed 32 bytes (X25519), so concatenation is unambiguous.
/// If key types ever change, this must be length-prefixed.
fn derive_symmetric_key(
    shared_secret: &[u8; 32],
    session_id_bytes: &[u8; 16],
    client_pub: &[u8; 32],
    tee_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(session_id_bytes), shared_secret);
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 64);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(client_pub);
    info.extend_from_slice(tee_pub);

    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(key)
}

/// Decrypt an encrypted payload using the TEE's session secret key.
///
/// Returns the decrypted plaintext wrapped in `Zeroizing` so it is
/// automatically zeroed when dropped.
pub fn decrypt_payload(
    tee_secret: &Zeroizing<StaticSecret>,
    tee_pub: &PublicKey,
    payload_client_pubkey: &[u8; 32],
    payload_nonce: &[u8; 12],
    payload_ciphertext: &[u8],
    session_id_bytes: &[u8; 16],
    expected_aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let client_pub = PublicKey::from(*payload_client_pubkey);
    let shared_secret = tee_secret.diffie_hellman(&client_pub);

    let key = derive_symmetric_key(
        shared_secret.as_bytes(),
        session_id_bytes,
        payload_client_pubkey,
        tee_pub.as_bytes(),
    )?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Decryption)?;
    let nonce = Nonce::from_slice(payload_nonce);

    let aead_payload = aes_gcm::aead::Payload {
        msg: payload_ciphertext,
        aad: expected_aad,
    };

    let plaintext = cipher
        .decrypt(nonce, aead_payload)
        .map_err(|_| CryptoError::Decryption)?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt a payload (client-side helper, primarily for testing).
pub fn encrypt_payload(
    client_secret: &StaticSecret,
    tee_pub: &PublicKey,
    plaintext: &[u8],
    session_id_bytes: &[u8; 16],
    aad: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
    let client_pub = PublicKey::from(client_secret);
    let shared_secret = client_secret.diffie_hellman(tee_pub);

    let key = derive_symmetric_key(
        shared_secret.as_bytes(),
        session_id_bytes,
        client_pub.as_bytes(),
        tee_pub.as_bytes(),
    )?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Decryption)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let aead_payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, aead_payload)
        .map_err(|_| CryptoError::Decryption)?;

    Ok((ciphertext, *client_pub.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn test_session_id() -> [u8; 16] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    }

    fn test_contract_hash() -> Vec<u8> {
        vec![0xAA; 32]
    }

    #[test]
    fn ecdh_roundtrip_encrypt_decrypt() {
        let tee_secret = Zeroizing::new(StaticSecret::random_from_rng(&mut rand::thread_rng()));
        let tee_pub = PublicKey::from(&*tee_secret);

        let client_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());

        let session_id = test_session_id();
        let aad = build_aad(
            &session_id,
            &test_contract_hash(),
            ParticipantRole::Initiator,
        );
        let nonce = [0u8; 12]; // deterministic for test
        let plaintext = b"hello confidential world";

        let (ciphertext, client_pub_bytes) = encrypt_payload(
            &client_secret,
            &tee_pub,
            plaintext,
            &session_id,
            &aad,
            &nonce,
        )
        .unwrap();

        let decrypted = decrypt_payload(
            &tee_secret,
            &tee_pub,
            &client_pub_bytes,
            &nonce,
            &ciphertext,
            &session_id,
            &aad,
        )
        .unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn aad_mismatch_wrong_session_id() {
        let tee_secret = Zeroizing::new(StaticSecret::random_from_rng(&mut rand::thread_rng()));
        let tee_pub = PublicKey::from(&*tee_secret);
        let client_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());

        let session_id = test_session_id();
        let aad = build_aad(
            &session_id,
            &test_contract_hash(),
            ParticipantRole::Initiator,
        );
        let nonce = [0u8; 12];

        let (ciphertext, client_pub_bytes) = encrypt_payload(
            &client_secret,
            &tee_pub,
            b"secret",
            &session_id,
            &aad,
            &nonce,
        )
        .unwrap();

        // Use wrong session_id in AAD
        let wrong_session = [99u8; 16];
        let wrong_aad = build_aad(
            &wrong_session,
            &test_contract_hash(),
            ParticipantRole::Initiator,
        );

        let result = decrypt_payload(
            &tee_secret,
            &tee_pub,
            &client_pub_bytes,
            &nonce,
            &ciphertext,
            &session_id,
            &wrong_aad,
        );
        assert!(result.is_err());
    }

    #[test]
    fn aad_mismatch_wrong_contract_hash() {
        let tee_secret = Zeroizing::new(StaticSecret::random_from_rng(&mut rand::thread_rng()));
        let tee_pub = PublicKey::from(&*tee_secret);
        let client_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());

        let session_id = test_session_id();
        let aad = build_aad(
            &session_id,
            &test_contract_hash(),
            ParticipantRole::Initiator,
        );
        let nonce = [0u8; 12];

        let (ciphertext, client_pub_bytes) = encrypt_payload(
            &client_secret,
            &tee_pub,
            b"secret",
            &session_id,
            &aad,
            &nonce,
        )
        .unwrap();

        // Use wrong contract hash
        let wrong_aad = build_aad(&session_id, &[0xBB; 32], ParticipantRole::Initiator);

        let result = decrypt_payload(
            &tee_secret,
            &tee_pub,
            &client_pub_bytes,
            &nonce,
            &ciphertext,
            &session_id,
            &wrong_aad,
        );
        assert!(result.is_err());
    }

    #[test]
    fn aad_mismatch_wrong_role() {
        let tee_secret = Zeroizing::new(StaticSecret::random_from_rng(&mut rand::thread_rng()));
        let tee_pub = PublicKey::from(&*tee_secret);
        let client_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());

        let session_id = test_session_id();
        let initiator_aad = build_aad(
            &session_id,
            &test_contract_hash(),
            ParticipantRole::Initiator,
        );
        let nonce = [0u8; 12];

        let (ciphertext, client_pub_bytes) = encrypt_payload(
            &client_secret,
            &tee_pub,
            b"secret",
            &session_id,
            &initiator_aad,
            &nonce,
        )
        .unwrap();

        // Try decrypting with responder AAD — should fail (role swap attack)
        let responder_aad = build_aad(
            &session_id,
            &test_contract_hash(),
            ParticipantRole::Responder,
        );

        let result = decrypt_payload(
            &tee_secret,
            &tee_pub,
            &client_pub_bytes,
            &nonce,
            &ciphertext,
            &session_id,
            &responder_aad,
        );
        assert!(result.is_err());
    }

    #[test]
    fn aad_construction_includes_role_tag() {
        let session_id = test_session_id();
        let contract = test_contract_hash();
        let init_aad = build_aad(&session_id, &contract, ParticipantRole::Initiator);
        let resp_aad = build_aad(&session_id, &contract, ParticipantRole::Responder);

        assert_ne!(init_aad, resp_aad);
        assert!(init_aad.ends_with(b":initiator"));
        assert!(resp_aad.ends_with(b":responder"));
    }
}
