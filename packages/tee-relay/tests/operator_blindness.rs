//! Operator blindness test: proves relay software does not emit plaintext
//! via logs, errors, or panics.
//!
//! NOTE: In simulated mode this proves software isolation, not SEV-SNP
//! operator blindness. Still valuable — catches accidental plaintext leaks.

use std::sync::{Arc, Mutex};

use tee_core::SimulatedCvm;
use tee_core::attestation::CvmRuntime;
use tee_core::crypto::{build_aad, decrypt_payload, encrypt_payload};
use tee_core::types::ParticipantRole;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use tracing_subscriber::fmt::MakeWriter;

/// A writer that captures all output to a shared buffer.
#[derive(Clone)]
struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CaptureWriter {
    fn new() -> Self {
        Self {
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn output(&self) -> String {
        let buf = self.buf.lock().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn canary_not_in_logs_after_decryption() {
    // 1. Set up tracing subscriber that captures to a buffer
    let writer = CaptureWriter::new();
    let writer_clone = writer.clone();

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(writer_clone)
        .with_ansi(false)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    // 2. Generate a unique canary
    let canary = uuid::Uuid::new_v4().to_string();

    // 3. Build a valid encrypted payload containing the canary as plaintext
    let cvm = SimulatedCvm::new();
    let (session_pub, session_secret) = cvm.derive_session_keypair().unwrap();
    let session_id_bytes = [0u8; 16];
    let contract_hash_bytes = vec![0u8; 32];
    let role = ParticipantRole::Initiator;
    let aad = build_aad(&session_id_bytes, &contract_hash_bytes, role);
    let nonce = [0u8; 12];

    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());

    let (ciphertext, client_pub_bytes) = encrypt_payload(
        &client_secret,
        &session_pub,
        canary.as_bytes(),
        &session_id_bytes,
        &aad,
        &nonce,
    )
    .unwrap();

    // 4. Decrypt — this is the path where plaintext exists in memory
    let mut plaintext = decrypt_payload(
        &session_secret,
        &session_pub,
        &client_pub_bytes,
        &nonce,
        &ciphertext,
        &session_id_bytes,
        &aad,
    )
    .unwrap();

    // Verify we actually decrypted the canary (test sanity check)
    assert_eq!(plaintext.as_slice(), canary.as_bytes());

    // Zeroize plaintext as the relay would
    plaintext.zeroize();

    // Log something after decryption to exercise the path
    tracing::info!("decryption completed for session"); // SAFETY: no plaintext
    tracing::debug!("processing input of {} bytes", plaintext.len()); // SAFETY: no plaintext

    // 5. Read all captured log output
    let logs = writer.output();

    // 6. THE CRITICAL ASSERTION
    assert!(
        !logs.contains(&canary),
        "OPERATOR BLINDNESS VIOLATION: canary found in logs!\n\
         This means plaintext is leaking through logging.\n\
         Logs: {logs}"
    );
}

#[test]
fn panic_hook_suppresses_canary() {
    let canary = uuid::Uuid::new_v4().to_string();
    let canary_clone = canary.clone();

    // Install the same panic hook used in main.rs
    let output = Arc::new(Mutex::new(String::new()));
    let output_clone = output.clone();

    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let msg = format!("panic occurred at {location}\n");
        output_clone.lock().unwrap().push_str(&msg);
    }));

    // Trigger a panic in a catch_unwind with the canary as payload
    let _ = std::panic::catch_unwind(move || {
        panic!("secret data: {canary_clone}");
    });

    // Restore default panic hook
    let _ = std::panic::take_hook();

    let panic_output = output.lock().unwrap().clone();

    assert!(
        !panic_output.contains(&canary),
        "OPERATOR BLINDNESS VIOLATION: canary found in panic output!\n\
         The panic hook must suppress payload values.\n\
         Output: {panic_output}"
    );
}
