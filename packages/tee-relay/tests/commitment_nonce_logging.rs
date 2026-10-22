//! The commitment nonce never reaches the relay's logs, on success, on
//! failure or when a submission is rejected.

mod support;

use std::sync::{Arc, Mutex};

use tee_core::types::ParticipantRole;
use tracing_subscriber::fmt::MakeWriter;

use support::*;

#[derive(Clone, Default)]
struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CaptureWriter {
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().unwrap()).to_string()
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

#[tokio::test]
async fn commitment_nonce_is_not_logged() {
    let writer = CaptureWriter::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(writer.clone())
            .with_ansi(false)
            .finish(),
    )
    .unwrap();

    let client = reqwest::Client::new();

    // Successful session.
    let base = start_relay_server(&start_mock_provider(r#"{"decision":"PROCEED"}"#).await).await;
    let session = create_session(&client, &base, contract_json()).await;
    run_session(
        &client,
        &base,
        &session,
        &serde_json::json!({"k": 1}),
        &serde_json::json!({"k": 2}),
    )
    .await;

    // Failed session (provider error, failure receipt).
    let base = start_relay_server(&start_failing_mock_provider().await).await;
    let session = create_session(&client, &base, contract_json()).await;
    run_session(
        &client,
        &base,
        &session,
        &serde_json::json!({"k": 3}),
        &serde_json::json!({"k": 4}),
    )
    .await;

    // Rejected submission (uppercase nonce).
    let malformed = ALICE_NONCE.to_uppercase();
    let session = create_session(&client, &base, contract_json()).await;
    let (status, _) = submit_input(
        &client,
        &base,
        &session,
        ParticipantRole::Initiator,
        "alice",
        &serde_json::json!({}),
        &malformed,
    )
    .await;
    assert_eq!(status, 422);

    let logs = writer.output();
    for needle in [ALICE_NONCE, BOB_NONCE, malformed.as_str()] {
        assert!(!logs.contains(needle), "nonce found in logs");
    }
}
