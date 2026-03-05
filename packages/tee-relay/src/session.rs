use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use tee_core::types::ParticipantRole;

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Created,
    Partial,
    Processing,
    Completed,
    Aborted,
}

/// Per-session state tracking encrypted inputs and ECDH keys.
pub struct Session {
    pub session_id_bytes: [u8; 16],
    pub contract_hash_bytes: Vec<u8>,
    pub contract_hash_hex: String,
    pub contract: Option<vault_family_types::Contract>,
    pub tee_session_secret: Option<Zeroizing<StaticSecret>>,
    pub tee_session_pubkey: PublicKey,
    pub initiator_input: Option<Zeroizing<Vec<u8>>>,
    pub responder_input: Option<Zeroizing<Vec<u8>>>,
    pub initiator_ciphertext_hash: Option<String>,
    pub responder_ciphertext_hash: Option<String>,
    pub state: SessionState,
    pub output: Option<serde_json::Value>,
    pub receipt_v2: Option<receipt_core::ReceiptV2>,
    pub abort_signal: Option<String>,
    pub created_at: std::time::Instant,
    /// Tracks which roles have submitted (for duplicate detection).
    submitted: [bool; 2],
}

impl Session {
    pub fn new(
        session_id_bytes: [u8; 16],
        contract_hash_bytes: Vec<u8>,
        contract_hash_hex: String,
        contract: vault_family_types::Contract,
        tee_session_secret: Zeroizing<StaticSecret>,
        tee_session_pubkey: PublicKey,
    ) -> Self {
        Self {
            session_id_bytes,
            contract_hash_bytes,
            contract_hash_hex,
            contract: Some(contract),
            tee_session_secret: Some(tee_session_secret),
            tee_session_pubkey,
            initiator_input: None,
            responder_input: None,
            initiator_ciphertext_hash: None,
            responder_ciphertext_hash: None,
            state: SessionState::Created,
            output: None,
            receipt_v2: None,
            abort_signal: None,
            created_at: std::time::Instant::now(),
            submitted: [false; 2],
        }
    }

    /// Returns true if this role has already submitted.
    pub fn has_submitted(&self, role: ParticipantRole) -> bool {
        match role {
            ParticipantRole::Initiator => self.submitted[0],
            ParticipantRole::Responder => self.submitted[1],
        }
    }

    /// Mark a role as having submitted.
    pub fn mark_submitted(&mut self, role: ParticipantRole) {
        match role {
            ParticipantRole::Initiator => self.submitted[0] = true,
            ParticipantRole::Responder => self.submitted[1] = true,
        }
    }

    /// Returns true when both inputs have been decrypted.
    pub fn both_inputs_received(&self) -> bool {
        self.initiator_input.is_some() && self.responder_input.is_some()
    }

    /// Zeroize the session secret key (forward secrecy).
    pub fn zeroize_session_key(&mut self) {
        self.tee_session_secret = None;
    }

    /// Clear decrypted inputs from memory after inference.
    pub fn clear_inputs(&mut self) {
        self.initiator_input = None;
        self.responder_input = None;
    }
}

/// Thread-safe in-memory session store with TTL support.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    ttl: Duration,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(600))
    }
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn insert(&self, id: String, session: Session) {
        self.sessions.lock().unwrap().insert(id, session);
    }

    pub fn with_session<F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut Session) -> R,
    {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.get_mut(id).map(f)
    }

    pub fn remove(&self, id: &str) -> Option<Session> {
        self.sessions.lock().unwrap().remove(id)
    }

    /// Reap expired sessions. Returns number removed.
    pub fn reap_expired(&self) -> usize {
        let now = std::time::Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|_, session| {
            // Don't reap sessions with inference in flight
            session.state == SessionState::Processing
                || now.duration_since(session.created_at) < self.ttl
        });
        before - sessions.len()
    }
}

/// Start a reaper task for an Arc<SessionStore>.
pub fn start_session_reaper(store: std::sync::Arc<SessionStore>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let reaped = store.reap_expired();
            if reaped > 0 {
                tracing::info!(reaped, "session reaper: expired sessions removed");
            }
        }
    })
}
