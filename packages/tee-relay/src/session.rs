use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use tee_core::types::ParticipantRole;

/// Error returned when the session store mutex has been poisoned.
#[derive(Debug)]
pub struct SessionStorePoisoned;

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

    /// Lock the session map, returning an error if the mutex is poisoned.
    fn lock_sessions(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Session>>, SessionStorePoisoned> {
        self.sessions.lock().map_err(|_| {
            tracing::error!("session store mutex was poisoned, refusing to continue"); // SAFETY: no plaintext
            SessionStorePoisoned
        })
    }

    pub fn insert(&self, id: String, session: Session) -> Result<(), SessionStorePoisoned> {
        self.lock_sessions()?.insert(id, session);
        Ok(())
    }

    pub fn with_session<F, R>(&self, id: &str, f: F) -> Result<Option<R>, SessionStorePoisoned>
    where
        F: FnOnce(&mut Session) -> R,
    {
        let mut sessions = self.lock_sessions()?;
        Ok(sessions.get_mut(id).map(f))
    }

    pub fn remove(&self, id: &str) -> Result<Option<Session>, SessionStorePoisoned> {
        Ok(self.lock_sessions()?.remove(id))
    }

    /// Reap expired sessions. Returns number removed.
    pub fn reap_expired(&self) -> Result<usize, SessionStorePoisoned> {
        let now = std::time::Instant::now();
        let mut sessions = self.lock_sessions()?;
        let before = sessions.len();
        // Hard cap for Processing sessions (5 minutes) to prevent leaked sessions
        let processing_max = Duration::from_secs(300);
        sessions.retain(|_, session| {
            let age = now.duration_since(session.created_at);
            match session.state {
                SessionState::Processing => age < processing_max,
                _ => age < self.ttl,
            }
        });
        Ok(before - sessions.len())
    }
}

/// Start a reaper task for an `Arc<SessionStore>`.
///
/// If the session store mutex is poisoned, the reaper logs an error and
/// exits the process. A service with a poisoned session store cannot safely
/// process sessions — better to restart cleanly.
pub fn start_session_reaper(store: std::sync::Arc<SessionStore>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match store.reap_expired() {
                Ok(reaped) => {
                    if reaped > 0 {
                        tracing::info!(reaped, "session reaper: expired sessions removed"); // SAFETY: no plaintext
                    }
                }
                Err(_) => {
                    tracing::error!("session reaper: session store poisoned, shutting down"); // SAFETY: no plaintext
                    std::process::exit(1);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn poisoned_mutex_returns_error() {
        let store = Arc::new(SessionStore::default());

        // Poison the mutex by panicking while holding the lock
        let store_clone = store.clone();
        let handle = std::thread::spawn(move || {
            let _guard = store_clone.sessions.lock().unwrap();
            panic!("intentional panic to poison mutex");
        });
        let _ = handle.join(); // join the panicked thread

        // Now the mutex is poisoned — with_session should return Err
        let result = store.with_session("any-id", |_| ());
        assert!(
            result.is_err(),
            "with_session should return Err on poisoned mutex"
        );

        let result = store.insert("id".to_string(), make_dummy_session());
        assert!(
            result.is_err(),
            "insert should return Err on poisoned mutex"
        );

        let result = store.remove("id");
        assert!(
            result.is_err(),
            "remove should return Err on poisoned mutex"
        );

        let result = store.reap_expired();
        assert!(
            result.is_err(),
            "reap_expired should return Err on poisoned mutex"
        );
    }

    fn make_dummy_session() -> Session {
        use x25519_dalek::StaticSecret;
        use zeroize::Zeroizing;

        let secret = Zeroizing::new(StaticSecret::random_from_rng(rand::thread_rng()));
        let pubkey = x25519_dalek::PublicKey::from(&*secret);
        Session::new(
            [0u8; 16],
            vec![0u8; 32],
            "0".repeat(64),
            vault_family_types::Contract {
                purpose_code: vault_family_types::Purpose::Mediation,
                output_schema_id: "test".to_string(),
                output_schema: serde_json::json!({}),
                participants: vec![],
                prompt_template_hash: "a".repeat(64),
                entropy_budget_bits: None,
                timing_class: None,
                metadata: serde_json::Value::Null,
                model_profile_id: None,
                enforcement_policy_hash: None,
                output_schema_hash: None,
                model_constraints: None,
                max_completion_tokens: None,
                session_ttl_secs: None,
                invite_ttl_secs: None,
                entropy_enforcement: None,
                relay_verifying_key_hex: None,
            },
            secret,
            pubkey,
        )
    }
}
