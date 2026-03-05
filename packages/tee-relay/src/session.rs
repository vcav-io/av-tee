use std::collections::HashMap;
use std::sync::Mutex;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use tee_core::types::ParticipantRole;

/// Per-session state tracking encrypted inputs and ECDH keys.
pub struct Session {
    pub session_id_bytes: [u8; 16],
    pub contract_hash_bytes: Vec<u8>,
    pub tee_session_secret: Option<Zeroizing<StaticSecret>>,
    pub tee_session_pubkey: PublicKey,
    pub initiator_input: Option<Zeroizing<Vec<u8>>>,
    pub responder_input: Option<Zeroizing<Vec<u8>>>,
    pub initiator_ciphertext_hash: Option<String>,
    pub responder_ciphertext_hash: Option<String>,
    /// Tracks which roles have submitted (for duplicate detection).
    submitted: [bool; 2],
}

impl Session {
    pub fn new(
        session_id_bytes: [u8; 16],
        contract_hash_bytes: Vec<u8>,
        tee_session_secret: Zeroizing<StaticSecret>,
        tee_session_pubkey: PublicKey,
    ) -> Self {
        Self {
            session_id_bytes,
            contract_hash_bytes,
            tee_session_secret: Some(tee_session_secret),
            tee_session_pubkey,
            initiator_input: None,
            responder_input: None,
            initiator_ciphertext_hash: None,
            responder_ciphertext_hash: None,
            submitted: [false; 2],
        }
    }

    /// Returns true if this role has already submitted. Used for duplicate detection.
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
}

/// Thread-safe in-memory session store.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
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
}
