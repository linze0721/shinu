//! Coordination locks for concurrent operations on spaces and the state file.
//!
//! Long-running operations acquire the space lock first and the state lock
//! second; this fixed order prevents deadlocks between connections. The state
//! lock is held only across `State::load`, the in-memory change, and
//! `State::store`, never across a btrfs or VM operation. Poisoning is recovered
//! with `into_inner`: these locks serialize state-file access rather than guard
//! an in-memory invariant, so continuing after a panicking connection is safe.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub struct Registry {
    state: Mutex<()>,
    spaces: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(()),
            spaces: Mutex::new(HashMap::new()),
        }
    }

    pub fn space_lock(&self, id: Uuid) -> Arc<Mutex<()>> {
        let mut spaces = self.spaces.lock().unwrap_or_else(|error| error.into_inner());
        spaces
            .entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn state_lock(&self) -> &Mutex<()> {
        &self.state
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
