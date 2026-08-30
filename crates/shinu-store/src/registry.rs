//! Coordination locks for concurrent operations on spaces and the state file.
//!
//! Long-running operations acquire the space lock first and the state lock
//! second; this fixed order prevents deadlocks between connections. The state
//! lock is held only across `State::load`, the in-memory change, and
//! `State::store`, never across a btrfs or VM operation. Poisoning is recovered
//! with `into_inner`: these locks serialize state-file access rather than guard
//! an in-memory invariant, so continuing after a panicking connection is safe.
//! Entries whose only owner is the registry are swept when another space lock
//! is acquired, so abandoned ids do not remain in the map forever.
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
        let mut spaces = self
            .spaces
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        spaces.retain(|_, lock| Arc::strong_count(lock) > 1);
        spaces
            .entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn state_lock(&self) -> &Mutex<()> {
        &self.state
    }

    #[cfg(test)]
    fn space_lock_count(&self) -> usize {
        self.spaces
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_space_locks_are_evicted_on_next_acquire() {
        let registry = Registry::new();

        for _ in 0..1_000 {
            let space_lock = registry.space_lock(Uuid::new_v4());
            let _space_guard = space_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        let count = registry.space_lock_count();
        assert!(count <= 1, "space lock map grew to {count} entries");
    }
}
