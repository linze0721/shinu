//! Coordination locks for concurrent operations on spaces, checkpoints, jobs,
//! and the state file.
//!
//! Long-running operations acquire the space lock first, then an optional job
//! or target checkpoint lock when one is involved, then the state lock and
//! database; garbage collection and checkpoint removal start with one
//! checkpoint lock. Job-only monitor paths use job, state, database. This fixed
//! order prevents deadlocks between connections. The state lock is held only
//! across `State::load`, the in-memory change, and `State::store`, never across
//! a btrfs or VM operation. Poisoning is recovered with `into_inner`: these
//! locks serialize state-file access rather than guard an in-memory invariant,
//! so continuing after a panicking connection is safe. Entries whose only owner
//! is the registry are swept when another resource lock is acquired, so
//! abandoned ids do not remain in the maps.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub struct Registry {
    state: Mutex<()>,
    spaces: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    checkpoints: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    jobs: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(()),
            spaces: Mutex::new(HashMap::new()),
            checkpoints: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
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

    /// Serializes operations that read or remove one checkpoint's files.
    ///
    /// Entries with no external `Arc` owner are evicted on the next acquire,
    /// matching [`Self::space_lock`] so the registry does not grow with every
    /// short-lived checkpoint id.
    pub fn checkpoint_lock(&self, id: Uuid) -> Arc<Mutex<()>> {
        let mut checkpoints = self
            .checkpoints
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        checkpoints.retain(|_, lock| Arc::strong_count(lock) > 1);
        checkpoints
            .entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
    /// Serializes operations that monitor, cancel, or reconcile one job.
    ///
    /// Job-only paths acquire this lock before the state and database locks;
    /// space lifecycle paths query active rows directly and never acquire it.
    pub fn job_lock(&self, id: Uuid) -> Arc<Mutex<()>> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        jobs.retain(|_, lock| Arc::strong_count(lock) > 1);
        jobs.entry(id)
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

    #[cfg(test)]
    fn checkpoint_lock_count(&self) -> usize {
        self.checkpoints
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    #[cfg(test)]
    fn job_lock_count(&self) -> usize {
        self.jobs
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
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;

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

    #[test]
    fn released_checkpoint_locks_are_evicted_on_next_acquire() {
        let registry = Registry::new();

        for _ in 0..1_000 {
            let checkpoint_lock = registry.checkpoint_lock(Uuid::new_v4());
            let _checkpoint_guard = checkpoint_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        let count = registry.checkpoint_lock_count();
        assert!(count <= 1, "checkpoint lock map grew to {count} entries");
    }

    #[test]
    fn checkpoint_lock_blocks_same_id_until_consumer_finishes() {
        let registry = Arc::new(Registry::new());
        let id = Uuid::new_v4();
        let checkpoint_lock = registry.checkpoint_lock(id);
        let checkpoint_guard = checkpoint_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempted = Arc::new(Barrier::new(2));
        let entered = Arc::new(Barrier::new(2));
        let acquired = Arc::new(AtomicBool::new(false));
        let worker_lock = Arc::clone(&checkpoint_lock);
        let worker_attempted = Arc::clone(&attempted);
        let worker_entered = Arc::clone(&entered);
        let worker_acquired = Arc::clone(&acquired);
        let worker = thread::spawn(move || {
            worker_attempted.wait();
            let _guard = worker_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            worker_acquired.store(true, Ordering::Release);
            worker_entered.wait();
        });
        attempted.wait();
        assert!(!acquired.load(Ordering::Acquire));
        drop(checkpoint_guard);
        entered.wait();
        worker.join().expect("checkpoint consumer thread");
    }

    #[test]
    fn released_job_locks_are_evicted_on_next_acquire() {
        let registry = Registry::new();

        for _ in 0..1_000 {
            let job_lock = registry.job_lock(Uuid::new_v4());
            let _job_guard = job_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        let count = registry.job_lock_count();
        assert!(count <= 1, "job lock map grew to {count} entries");
    }

    #[test]
    fn job_lock_blocks_same_id_until_consumer_finishes() {
        let registry = Arc::new(Registry::new());
        let id = Uuid::new_v4();
        let job_lock = registry.job_lock(id);
        let job_guard = job_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempted = Arc::new(Barrier::new(2));
        let entered = Arc::new(Barrier::new(2));
        let acquired = Arc::new(AtomicBool::new(false));
        let worker_lock = Arc::clone(&job_lock);
        let worker_attempted = Arc::clone(&attempted);
        let worker_entered = Arc::clone(&entered);
        let worker_acquired = Arc::clone(&acquired);
        let worker = thread::spawn(move || {
            worker_attempted.wait();
            let _guard = worker_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            worker_acquired.store(true, Ordering::Release);
            worker_entered.wait();
        });
        attempted.wait();
        assert!(!acquired.load(Ordering::Acquire));
        drop(job_guard);
        entered.wait();
        worker.join().expect("job consumer thread");
    }
}
