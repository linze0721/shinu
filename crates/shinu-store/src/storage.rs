//! Host capacity watermarks, explicit Space write protection, and usage samples.
use shinu_core::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

/// Daemon-wide storage policy, validated once before accepting requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoragePolicy {
    pub watermarks: Watermarks,
}

impl StoragePolicy {
    pub fn from_env() -> Result<Self> {
        let read = |key| match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(Error::Invalid(format!("{key}: {error}"))),
        };
        let read_mib = |key: &'static str, default| -> Result<u64> {
            read(key)?.map_or(Ok(default), |value| {
                value
                    .parse::<u64>()
                    .map_err(|_| Error::Invalid(format!("{key} must be unsigned decimal MiB")))
            })
        };
        Ok(Self {
            watermarks: Watermarks {
                min_store_free_mib: read_mib("SHINU_MIN_STORE_FREE_MIB", 1024)?,
                min_mem_available_mib: read_mib("SHINU_MIN_MEM_AVAILABLE_MIB", 512)?,
            },
        })
    }

    pub fn write_cap(self, explicit: Option<u64>) -> Result<u64> {
        let cap = explicit.unwrap_or(0);
        if i64::try_from(cap).is_err() {
            return Err(Error::Invalid(
                "write_cap_mib exceeds signed 64-bit MiB".into(),
            ));
        }
        Ok(cap)
    }
}

/// Sampled exclusive bytes; requests never walk every retained file's extents.
#[derive(Default)]
pub struct StorageAccounting {
    pub policy: StoragePolicy,
    samples: Mutex<HashMap<uuid::Uuid, u64>>,
}

impl StorageAccounting {
    pub fn exclusive(&self, id: uuid::Uuid) -> Option<u64> {
        self.samples
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&id)
            .copied()
    }

    pub fn record(&self, id: uuid::Uuid, bytes: u64) {
        self.samples
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(id, bytes);
    }

    pub fn retain(&self, state: &crate::state::State) {
        let live: std::collections::HashSet<_> = state
            .spaces
            .iter()
            .map(|space| space.id)
            .chain(state.ckpts.iter().map(|checkpoint| checkpoint.id))
            .collect();
        self.samples
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|id, _| live.contains(id));
    }
}

/// Host-wide admission floors, not project allocations or reservations.
#[derive(Debug, Clone, Copy, Default)]
pub struct Watermarks {
    pub min_store_free_mib: u64,
    pub min_mem_available_mib: u64,
}

impl Watermarks {
    pub fn check(self, store_free_mib: u64, mem_available_mib: u64) -> Result<()> {
        if store_free_mib < self.min_store_free_mib
            || mem_available_mib < self.min_mem_available_mib
        {
            return Err(Error::CapacityWatermark(format!(
                "store_free_mib={store_free_mib} (minimum {}), mem_available_mib={mem_available_mib} (minimum {})",
                self.min_store_free_mib, self.min_mem_available_mib
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod storage_tests {
    use super::{Error, StoragePolicy, Watermarks};

    #[test]
    fn capacity_watermarks_allow_exact_floors_and_reject_either_shortfall() {
        let floors = Watermarks {
            min_store_free_mib: 1024,
            min_mem_available_mib: 512,
        };
        assert!(floors.check(1024, 512).is_ok());
        assert!(matches!(
            floors.check(1023, 512),
            Err(Error::CapacityWatermark(_))
        ));
        assert!(matches!(
            floors.check(1024, 511),
            Err(Error::CapacityWatermark(_))
        ));
    }

    #[test]
    fn only_explicit_write_caps_are_enabled() {
        let policy = StoragePolicy::default();
        assert_eq!(policy.write_cap(None).unwrap(), 0);
        assert_eq!(policy.write_cap(Some(0)).unwrap(), 0);
        assert_eq!(policy.write_cap(Some(42)).unwrap(), 42);
        assert!(policy.write_cap(Some(u64::MAX)).is_err());
    }
}
