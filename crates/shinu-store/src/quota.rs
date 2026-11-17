//! Per-project resource ceilings and request throttling.
use shinu_core::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_API_PER_MIN: u32 = 0;
const DEFAULT_MAX_VCPUS: u32 = 0;
const DEFAULT_MAX_MEM_MIB: u32 = 0;
const WINDOW: Duration = Duration::from_mins(1);

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

/// Optional request limits. Zero, including an unset environment setting, is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_spaces: u32,
    pub max_disk_mib: u64,
    pub max_vcpus: u32,
    pub max_mem_mib: u32,
    pub max_running: u32,
    pub api_per_min: u32,
}

impl Limits {
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        Self {
            max_spaces: 0,
            max_disk_mib: 0,
            max_vcpus: positive_u32(&lookup, "SHINU_LIMIT_VCPUS", DEFAULT_MAX_VCPUS),
            max_mem_mib: positive_u32(&lookup, "SHINU_LIMIT_MEM_MIB", DEFAULT_MAX_MEM_MIB),
            max_running: 0,
            api_per_min: positive_u32(&lookup, "SHINU_LIMIT_API_PER_MIN", DEFAULT_API_PER_MIN),
        }
    }
}

fn positive_u32<F>(lookup: &F, key: &str, default: u32) -> u32
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

pub struct RateLimiter {
    requests: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, project: &str, per_min: u32) -> Result<()> {
        self.check_at(project, per_min, Instant::now())
    }

    fn check_at(&self, project: &str, per_min: u32, now: Instant) -> Result<()> {
        if per_min == 0 {
            return Ok(());
        }

        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Sweep all queues so inactive projects do not retain stale entries.
        for timestamps in requests.values_mut() {
            while timestamps.front().is_some_and(|at| {
                now.checked_duration_since(*at)
                    .is_some_and(|elapsed| elapsed >= WINDOW)
            }) {
                timestamps.pop_front();
            }
        }
        requests.retain(|_, timestamps| !timestamps.is_empty());

        let timestamps = requests.entry(project.to_owned()).or_default();
        if timestamps.len() >= per_min as usize {
            return Err(Error::Quota(format!(
                "rate limit exceeded: {per_min} requests per minute"
            )));
        }

        timestamps.push_back(now);
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn check_vcpu_limit(requested: u32, limits: &Limits) -> Result<()> {
    if limits.max_vcpus != 0 && requested > limits.max_vcpus {
        return Err(Error::Quota(format!(
            "vcpus limit exceeded (requested {requested}, cap {})",
            limits.max_vcpus
        )));
    }
    Ok(())
}

pub fn check_mem_limit(requested: u32, limits: &Limits) -> Result<()> {
    if limits.max_mem_mib != 0 && requested > limits.max_mem_mib {
        return Err(Error::Quota(format!(
            "memory limit exceeded (requested {requested} MiB, cap {} MiB)",
            limits.max_mem_mib
        )));
    }
    Ok(())
}

#[cfg(test)]
mod quota_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn limits_default_to_unlimited() {
        let limits = Limits::from_lookup(|_| None);
        assert_eq!(limits.max_spaces, 0);
        assert_eq!(limits.max_disk_mib, 0);
        assert_eq!(limits.max_vcpus, 0);
        assert_eq!(limits.max_mem_mib, 0);
        assert_eq!(limits.max_running, 0);
        assert_eq!(limits.api_per_min, 0);
    }

    #[test]
    fn limits_environment_values_override_defaults() {
        let limits = Limits::from_lookup(|key| {
            Some(
                match key {
                    "SHINU_LIMIT_SPACES" => "9",
                    "SHINU_LIMIT_DISK_MIB" => "20480",
                    "SHINU_LIMIT_VCPUS" => "8",
                    "SHINU_LIMIT_MEM_MIB" => "16384",
                    "SHINU_LIMIT_RUNNING" => "4",
                    "SHINU_LIMIT_API_PER_MIN" => "600",
                    _ => return None,
                }
                .to_owned(),
            )
        });
        assert_eq!(limits.max_spaces, 0);
        assert_eq!(limits.max_disk_mib, 0);
        assert_eq!(limits.max_vcpus, 8);
        assert_eq!(limits.max_mem_mib, 16_384);
        assert_eq!(limits.max_running, 0);
        assert_eq!(limits.api_per_min, 600);
    }

    #[test]
    fn invalid_or_empty_environment_values_use_defaults() {
        let limits = Limits::from_lookup(|key| {
            Some(
                match key {
                    "SHINU_LIMIT_SPACES" => "not-a-number",
                    "SHINU_LIMIT_DISK_MIB" => " ",
                    "SHINU_LIMIT_RUNNING" => "-1",
                    "SHINU_LIMIT_API_PER_MIN" => "-1",
                    "SHINU_LIMIT_VCPUS" => "0",
                    "SHINU_LIMIT_MEM_MIB" => " ",
                    _ => return None,
                }
                .to_owned(),
            )
        });
        assert_eq!(limits, Limits::from_lookup(|_| None));
    }

    #[test]
    fn zero_environment_values_are_unlimited() {
        let limits = Limits::from_lookup(|key| {
            Some(
                match key {
                    "SHINU_LIMIT_SPACES"
                    | "SHINU_LIMIT_DISK_MIB"
                    | "SHINU_LIMIT_RUNNING"
                    | "SHINU_LIMIT_API_PER_MIN" => "0",
                    _ => return None,
                }
                .to_owned(),
            )
        });
        assert_eq!(limits.max_spaces, 0);
        assert_eq!(limits.max_disk_mib, 0);
        assert_eq!(limits.max_running, 0);
        assert_eq!(limits.api_per_min, 0);
    }

    #[test]
    fn project_zero_limits_are_unlimited() {
        let limits = Limits {
            max_spaces: 0,
            max_disk_mib: 0,
            max_running: 0,
            api_per_min: 0,
            ..Limits::from_lookup(|_| None)
        };

        let limiter = RateLimiter::new();
        for _ in 0..100 {
            assert!(limiter.check("demo", limits.api_per_min).is_ok());
        }
        let requests = limiter
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(requests.is_empty());
    }

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
    fn vcpu_limit_allows_exact_cap_and_rejects_above() {
        let limits = Limits {
            max_vcpus: 4,
            ..Limits::from_lookup(|_| None)
        };
        assert!(check_vcpu_limit(4, &limits).is_ok());
        assert!(matches!(
            check_vcpu_limit(5, &limits),
            Err(Error::Quota(message))
                if message.contains("requested 5") && message.contains("cap 4")
        ));
    }

    #[test]
    fn memory_limit_allows_exact_cap_and_rejects_above() {
        let limits = Limits {
            max_mem_mib: 1024,
            ..Limits::from_lookup(|_| None)
        };
        assert!(check_mem_limit(1024, &limits).is_ok());
        assert!(matches!(
            check_mem_limit(1025, &limits),
            Err(Error::Quota(message))
                if message.contains("requested 1025") && message.contains("cap 1024")
        ));
    }

    #[test]
    fn rate_limiter_rejects_calls_over_the_window_budget() {
        let limiter = RateLimiter::new();
        assert!(limiter.check("demo", 2).is_ok());
        assert!(limiter.check("demo", 2).is_ok());
        assert!(matches!(
            limiter.check("demo", 2),
            Err(Error::Quota(message))
                if message == "rate limit exceeded: 2 requests per minute"
        ));
    }

    #[test]
    fn rate_limiter_allows_a_call_after_the_window_slides() {
        let limiter = RateLimiter::new();
        let first = Instant::now();
        assert!(limiter.check_at("demo", 1, first).is_ok());
        assert!(
            limiter
                .check_at("demo", 1, first + Duration::from_secs(59))
                .is_err()
        );
        assert!(
            limiter
                .check_at("demo", 1, first + Duration::from_mins(1))
                .is_ok()
        );
    }

    #[test]
    fn rate_limiter_removes_expired_entries() {
        let limiter = RateLimiter::new();
        let first = Instant::now();
        assert!(limiter.check_at("stale", 1, first).is_ok());
        assert!(
            limiter
                .check_at("active", 1, first + Duration::from_secs(61))
                .is_ok()
        );
        let requests = limiter
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(!requests.contains_key("stale"));
        assert_eq!(requests.get("active").map(|times| times.len()), Some(1));
    }
}

#[cfg(test)]
mod storage_tests {
    use super::StoragePolicy;

    #[test]
    fn only_explicit_write_caps_are_enabled() {
        let policy = StoragePolicy::default();
        assert_eq!(policy.write_cap(None).unwrap(), 0);
        assert_eq!(policy.write_cap(Some(0)).unwrap(), 0);
        assert_eq!(policy.write_cap(Some(42)).unwrap(), 42);
        assert!(policy.write_cap(Some(u64::MAX)).is_err());
    }
}
