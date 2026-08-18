//! Per-project resource ceilings and request throttling for the hosted demo.
use shinu_core::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_MAX_SPACES: u32 = 5;
const DEFAULT_MAX_DISK_MIB: u64 = 10_240;
const DEFAULT_MAX_RUNNING: u32 = 2;
const DEFAULT_API_PER_MIN: u32 = 120;
// These caps leave room for explicitly larger guests than the legacy
// defaults while keeping one tenant from exhausting a host by accident.
const DEFAULT_MAX_VCPUS: u32 = 16;
const DEFAULT_MAX_MEM_MIB: u32 = 32 * 1024;

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

    // A reader seam keeps parser tests deterministic without mutating the process environment.
    fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        Self {
            max_spaces: nonnegative_u32(&lookup, "SHINU_LIMIT_SPACES", DEFAULT_MAX_SPACES),
            max_disk_mib: nonnegative_u64(
                &lookup,
                "SHINU_LIMIT_DISK_MIB",
                DEFAULT_MAX_DISK_MIB,
            ),
            max_vcpus: positive_u32(&lookup, "SHINU_LIMIT_VCPUS", DEFAULT_MAX_VCPUS),
            max_mem_mib: positive_u32(&lookup, "SHINU_LIMIT_MEM_MIB", DEFAULT_MAX_MEM_MIB),
            max_running: nonnegative_u32(&lookup, "SHINU_LIMIT_RUNNING", DEFAULT_MAX_RUNNING),
            api_per_min: nonnegative_u32(&lookup, "SHINU_LIMIT_API_PER_MIN", DEFAULT_API_PER_MIN),
        }
    }
}

fn positive_u32<F>(lookup: &F, key: &str, default: u32) -> u32
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn nonnegative_u32<F>(lookup: &F, key: &str, default: u32) -> u32
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn nonnegative_u64<F>(lookup: &F, key: &str, default: u64) -> u64
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
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

        const WINDOW: Duration = Duration::from_secs(60);

        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Sweep every tenant on each request: otherwise a tenant that stops
        // sending calls would leave its timestamp and map key forever.
        for timestamps in requests.values_mut() {
            while timestamps.front().is_some_and(|at| {
                now.checked_duration_since(*at)
                    .is_some_and(|elapsed| elapsed >= WINDOW)
            }) {
                timestamps.pop_front();
            }
        }
        requests.retain(|_, timestamps| !timestamps.is_empty());

        let mut timestamps = requests.remove(project).unwrap_or_default();

        if timestamps.len() >= per_min as usize {
            if !timestamps.is_empty() {
                requests.insert(project.to_owned(), timestamps);
            }
            return Err(Error::Quota(format!(
                "rate limit exceeded: {per_min} requests per minute"
            )));
        }

        timestamps.push_back(now);
        requests.insert(project.to_owned(), timestamps);
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn check_space_limit(current_spaces: u32, limits: &Limits) -> Result<()> {
    if limits.max_spaces != 0 && current_spaces >= limits.max_spaces {
        return Err(Error::Quota(format!(
            "space limit reached ({current_spaces}/{}); delete a space or upgrade",
            limits.max_spaces
        )));
    }
    Ok(())
}

pub fn check_vcpu_limit(requested: u32, limits: &Limits) -> Result<()> {
    if requested > limits.max_vcpus {
        return Err(Error::Quota(format!(
            "vcpus limit exceeded (requested {requested}, cap {})",
            limits.max_vcpus
        )));
    }
    Ok(())
}

pub fn check_mem_limit(requested: u32, limits: &Limits) -> Result<()> {
    if requested > limits.max_mem_mib {
        return Err(Error::Quota(format!(
            "memory limit exceeded (requested {requested} MiB, cap {} MiB)",
            limits.max_mem_mib
        )));
    }
    Ok(())
}

pub fn check_disk_limit(
    current_mib: u64,
    adding_mib: u64,
    limits: &Limits,
) -> Result<()> {
    if limits.max_disk_mib == 0 {
        return Ok(());
    }
    let projected_mib = current_mib.saturating_add(adding_mib);
    if projected_mib > limits.max_disk_mib {
        return Err(Error::Quota(format!(
            "disk limit exceeded (requested total {projected_mib} MiB, cap {} MiB; current {current_mib}, adding {adding_mib})",
            limits.max_disk_mib
        )));
    }
    Ok(())
}

pub fn check_running_limit(current_running: u32, limits: &Limits) -> Result<()> {
    if limits.max_running != 0 && current_running >= limits.max_running {
        return Err(Error::Quota(format!(
            "running VM limit reached ({current_running}/{}); stop a VM or upgrade",
            limits.max_running
        )));
    }
    Ok(())
}

#[cfg(test)]
mod quota_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn limits_default_values_are_conservative() {
        let limits = Limits::from_lookup(|_| None);
        assert_eq!(limits.max_spaces, 5);
        assert_eq!(limits.max_disk_mib, 10_240);
        assert_eq!(limits.max_vcpus, 16);
        assert_eq!(limits.max_mem_mib, 32 * 1024);
        assert_eq!(limits.max_running, 2);
        assert_eq!(limits.api_per_min, 120);
    }

    #[test]
    fn limits_environment_values_override_defaults() {
        let limits = Limits::from_lookup(|key| {
            Some(match key {
                "SHINU_LIMIT_SPACES" => "9",
                "SHINU_LIMIT_DISK_MIB" => "20480",
                "SHINU_LIMIT_VCPUS" => "8",
                "SHINU_LIMIT_MEM_MIB" => "16384",
                "SHINU_LIMIT_RUNNING" => "4",
                "SHINU_LIMIT_API_PER_MIN" => "600",
                _ => return None,
            }
            .to_owned())
        });
        assert_eq!(limits.max_spaces, 9);
        assert_eq!(limits.max_disk_mib, 20_480);
        assert_eq!(limits.max_vcpus, 8);
        assert_eq!(limits.max_mem_mib, 16_384);
        assert_eq!(limits.max_running, 4);
        assert_eq!(limits.api_per_min, 600);
    }

    #[test]
    fn invalid_or_empty_environment_values_use_defaults() {
        let limits = Limits::from_lookup(|key| {
            Some(match key {
                "SHINU_LIMIT_SPACES" => "not-a-number",
                "SHINU_LIMIT_DISK_MIB" => " ",
                "SHINU_LIMIT_RUNNING" => "-1",
                "SHINU_LIMIT_API_PER_MIN" => "-1",
                "SHINU_LIMIT_VCPUS" => "0",
                "SHINU_LIMIT_MEM_MIB" => " ",
                _ => return None,
            }
            .to_owned())
        });
        assert_eq!(limits, Limits::from_lookup(|_| None));
    }

    #[test]
    fn zero_environment_values_disable_quota_checks() {
        let limits = Limits::from_lookup(|key| {
            Some(match key {
                "SHINU_LIMIT_SPACES"
                | "SHINU_LIMIT_DISK_MIB"
                | "SHINU_LIMIT_RUNNING"
                | "SHINU_LIMIT_API_PER_MIN" => "0",
                _ => return None,
            }
            .to_owned())
        });
        assert_eq!(limits.max_spaces, 0);
        assert_eq!(limits.max_disk_mib, 0);
        assert_eq!(limits.max_running, 0);
        assert_eq!(limits.api_per_min, 0);
        assert_eq!(limits.max_vcpus, 16);
        assert_eq!(limits.max_mem_mib, 32 * 1024);

        // These values are deliberately beyond the normal defaults: zero is
        // an explicit unlimited setting, not a request for the defaults.
        assert!(check_space_limit(6, &limits).is_ok());
        assert!(check_disk_limit(u64::MAX, u64::MAX, &limits).is_ok());
        assert!(check_running_limit(3, &limits).is_ok());

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
    fn space_limit_rejects_boundary_and_allows_below() {
        let limits = Limits {
            max_spaces: 5,
            ..Limits::from_lookup(|_| None)
        };
        assert!(check_space_limit(4, &limits).is_ok());
        assert!(matches!(
            check_space_limit(5, &limits),
            Err(Error::Quota(message)) if message.contains("5/5")
        ));
    }

    #[test]
    fn disk_limit_allows_exact_cap_and_rejects_above() {
        let limits = Limits {
            max_disk_mib: 100,
            ..Limits::from_lookup(|_| None)
        };
        // The cap is inclusive: a 100 MiB allowance has to permit exactly
        // 100 MiB, or the advertised number is never actually reachable.
        assert!(check_disk_limit(90, 10, &limits).is_ok());
        assert!(matches!(
            check_disk_limit(90, 11, &limits),
            Err(Error::Quota(message)) if message.contains("100")
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
    fn running_limit_rejects_boundary_and_allows_below() {
        let limits = Limits {
            max_running: 2,
            ..Limits::from_lookup(|_| None)
        };
        assert!(check_running_limit(1, &limits).is_ok());
        assert!(matches!(
            check_running_limit(2, &limits),
            Err(Error::Quota(message)) if message.contains("2/2")
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
        assert!(limiter
            .check_at("demo", 1, first + Duration::from_secs(59))
            .is_err());
        assert!(limiter
            .check_at("demo", 1, first + Duration::from_secs(60))
            .is_ok());
    }

    #[test]
    fn rate_limiter_removes_expired_entries() {
        let limiter = RateLimiter::new();
        let first = Instant::now();
        assert!(limiter.check_at("stale", 1, first).is_ok());
        assert!(limiter
            .check_at("active", 1, first + Duration::from_secs(61))
            .is_ok());
        let requests = limiter
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(!requests.contains_key("stale"));
        assert_eq!(requests.get("active").map(|times| times.len()), Some(1));
    }
}
