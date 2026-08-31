use serde::{Deserialize, Serialize};
use shinu_core::Image;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotMode {
    #[default]
    None,
    Full,
    Diff,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Req {
    New {
        name: String,
        image: Option<Image>,
        vcpus: Option<u32>,
        mem_mib: Option<u32>,
        disk_mib: Option<u64>,
        #[serde(default)]
        network: Option<String>,
        /// Positive lifetime in seconds; omitted or null means no expiry.
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    Resize {
        space: String,
        vcpus: Option<Option<u32>>,
        mem_mib: Option<Option<u32>>,
        disk_mib: Option<Option<u64>>,
    },
    Images,
    Fork {
        ckpt: Uuid,
        name: String,
        /// Positive lifetime in seconds; omitted or null means no expiry.
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    /// `hot: true` syncs a running guest without remounting read-only and
    /// is not crash-consistent; `hot: false` requires the space to be stopped.
    /// A full snapshot captures guest memory and CPU state; a diff snapshot
    /// captures only dirty memory relative to its selected full base.
    Commit {
        space: String,
        note: String,
        hot: bool,
        #[serde(default)]
        snapshot: SnapshotMode,
    },
    Checkout {
        space: String,
        commit: Uuid,
    },
    /// Lists only commits reachable from the space's head, like `git log`.
    Log {
        space: String,
    },
    /// Lists every checkpoint archived for the space, including automatic
    /// checkpoints that checkout created and then left unreachable.
    Reflog {
        space: String,
    },
    /// Compares filesystem trees; `from` and `to` are checkpoint IDs when
    /// supplied, otherwise the space's current image is compared with HEAD.
    Diff {
        space: String,
        from: Option<Uuid>,
        to: Option<Uuid>,
        all: bool,
        limit: usize,
    },
    Rm {
        space: String,
    },
    /// Removes one project-scoped commit when no space or commit derives from it.
    RmCkpt {
        ckpt: Uuid,
    },
    Ls,
    /// Starts the space's VM if it is not running and reports whether it booted.
    Start {
        space: String,
    },
    /// Shuts the space's VM down. Idempotent.
    Stop {
        space: String,
    },
    /// Executes a command in the guest. Without `session`, each request is stateless;
    /// a session lives only as long as its VM and preserves shell state between calls.
    /// The command runs in that shell, so built-ins such as `cd` and `export` persist;
    /// state changed inside an explicit child process does not.
    Exec {
        space: String,
        cmd: Vec<String>,
        #[serde(default)]
        stdin: Option<String>,
        #[serde(default)]
        session: Option<String>,
    },
    /// Marks the VM as in use so the idle sweeper leaves it alone.
    Touch {
        space: String,
    },
    Usage {
        from: Option<i64>,
        to: Option<i64>,
    },
    Limits,
    Gc {
        free_below: u64,
        dry_run: bool,
    },
    /// Starts a command detached from the submitting HTTP connection.
    SubmitJob {
        space: String,
        cmd: Vec<String>,
        #[serde(default)]
        stdin: Option<String>,
    },
    /// Lists detached jobs in the authenticated project.
    ListJobs,
    /// Retrieves one detached job in the authenticated project.
    GetJob {
        id: Uuid,
    },
    /// Retrieves the bounded terminal-rendered log for one detached job.
    GetJobLogs {
        id: Uuid,
    },
    /// Requests cancellation of one detached job.
    CancelJob {
        id: Uuid,
    },
    /// Sets or clears the authenticated space's lease.
    SetLease {
        space: String,
        /// Positive lifetime in seconds; null clears the lease.
        ttl_seconds: Option<u64>,
    },
}
