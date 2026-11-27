use serde::{Deserialize, Serialize};
use shinu_core::{Image, ReadySpec};
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
        #[serde(default)]
        readiness: Option<ReadySpec>,
    },
    Resize {
        space: String,
        vcpus: Option<Option<u32>>,
        mem_mib: Option<Option<u32>>,
        disk_mib: Option<Option<u64>>,
        #[serde(default)]
        readiness: Option<ReadySpec>,
    },
    Images,
    Fork {
        ckpt: Uuid,
        name: String,
        /// Positive lifetime in seconds; omitted or null means no expiry.
        #[serde(default)]
        ttl_seconds: Option<u64>,
        /// Omitted or zero is uncapped; positive values are explicit Space protection.
        #[serde(default)]
        write_cap_mib: Option<u64>,
        /// Omitted inherits the checkpoint's readiness policy.
        #[serde(default)]
        readiness: Option<ReadySpec>,
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
    /// With `detach`, space and checkpoint `parent` edges to it are cleared
    /// instead of refusing; space heads, templates, and memory bases still refuse.
    RmCkpt {
        ckpt: Uuid,
        #[serde(default)]
        detach: bool,
    },
    Ls,
    /// Starts the space's VM if it is not running and reports whether it booted.
    Start {
        space: String,
        #[serde(default)]
        load_only: bool,
        #[serde(default = "default_track_dirty")]
        track_dirty: bool,
    },
    Resume {
        space: String,
    },
    WarmCheckpoint {
        ckpt: Uuid,
    },
    /// Shuts the space's VM down. Idempotent.
    Stop {
        space: String,
    },
    /// Offline hole reclamation and Btrfs recompression of a stopped space.
    Compact {
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
    /// Sets guest kernel time dilation on a running space.
    TimeScale {
        space: String,
        /// Integer 1..=10; 1 is real time.
        scale: u32,
        /// Whether `CLOCK_REALTIME` advances with the scaled monotonic clock.
        #[serde(default = "default_sync_realtime")]
        sync_realtime: bool,
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
    /// Creates an immutable project-scoped checkpoint template.
    CreateTemplate {
        name: String,
        checkpoint: Uuid,
    },
    /// Lists immutable checkpoint templates in the authenticated project.
    ListTemplates,
    /// Removes one project-scoped checkpoint template reference.
    DeleteTemplate {
        name: String,
    },
    /// Forks a space from a project-scoped checkpoint template.
    ForkTemplate {
        template: String,
        name: String,
        /// Positive lifetime in seconds; omitted or null means no expiry.
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
}

const fn default_track_dirty() -> bool {
    true
}

const fn default_sync_realtime() -> bool {
    true
}
