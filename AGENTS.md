# Repository Guidelines

## Project Overview

`shinu` is a multi-tenant sandbox platform for AI agents, offering Firecracker microVM execution with git-like version control, copy-on-write disk branching, optional Space leases, physical capacity admission, usage metering, detached jobs, named networks, HTTP proxying, guest desktops, user accounts, and an MCP server.

A **space** is a named microVM instance tied to an ext4 disk image cloned via CoW (`cp --reflink=always`) from a base rootfs image (e.g. `base-void.ext4`).
`shinu` provides git-like disk versioning: spaces track commit DAGs, support cold/hot commits, history log chains, head checkouts (with auto-commit reflogs), commit forks, and optional TTL leases.
A **Template** is an immutable, project-scoped name-to-checkpoint reference with logical fields `{name, checkpoint, created_at}`. Names are 1–64 lowercase ASCII characters matching `[a-z0-9-]`; template deletion removes only the reference, never checkpoint files.

VMs can run in four guest base images: `void` (default), `ubuntu`, `arch`, and `rocky`. Commits support three snapshot modes: `none`, `full`, and `diff`. A `full` snapshot captures guest memory plus CPU state; a `diff` snapshot captures dirty memory pages relative to a selected full base recorded in the `ckpts.base` field of the database. The platform also supports an image filesystem tree `diff` (entirely distinct from diff memory snapshots) that compares file-level changes between checkpoints or spaces.

Clients interact with `shinud` strictly over HTTP/1.1 using Bearer token authentication or console session credentials. TLS is terminated externally (e.g., via Caddy), while the daemon listens on loopback. Synchronous `exec` runs over SSH/vsock and streams chunked NDJSON; detached jobs run asynchronously through REST, CLI, and MCP surfaces and expose terminal-rendered logs. The web console dashboard (build-free, framework-free vanilla JS) allows users to register, log in, manage access tokens, and inspect logs plus read-only lease expiry, but has no detached-job controls.

MicroVM processes are jailed inside unprivileged user/cgroup chroot sandboxes managed via Firecracker's Jailer.

## Architecture & Data Flow

```mermaid
graph TD
  Client[AI Agent / CLI Client] --|HTTPS / Bearer Token| Caddy[Caddy Proxy / TLS Termination]
  Console[Web Console / Console Session] --|HTTPS / Session Cookie| Caddy
  Caddy --|HTTP / Loopback 127.0.0.1:7878| Daemon[shinud daemon]
  MCP[shinu-mcp JSON-RPC] --|shinu client CLI wrapper| Daemon
  Daemon --|SQLite WAL| DB[(<root>/shinu.db)]
  Daemon --|Host capacity check and usage samples| Storage[storage module]
  Daemon --|Spawn via Jailer uid 30000| Jailer[jailer exec chroot]
  Jailer --|cgroup v2 & hardlink rootfs/kernel| VM[firecracker microVM]
  Daemon --|SSH over vsock / NDJSON / VNC / Proxy| VM
```

- **Control Plane & Protocol** — `shinud` is a thread-per-connection HTTP/1.1 daemon listening by default on `127.0.0.1:7878` (configured via `SHINU_LISTEN`). Request routing is handled in `src/bin/shinud.rs:2188-2273`, with HTTP method validation enforced in the `method_allowed` matrix at `src/bin/shinud.rs:2428-2467`. Standard REST actions return JSON. Synchronous `exec` streams NDJSON chunks via `Transfer-Encoding: chunked`, ending with `{"exit": N}` (`src/bin/shinud.rs:4669-4785`); `GET /v1/jobs/{id}/logs` instead returns one terminal-rendered text stream capped at 1 MiB. `Req::Exec` carries an optional `session: Option<String>` field (`#[serde(default)]`, so existing clients without it are unaffected) supporting persistent shell sessions where builtins (`cd`, `export`) persist across calls.
  Execution spawns host `ssh` using `ProxyCommand=shinu-vsock <uds> 2222`, tunnelled through Firecracker's AF_VSOCK device to an in-guest `socat` listener (`VSOCK-LISTEN:2222`) forwarding to guest `sshd` (`127.0.0.1:22`). VNC connections tunnel through vsock port `2223` (`VSOCK_VNC_PORT` in `crates/shinu-core/src/lib.rs:20`).
  Data transfer uses `exec` `stdin` for pasting text, or `push` (`POST /v1/spaces/{name}/push?path=...`) and `pull` (`GET /v1/spaces/{name}/pull?path=...`) for streaming binary files up to 256 MiB (`MAX_UPLOAD_BYTES` in `crates/shinu-core/src/lib.rs:22`).
  HTTP proxying (`/v1/spaces/{name}/proxy/{port}[/{path}]`) maps requests into guest-exposed TCP ports over vsock.
  Adding an operation requires touching:
  1. `proto::Req` in `crates/shinu-proto/src/proto.rs:16-101`
  2. CLI `Command` enum in `src/bin/shinu.rs:33-177`
  3. HTTP route parser in `src/bin/shinud.rs:2188-2273`
  4. HTTP method validation matrix `method_allowed` in `src/bin/shinud.rs:2428-2467`
  5. `request_for` mapping and `handle()` dispatcher in `src/bin/shinud.rs:2059-2146`
  6. Physical capacity admission points in `src/bin/shinud.rs`.
  7. Usage event logging (`state::record_usage`) in `src/bin/shinud.rs`
  8. `shinu-mcp` tool table and arg validator in `src/bin/shinu-mcp.rs:873-1004` (if exposing to MCP)
  9. Web console `src/console/app.js` UI routes (if console-exposed)

- **Identity & Project Tenant Isolation** — Authentication uses either `Authorization: Bearer <token>` or console session cookies. A Bearer token is always authoritative when present. Tokens map to a **project** name (`crates/shinu-crypto/src/token.rs`). Tokens are stored in `<root>/tokens.json` (mode `0600`) as SHA-256 hashes and compared in constant time. Users register and authenticate through the console UI, writing passwords hashed with PBKDF2-HMAC-SHA256 (210,000 iterations, 32-byte salt) to the database, which grants user sessions. Spaces, checkpoints, templates, jobs, and usage records belong to a project. Cross-project lookups return `NotFound` (404) to avoid leaking existence.

- **Jailer Sandbox Isolation** — `vm::start` (`crates/shinu-vm/src/vm.rs:988`) launches Firecracker microVMs inside jailer chroot sandboxes (`/usr/bin/jailer`). Process credentials drop to unprivileged `shinu-jail` user/group (`SHINU_JAIL_UID` / `SHINU_JAIL_GID`, default 30000). cgroup v2 resource limits are enforced on each sandbox (`memory.max=<mem>M`, `pids.max=512`). Kernel (`assets/vmlinux`) and rootfs images are hardlinked into the chroot tree at `<root>/jail/firecracker/<uuid>/root/` (`link_resource` in `crates/shinu-vm/src/vm.rs:920-935`).

- **Capacity** — Create/fork/start/resume use actual store-free and host MemAvailable floors. Read README's “Physical Capacity” and “Loaded Spaces and shared Full memory” before editing admission, restore, or storage accounting.

- **State Storage & Indexing** — SQLite in WAL mode (`<root>/shinu.db`, mode `0600`) manages state. The schema in `crates/shinu-store/src/state.rs` contains:
  - `spaces`: microVM metadata, parent commit, current head, sizing (vcpus, mem_mib, disk_mib), network name, creation time, and optional `expires_at` (RFC3339 or `null`).
  - `ckpts`: commit records, including auto-commits, full snapshot flag, parent/base commit UUIDs, `snapshot_version`, and nullable captured sizing (`vcpus INTEGER`, `mem_mib INTEGER`, `disk_mib INTEGER`). Schema migration backfills sizing once from surviving source spaces; orphan legacy rows remain NULL.
  - `usage_events`: metered usages (disk_mib_hour, vm_seconds, api_call, space_created).
  - `users`: user emails, password hashes, and registration timestamps.
  - `memberships`: maps users to projects with roles.
  - `sessions`: session IDs, user IDs, and expiration times.
  - `jobs`: detached command records with columns `id`, `project`, `space`, `command`, `state`, `created_at`, `started_at`, `finished_at`, `exit_code`, `error`, `log_bytes`, and `log_truncated`. States are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`.
  - `job_log_deletions`: durable pending unlinks for terminal-job archives. The same transaction retires the job row; the sweep retries the unlink until it succeeds.
  - `templates`: immutable project-scoped checkpoint references with `{name, checkpoint, created_at}` and unique names per project. The daemon lists them by name cursor without loading them into the Space/Checkpoint graph.
  - `sqlite_sequence`: internal autoincrement tracking.
  
  Indexes (`templates_project_checkpoint` at `crates/shinu-store/src/state.rs:224`; `spaces_project_expires` in `init_schema` at `state.rs:317-318`):
  - `spaces(project, name)`
  - `ckpts(project)`
  - `ckpts(space)`
  - `usage_events(project, "at")`
  - `sessions(user_id)`
  - `memberships(project)`
  - `jobs_project_created(project, created_at DESC, id DESC)`
  - `jobs_project_space_state(project, space, state)`
  - `jobs_project_state(project, state)`
  - `templates_project_checkpoint`
  - `spaces_project_expires`

- **Space Lease Runtime** — `expires_at` is RFC3339 or `null`; existing spaces and spaces created without a TTL use `null` and never expire. Expired leases reject new starts, auto-starts, and jobs. Detached-job deadlines are capped by the current lease, so active jobs postpone VM stopping and cleanup only through the existing bounded cancellation/final-log pipeline. After `SHINU_LEASE_GRACE_SECS`, the expiry sweep deletes the mutable Space using claim-before-delete; renewal under the Space lock wins. Checkpoints, their archived memory-snapshot SSH credentials, and templates remain usable without the source Space.

- **Concurrency & Locking Discipline** — `shinud` uses thread-per-connection concurrency with `shinu_store::registry::Registry` (`crates/shinu-store/src/registry.rs`). Locking follows a multi-tier model:
  1. Per-space lock (`Arc<Mutex<()>>` via `Registry::space_lock`): serializes long-running VM and space-scoped job operations.
  2. Optional per-job/checkpoint lock: serializes operations on one job or checkpoint.
  3. Global state lock (`Registry::state_lock`): serializes SQLite transactions and state modifications.
  4. Database connection lock (`Mutex<Connection>`): serializes SQLite access.
  
  **Lock Order Invariant**: Space-scoped paths acquire space → optional job/checkpoint → state → database connection. Job-monitor paths acquire job → state → database connection. Template create/delete/fork state transitions resolve project-scoped references under state → database connection and template fork releases those locks before CoW/VM work. Never hold state or database locks across long disk CoW, subprocess, VM, or network operations.

## Key Directories

| Path | Purpose |
|---|---|
| `crates/shinu-core/` | Low-level common types and constants: `Error`, `Result`, `Image` enum, path resolution, base layout initialisation, Btrfs CoW helpers, and SSH proxy vsock banner parsing (`crates/shinu-core/src/lib.rs`). |
| `crates/shinu-store/` | State management: SQLite schemas and migrations (`state.rs`), lock registry (`registry.rs`), checkpoint DAG logic (`chain.rs`), and host watermarks and storage usage samples (`storage.rs`). |
| `crates/shinu-crypto/` | Cryptographic functions: authentication algorithms (`auth.rs`), SHA-256 implementation (`sha2.rs`), and token verification (`token.rs`). |
| `crates/shinu-image/` | Distribution assets: base image building (`build.rs`), OCI fetching (`fetch.rs`), guest network configuration (`configure.rs`), tree diffing (`diff.rs`), and extraction (`extract.rs`). |
| `crates/shinu-vm/` | Execution harness: VM sandbox launcher and state probe (`vm.rs`), network TAP and IP/iptables bridge config (`net.rs`), and VM configuration (`config.rs`). |
| `crates/shinu-proto/` | Wire protocol: HTTP request parsing and responses (`http.rs`) and serialization models (`proto.rs`). |
| `src/lib.rs` | Re-export facade mapping the six workspace crates into a single flat namespace for binaries (`src/lib.rs`). |
| `src/bin/shinu.rs` | Client CLI: Clap CLI parsing, stream parsing, and local token generation (`src/bin/shinu.rs`). |
| `src/bin/shinud.rs` | Control daemon: Route handlers, connection loop, console auth, CSRF pre-checks, and GC (`src/bin/shinud.rs`). |
| `src/bin/shinu-mcp.rs` | MCP Server: Line-delimited JSON-RPC 2.0 interface providing 25 tools for agents (`src/bin/shinu-mcp.rs`). |
| `src/bin/shinu-vsock.rs`| Stdio-to-vsock bridge helper used as SSH ProxyCommand (`src/bin/shinu-vsock.rs`). |
| `src/console/` | Web Console: Framework-free frontend dashboard (`index.html`, `auth.html`, `app.js`, `app.css`). |
| `site/` | Astro-based marketing and documentation site. |
| `packaging/` | Runit configuration (`sv/shinud/run`), reverse proxy config (`caddy/Caddyfile`), and the target installation script (`install.sh`). |

Runtime layout (`crates/shinu-core/src/lib.rs:359-374` `init_layout`):

```
<root>/tokens.json                 0600    hashed Bearer tokens
<root>/shinu.db                    0600    SQLite daemon state
<root>/state.json.migrated         0600    backup of migrated legacy state JSON (if migrated)
<root>/base-void.ext4              0644    golden base disk image for Void
<root>/spaces/                     0700    dir; space CoW disk images (<id>.ext4)
<root>/ckpts/                      0700    dir; immutable commits (<id>.ext4, <id>.mem, <id>.state, <id>.key, <id>.pub; SSH credentials mode 0600)
<root>/jobs/                      0700    root-owned detached-job log directory (<uuid>.log files mode 0600)
<root>/vm/<uuid>/                  0700    dir; VM host-side assets: last_used, id_ed25519
<root>/jail/firecracker/<uuid>/    0700    dir; jailer chroot root: root/ (fc.json, fc.sock, vsock.sock, firecracker.pid)
<root>/assets/                     0755    firecracker binary + vmlinux kernel
<root>/cache/                      0755    downloaded rootfs tarballs
```

## Development Commands

```sh
cargo build                          # debug build
cargo build --release                # release build expected by packaging/install.sh
cargo test --workspace               # run full cargo workspace test suite (321 tests across 20 suites)
cargo clippy --all-targets           # check for lint issues against workspace posture
cargo fmt --check                    # check formatting
```

### Compiler Lints Baseline
The workspace enforces a strict Clippy posture defined in the root `Cargo.toml`. `clippy::all` is set to `deny`, while `pedantic` and `nursery` are set to `warn`. An allow-list with explicit hit counts acts as a pinned baseline (e.g. `missing_errors_doc = "allow"` annotated with 91 hits, `unreadable_literal = "allow"` annotated with 72 hits) to keep compilation warnings clean without forcing immediate refactoring.

Host requirements for running `shinud`:
- Root privileges (for mount, net, TAP, chown, iptables operations).
- Linux host with `/dev/kvm` and a btrfs mount point for CoW reflink support.
- Dedicated unprivileged user/group `shinu-jail` (uid=30000, gid=30000).
- Linux cgroup v2 unified hierarchy mounted at `/sys/fs/cgroup`.

Running the daemon and interacting via CLI / HTTP API:

```sh
# Start daemon
sudo ./target/release/shinud --root /tmp/shinu-dev

# Generate an authentication token for a project (local root command, does not use HTTP)
sudo ./target/release/shinu token new --project demo

# Set environment variables for client
export SHINU_ENDPOINT="http://127.0.0.1:7878"
export SHINU_TOKEN="<token-from-shinu-token-new>"

# CLI commands
shinu new web --image void --ttl 2h  # create space with void image and a lease (alternatives: ubuntu, arch, rocky)
shinu resize web --vcpus 4 --mem 2048 # resize CPU or memory allocations (must be stopped)
shinu exec web -- uname -a           # synchronous command; streams chunked NDJSON
# Run a detached job; this returns a job ID without waiting for completion
shinu job run web -- sh -c 'echo started; sleep 5; echo done'
shinu job ls
shinu job status <job-uuid>
shinu job logs <job-uuid>
shinu job wait <job-uuid>
shinu job cancel <job-uuid>
shinu commit web --note "v1"         # create cold commit (space must be stopped)
shinu commit web --note "hot" --hot  # create hot commit while running
shinu log web                        # show commit history DAG
shinu reflog web                     # show full reflog history
shinu checkout web <commit-uuid>     # checkout commit (creates auto-commit reflog)
shinu fork <commit-uuid> web-branch --ttl 30m  # fork commit into a new space with a lease
# Name and list a checkpoint with an immutable template reference
shinu template create baseline <commit-uuid>
shinu template ls
# Fork the template's concrete checkpoint into a new space
shinu template fork baseline template-demo --ttl 30m
# Remove only the template reference; the checkpoint remains
shinu template rm baseline
shinu lease web --ttl 2h             # set a space lease
shinu lease web --clear              # clear a space lease
shinu stop web                       # stop microVM
shinu rm web                         # delete space
shinu rmckpt <commit-uuid>           # delete commit (refused if referenced)
shinu rmckpt --detach <commit-uuid>  # delete commit, clearing parent links; heads/templates/bases still refuse
shinu gc --free-below 10737418240    # run garbage collection
shinu usage                          # show project resource usage summary
shinu limits                         # show host capacity watermarks and current project usage
shinu desktop web                    # launch and hook up guest X11 desktop environment
shinu vnc web --port 5901            # connect to GUI desktop via VNC bridge
shinu proxy web 8080 --path /api     # proxy host requests into guest port 8080
```

HTTP API usage via `curl`:

```sh
# Query host watermarks and project usage
curl -sH "Authorization: Bearer $SHINU_TOKEN" http://127.0.0.1:7878/v1/limits

# Query project usage metrics
curl -sH "Authorization: Bearer $SHINU_TOKEN" http://127.0.0.1:7878/v1/usage

# Create a space
curl -sX POST -H "Authorization: Bearer $SHINU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"api-space","image":"void"}' \
  http://127.0.0.1:7878/v1/spaces

# Stream exec execution
curl -sX POST -H "Authorization: Bearer $SHINU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cmd":["echo","hello"]}' \
  http://127.0.0.1:7878/v1/spaces/api-space/exec
```

CLI Subcommand Surface (`src/bin/shinu.rs:33-177`):
- `new <name> [--image <img-id>] [--vcpus <n>] [--mem <mib>] [--disk <mib>] [--network <name>] [--ttl <duration>]`
- `resize <space> [--vcpus <n>] [--mem <mib>] [--disk <mib>]`
- `images`
- `ls [--json]`
- `network <name>`
- `rm <space>`
- `start <space> [--load-only] [--track-dirty true|false]`
- `resume <space>`
- `ckpt warm <checkpoint>`
- `stop <space>`
- `desktop <space>`
- `vnc <space> [--port <port>]`
- `proxy <space> <port> [--path <path>]`
- `exec <space> [--session <id>] [--stdin <file>] -- <cmd...>`
- `job run <space> -- <cmd...>`
- `job ls`
- `job status <job-id>`
- `job logs <job-id>`
- `job wait <job-id>`
- `job cancel <job-id>`
- `push <space> <local-file> <guest-path>`
- `pull <space> <guest-path> <local-file>`
- `commit <space> --note <note> [--hot] [--full|--diff]`
- `log <space> [--json]`
- `reflog <space> [--json]`
- `diff <source> [target] [--all] [--limit <n>]`
- `checkout <space> <commit-uuid>`
- `fork <commit-uuid> <name> [--ttl <duration>]`
- `rmckpt [--detach] <commit-uuid>`
- `template create <name> <checkpoint-uuid>`
- `template ls [--after <name>] [--json]`
- `template rm <name>`
- `template fork <template> <destination> [--ttl <duration>]`
- Listing returns at most 64 templates and a `next` name cursor; pass it as `after` to continue.
- `gc --free-below <bytes> [--dry-run]`
- `usage [--from <ts>] [--to <ts>] [--json]`
- `limits [set <project> --spaces <n> --disk-mib <mib> --running <n> --api-per-min <n> --inherit <list>] [clear <project>] [--json]`
- `token new --project <project> | ls | rm <hash-prefix>`
- `lease <space> [--ttl <duration>|--clear]`
- CLI lease durations use the grammar `N{s|m|h|d}`.
## Detached Jobs

- REST routes: `POST /v1/spaces/{space}/jobs`, `GET /v1/jobs`, `GET /v1/jobs/{id}`, `GET /v1/jobs/{id}/logs`, and `POST /v1/jobs/{id}/cancel`.
- CLI: `shinu job run|ls|status|logs|wait|cancel`.
- MCP: `shinu_run_job`, `shinu_list_jobs`, `shinu_job_status`, `shinu_job_logs`, and `shinu_cancel_job`.
- Existing `exec` remains synchronous. Job states are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`.
- Jobs survive client disconnect and daemon restart only while the VM stays running. Active jobs refresh idle use and block space stop/remove; VM loss yields `lost`.
- Job wall-clock deadlines are the earlier of `created_at + SHINU_JOB_MAX_SECS` (default `3600`, `0` disables this cap) and the current host Space lease expiry, if any. The job monitor requests durable `canceling`, then reuses fence → final capture → archive → cleanup; canceled jobs retain a deadline-specific `error`. Lease renewal/clear before cancellation affects the deadline but never revives a canceling job.
- Logs are one terminal-rendered text stream capped at 1 MiB and archived at `<root>/jobs/<uuid>.log` (mode `0600`); the `jobs/` directory is root-owned and mode `0700`.
- Detached commands accept at most 256 argv elements and 8192 total argument bytes.
- `GET /v1/jobs` returns the newest 64 jobs and includes `truncated` when older jobs are omitted. Startup recovery, idle sweeps, and Space job-log cleanup operate in bounded batches.
- Bounded control SSH kills its local process group on deadline or overflow. Cancellation fences the command before final capture, archive, and cleanup.
- There is no follow/raw log mode, force-stop, reboot survival, artifact support, or console control.

## Code Conventions & Common Patterns

- **Physical Admission Before Mutation** — New create/fork/start/resume admission checks actual store-free and host MemAvailable floors outside state/database locks. Removed project quotas must not be reintroduced via historical rows, nominal sizing, or reservations.
- **Strict Separation of Disk Measurement Metrics** —
  - Capacity reporting uses sampled btrfs exclusive bytes only; unknown samples report zero. Include private pending memory/state, but account checkpoint-linked Full memory once. Probe outside state/database locks; refresh in the usage sweep.
  - Usage billing tracking uses `disk_mib_hour` in `usage_events` as a **cumulative time series**.
  Physical admission uses store free space and MemAvailable, independently of usage billing totals.
- **Indexed Single-Row Queries vs. Full State Snapshots** —
  - Single-item lookups and mutation paths (`commit_space`, `checkout_space`, `remove_space`, `remove_checkpoint`) use direct SQL single-row queries via indexed fields (`project`, `name`, `id`).
  - Full DAG operations (`Ls`, `gc`, `Log`, `Reflog`, `is_referenced`) use `state::load` to fetch a full `State` snapshot.
  - Do NOT split `update_state` closure lookups into separate read transactions before lock acquisition, as this introduces TOCTOU (time-of-check to time-of-use) races.
- **Synchronous std only.** Uses `std::process::Command`, `std::os::unix::net`, `std::thread`, `std::sync::Mutex`. No Tokio, async runtimes, or `log` crate. Errors print to `stderr` via `eprintln!`.
- **No `libc` dependency.** System attributes and commands use `/proc` reads, `/sys/fs/cgroup` reads, or standard tools (`chown`, `df`, `btrfs`, `ip`, `iptables`, `sha256sum`, `jailer`).
- **Domain Errors** — Defined in `shinu_core::Error` (`crates/shinu-core/src/lib.rs:33-47`): `Btrfs(String)`, `NotFound(String)`, `Invalid(String)`, `Auth(String)`, `Quota(String)`, `Internal(String)`, `Io(std::io::Error)`, `Json(serde_json::Error)`.
- **External Command Failures** — Standardized via `command_failure` (`crates/shinu-core/src/lib.rs` / `crates/shinu-image/src/assets.rs`) to capture argv and stderr.
- **Environment-based Configuration** — All settings use `SHINU_*` env vars. No configuration files:
  - `SHINU_ROOT`: Root state directory (default `/var/lib/shinu`).
  - `SHINU_LISTEN`: HTTP daemon bind address (default `127.0.0.1:7878`, `src/bin/shinud.rs:94-97`).
  - `SHINU_REFLOG_DAYS`: Reflog auto-commit retention in days (default `7`).
  - `SHINU_JOB_RETENTION_DAYS`: Archived detached-job log retention in days (default `7`).
  - `SHINU_JOB_MAX_SECS`: Detached-job wall-clock cap from submission (default `3600`; `0` disables the cap, but Space lease expiry still applies).
  - `SHINU_SESSION_DAYS`: Console user session expiration in days (default `7`).
  - `SHINU_FULL_EVERY`: Per-base diff cap on the auto degradation path (default `8`, `0` disables).
  - `SHINU_VCPUS`: VM vCPU count (default `2`).
  - `SHINU_MEM_MIB`: VM memory limit in MiB (default `1024`).
  - `SHINU_IDLE_SECS`: Idle timeout before VM shutdown (default `3600`).
  - `SHINU_LEASE_GRACE_SECS`: Grace period in seconds after lease expiry before mutable-space cleanup (default `300`).
  - `SHINU_DISK_MIB`: Base disk size in MiB, read on base build (default `2048`).
  - `SHINU_JAIL_UID`: Unprivileged jailer UID (default `30000`).
  - `SHINU_JAIL_GID`: Unprivileged jailer GID (default `30000`).
  - `SHINU_MIN_STORE_FREE_MIB`: Actual store free-space admission floor (default `1024`).
  - `SHINU_MIN_MEM_AVAILABLE_MIB`: Host MemAvailable admission floor (default `512`).
  - Obsolete `SHINU_LIMIT_*` variables are ignored and named once at startup.
  - `SHINU_NET_ENABLE`: Enable TAP networking (default `true`).
  - `SHINU_NET_BASE`: IPv4 subnet base (default `172.31`).
  - `SHINU_NET_ALLOW`: Comma-separated guest egress whitelist CIDRs.
  - `SHINU_HOST_ALLOW`: Comma-separated guest host access rules (`protocol:port[@host]`).
  - `SHINU_NET_UPLINK`: Host egress interface for NAT.
  - `SHINU_GUEST_DNS`: Guest resolver fallback DNS server (default `1.1.1.1`).
  - `SHINU_PAYLOAD`: Files to inject into new guest filesystems.
  - `SHINU_PAYLOAD_SERVICE`: runit service to enable on boot.
  - `SHINU_ROOTFS_TARBALL`: Local rootfs archive overriding the download.
  - `SHINU_MIRROR`: Void package mirror (default `repo-default.voidlinux.org`).
  - `SHINU_ARCH`: Target guest architecture (default `uname -m`).
- **Concurrency & Lock Order Discipline** —
  1. Space-scoped paths lock space → optional job/checkpoint → state → database connection. Job-monitor paths lock job → state → database connection. Lease renewal and expiry cleanup use the per-space lock; renewal wins when serialized. Never acquire these locks in reverse order.
  2. Lock hold scope must be minimal. Do NOT hold state or database locks during btrfs disk operations, subprocess spawning, VM execution, or network calls.
- **Claim-before-Delete Pattern (GC & Mutation Discipline)** —
  When modifying shared state and deleting disk files (e.g. during `gc`, commit deletion, or expired-space cleanup), atomically claim the record under state lock first (re-verify conditions and remove entry from database), release the lock, and then delete files on disk. Expiry cleanup deletes only the mutable Space; checkpoints and templates remain. Template deletion is reference-only and MUST NOT unlink checkpoint files. `rmckpt` and GC MUST treat a template's checkpoint as referenced. Active jobs postpone cleanup, and renewal under the Space lock wins over expiry cleanup.
- **Automatic Snapshot Degradation Semantics** —
  - Full-to-Diff degradation requires a usable same-Space format-12 full base and a `snapshot-generation` marker matching that exact live dirty epoch. Positive `SHINU_FULL_EVERY` caps the auto path; zero disables it.
  - Invalidate the marker before every memory capture and on boot; publish it only after a successful checkpoint. FC resets dirty bits even when later disk cut/publication fails. A second Diff, restored VM, or uncertain epoch forces Full, including explicit Diff requests. At most one Diff currently follows each Full.
  - Hot capture owns freeze → pause → create/drain → disk reflink → resume → reverse thaw. Any failure attempts cleanup and prevents checkpoint publication. Restore must thaw the captured ledger before exposing the guest. Cold/legacy checkpoints are crash-consistent absent clean-shutdown evidence.

## Important Files

- `crates/shinu-store/src/state.rs:204` `state::open` — Opens `shinu.db` SQLite connection with WAL mode and foreign key constraints.
- `crates/shinu-store/src/state.rs:317` `state::migrate_from_json` — Imports legacy `state.json` into SQLite database and renames original file to `state.json.migrated`.
- `crates/shinu-store/src/storage.rs` — Capacity watermarks, explicit Space write protection, and sampled exclusive storage usage.
- `crates/shinu-vm/src/vm.rs:618` `vm::is_running` — VM running checks via UDS PID files and process argv inspection.
- `crates/shinu-proto/src/http.rs` — Hand-rolled HTTP parser, NDJSON chunk writer, and error status mapper.
- `crates/shinu-proto/src/http.rs:465` `http::status_for` — Sole mapping of `Error` enum variants to HTTP status codes (Auth->401, NotFound->404, Invalid->400, Quota->429, Btrfs/Io/Json/Internal->500).
- `packaging/caddy/Caddyfile` — Reverse proxy and TLS termination configuration. Configures `flush_interval -1` to stream NDJSON without buffering and `read_timeout 0` for long-running `exec` commands.
- `packaging/install.sh` — Copies binaries to `$PREFIX/bin` (`/usr/local/bin`) and service file to `$SVDIR/shinud`. Creates `shinu-jail` user/group (uid/gid 30000). Note: `packaging/sv/shinud/run` hardcodes `/usr/local/bin/shinud`.
- `Cargo.toml` — Rust workspace configuration, defining package compilation options and unified clippy/rust lint baseline policies.

## Runtime / Tooling Preferences

- **Single Addition Dependency** — `rusqlite 0.32` with `bundled` feature is the sole added dependency (total direct dependencies: 6). The `bundled` feature compiles SQLite directly into the crate, ensuring hermetic builds without relying on system `libsqlite3`.
- **Jailer Privileges & cgroup v2** — MicroVM isolation requires Firecracker's Jailer (`/usr/bin/jailer`), running under unprivileged UID/GID 30000 (`shinu-jail`) with cgroup v2 limits (`memory.max`, `pids.max`).
- **External TLS Termination** — `shinud` does not implement native TLS. TLS MUST be terminated by an upstream reverse proxy such as Caddy (`packaging/caddy/Caddyfile`), with `flush_interval -1` set to prevent buffering chunked NDJSON execution streams.

## Testing & QA

- Total test count: **321 tests across 20 suites**.
- **Test Execution Environment**:
  - Tests run via built-in `cargo test --workspace`.
  - Tests are hermetic: they run against temporary directories created via `std::env::temp_dir()`, use `NetConfig { enabled: false, .. }`, do not spawn real Firecracker VMs or Jailer sandboxes, do not perform btrfs reflink operations, and do not require root privileges.
- **Uncovered Paths (Require Manual Host Verification)**:
  - Execution via real Jailer `/usr/bin/jailer` chroot sandboxes.
  - Verification of cgroup v2 limits (`memory.max`, `pids.max`).
  - Hardlink creation for kernel and rootfs into jail chroots (verifying identical inode and zero-copy link).
  - Real Firecracker microVM boot, execution, and shutdown.
  - Actual btrfs image reflink cloning (`cp --reflink=always`).
  - Linux TAP interface creation and iptables NAT setup.
  - Named networks mesh and inter-VM peer communication.
  - VNC socket bridge forwarding and visual console desktop rendering.
  - HTTP proxying route mapping and guest port DNAT loopback communication.
  - Memory snapshot saving and sparseness-preserving diff merges.
  - Live base image building and OCI package extraction.
  - Manual smoke testing requires a Linux host with `/dev/kvm`, btrfs mount point, cgroup v2 enabled, and unprivileged user `shinu-jail` (uid=30000).

## Invariants Worth Guarding

1. **Jailer Sandbox Isolation is Non-Negotiable** — `vm::start` MUST execute microVMs through Firecracker's Jailer under an unprivileged UID/GID (default 30000). Direct `firecracker` execution on the host is prohibited.
2. **Kernel and Rootfs Zero-Copy Hardlinking** — Assets linked into jail chroots (`<root>/jail/firecracker/<uuid>/root/`) MUST use hardlinks (`std::fs::hard_link`). Never fall back to copy operations, which consume 2 GiB per VM instance.
3. **Physical Capacity Admission** — Create/fork/start/resume check actual host watermarks. Project quotas and admission reservations do not apply.
4. **Exclusive Storage Measurement** — Use actual exclusive samples, never nominal/reserved capacity or cumulative billing totals. The schema-versioned upgrade clears unproven inherited write caps exactly once; only newly explicit Space caps can stop a guest.
5. **Project Tenant Isolation Never Leaks Existence** — Lookups filter strictly by token project name and return `NotFound` (404). A space or commit belonging to another project is indistinguishable from a nonexistent entity.
6. **Tokens are Stored as Hashes & Compared in Constant Time** — Token plaintexts are never persisted; `<root>/tokens.json` stores SHA-256 hashes. Token validation uses `constant_time_eq` to prevent timing side-channel attacks.
7. **Strict Multi-Tier Lock Order** — Space-scoped paths acquire space → optional job/checkpoint → state → database connection. Job-monitor paths acquire job → state → database connection. Lock hold time MUST be minimal; never wrap long disk CoW, VM execution, or network calls inside locks.
8. **Atomically Claim Before Disk File Deletion** — State updates and record removals during deletions/GC must be completed inside the state lock before unlinking files from disk to prevent dangling references or race conditions.
9. **Reflink or Fail** — Space and commit creation must use `cp --reflink=always`. Never fall back to plain file copy on non-CoW filesystems.
10. **Reflog Preserves Explicit Commits** — Automatic cleanup (`gc`) or checkout reflogs must never auto-delete explicit user commits (`auto: false`).
11. **DAG Integrity via Multi-Edge Check** — `is_referenced` MUST check `space.parent`, `space.head`, every commit's `ckpt.parent`, and also the dirty memory base `ckpt.base`. Deleting a commit with child dependencies breaks history chains. The opt-in `rmckpt --detach` (`{"detach":true}`) is the only exception: it refuses on `blocking_references` (`space.head`, template `checkpoint`, `ckpt.base`, which still read the bytes) and clears `parent` edges via `detach_children` inside the same state claim, because each checkpoint image is an independent reflink and `parent` is lineage only.
12. **State Migration Preserves User Data** — SQLite migration (`migrate_from_json`) MUST NOT delete `state.json`. It renames `state.json` to `state.json.migrated` after successful insertion.
13. **Binary Placement** — `shinu-vsock` MUST reside in the same directory as `shinu` (`current_exe()` resolution in `vsock_helper`).
14. **SSH-Banner Readiness Over Vsock** — `wait_ready` checks for VM boot readiness by connecting to vsock port 2222, executing the handshake, and verifying both the `OK ` vsock bridge response and the `SSH-` daemon banner. The vsock CONNECT handshake alone is insufficient.
15. **Sparseness-Preserving Snapshot Merges** — Merging memory snapshots (`merge_snapshot_memory`) must preserve sparseness by calling `written_extents` using `SEEK_DATA`/`SEEK_HOLE` to read and write only modified regions.
16. **iptables Exception Ordering** — TAP interface iptables ACCEPT rules (such as gateway, net allow, and peer /32 exemptions) MUST be placed in position prior to any blanket private CIDR drops.
17. **TAP Name 15-Byte Limit** — TAP interface names must be formatted to fit within the 15-byte Linux kernel limit (`shinu` prefix followed by the first 10 hex characters of the space UUID).
18. **Auth Order Preference** — Bearer token authentication outranks the console session cookie. Falling back to a cookie if an invalid bearer is present is prohibited.
19. **Registration Abuse Protection** — Public console signup checks its per-IP limiter before account creation. It does not throttle authenticated requests.
20. **Snapshot Format Version Is Recorded and Enforced** — Memory checkpoints record `FC_SNAPSHOT_VERSION` (`12.0.0` for v1.18.0). `ensure_snapshot_loadable` refuses mismatches before FC load; fork/checkout/pending restore use the existing disk-only cold-boot path instead, preserving checkpoint files. Bumping FC requires checking upstream `SNAPSHOT_VERSION`. Generation JSON binds captured files, actual FC asset digest, format, lineage, consistency and freeze/pause/thaw timings.
21. **Free Page Reporting Does Not Replace Explicit Reclaim** — Cold boot enables `free_page_reporting` in the `fc.json` balloon object. Measured on a v1.16.1 host: a guest that allocated 500 MiB then freed it drove firecracker RSS 102.7 MiB → 596.9 MiB → 105.0 MiB within 5 seconds with no balloon inflate issued, so reporting does work for the anonymous mappings shinu boots with. `vm::reclaim`'s periodic explicit inflate MUST still be kept: reporting only returns pages the guest kernel puts on its free list, so it does nothing for memory held in guest page cache, which is exactly what the idle sweep's inflate targets via `available_memory`. Reporting is an optimisation layered on the inflate, not a replacement for it.
22. **Data-Sized VM API Calls Get Their Own Deadline** — `vm::api` applies `API_TIMEOUT_SECS` (5s) because a control-plane request that does not answer promptly means a wedged VMM. Snapshot creation is not a control-plane request: its duration scales with guest RAM and disk speed, measured at 5.4s for a 1 GiB guest on NVMe, which sat directly on the old shared deadline and made `commit --full` fail with HTTP 500 while Firecracker went on to write the snapshot successfully. `vm::snapshot` MUST therefore use `api_with_timeout` with `SNAPSHOT_TIMEOUT_SECS`. Any future endpoint whose cost scales with guest size, not VMM latency, MUST do the same rather than widening the shared timeout.
23. **Restore State and Dirty Tracking** — Per-start dirty tracking defaults true; explicit false must force later Diff captures to Full. Loaded VMMs are not admitted running Spaces: start/exec/jobs/commit cannot silently resume them. Preserve pending memory while loading/loaded because vCPUs never executed; once resuming, consume it before clearing the lifecycle record so stale memory can never pair with a modified disk. Daemon restart stops all interrupted generations. See README's loaded-Space contract for read-only inode sharing and cache charging.
24. **Detached Job Lifetime and Output** — Existing `exec` stays synchronous. Detached jobs survive client disconnect/restart only while their admitted VM stays running, refresh idle use, and prevent stop/remove. VM loss yields `lost`. Bound deadlines by the earlier of `SHINU_JOB_MAX_SECS` and Space lease expiry; durable cancellation reuses fence → final capture → archive → cleanup. Archive logs mode 0600, capped at 1 MiB. VM stop uses bounded guest flush then TERM; an unresponsive VMM reports an error rather than receiving SIGKILL. See README's detached-job contract for command, retention and presentation limits.
25. **Space Lease Expiry and Cleanup** — `expires_at` is RFC3339 or `null`; existing and no-TTL spaces never expire. Expired leases reject new start, auto-start, and job requests. Active jobs MUST postpone VM stopping and mutable-space cleanup until their lease-capped cancellation pipeline completes, rather than extending a lease with unbounded guest work. After `SHINU_LEASE_GRACE_SECS` (default `300`), cleanup MUST claim-before-delete only the mutable Space, and a renewal under the Space lock wins. Checkpoints, captured sizing, archived memory-snapshot SSH credentials, and templates MUST remain available for same-project fork after source Space deletion; legacy memory checkpoints without either archived or surviving source keys MUST fail explicitly with HTTP 400.
26. **Immutable Project-Scoped Template References** — A Template is exactly `{name, checkpoint, created_at}` plus project scope. Names MUST be 1–64 lowercase ASCII characters matching `[a-z0-9-]`; invalid or duplicate names return HTTP 400, and missing or foreign checkpoint targets return HTTP 404. List pages MUST be bounded by a name cursor, not by a retained-reference count cap. `template fork` MUST resolve the stored concrete checkpoint UUID and set the destination Space `parent` and `head` to that UUID, with optional TTL support, without requiring the checkpoint's source Space to exist. Fork sizing MUST resolve each checkpoint column first, then a surviving same-project source Space, then image logical size for disk and environment defaults for CPU/memory. Memory forks MUST prefer checkpoint-owned SSH keys, falling back only to surviving source credentials; disk-only forks retain fresh-key authorization. `rmckpt` and GC MUST treat template checkpoint references as live and unlink archived keys with other checkpoint assets only after claiming an unreferenced checkpoint; deleting a template removes only the reference and never checkpoint files. Templates have no tags, updates, renames, sharing, catalogs, or console UI.
