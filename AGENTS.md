# Repository Guidelines

## Project Overview

`shinu` is a multi-tenant sandbox platform designed for AI agents, offering Firecracker microVM execution with git-like version control, copy-on-write (CoW) disk image branching, per-tenant quotas, usage metering, named network namespaces for inter-agent communication, HTTP proxying, a guest desktop environment with a VNC bridge, user accounts, and an MCP server.

A **space** is a named microVM instance tied to an ext4 disk image cloned via CoW (`cp --reflink=always`) from a base rootfs image (e.g. `base-void.ext4`).
`shinu` provides git-like disk versioning: spaces track commit DAGs, support cold/hot commits, history log chains, head checkouts (with auto-commit reflogs), and commit forks.

VMs can run in four guest base images: `void` (default), `ubuntu`, `arch`, and `rocky`. Commits support three snapshot modes: `none`, `full`, and `diff`. A `full` snapshot captures guest memory plus CPU state; a `diff` snapshot captures dirty memory pages relative to a selected full base recorded in the `ckpts.base` field of the database. The platform also supports an image filesystem tree `diff` (entirely distinct from diff memory snapshots) that compares file-level changes between checkpoints or spaces.

Clients interact with `shinud` strictly over HTTP/1.1 using Bearer token authentication or console session credentials. TLS is terminated externally (e.g., via Caddy), while the daemon listens on loopback. The daemon proxies execution (`exec`) via SSH over `vsock`, streaming output as chunked NDJSON, so client processes need no direct access to host filesystem paths or special group memberships (such as `kvm`). Additionally, an MCP server (`shinu-mcp`) exposes the platform's control surface over standard I/O JSON-RPC 2.0 (using line-delimited stdio). The web console dashboard (build-free, framework-free vanilla JS) allows users to register, log in, manage access tokens, and inspect logs.

MicroVM processes are jailed inside unprivileged user/cgroup chroot sandboxes managed via Firecracker's Jailer.

## Architecture & Data Flow

```mermaid
graph TD
  Client[AI Agent / CLI Client] --|HTTPS / Bearer Token| Caddy[Caddy Proxy / TLS Termination]
  Console[Web Console / Console Session] --|HTTPS / Session Cookie| Caddy
  Caddy --|HTTP / Loopback 127.0.0.1:7878| Daemon[shinud daemon]
  MCP[shinu-mcp JSON-RPC] --|shinu client CLI wrapper| Daemon
  Daemon --|SQLite WAL| DB[(<root>/shinu.db)]
  Daemon --|Quota Check & Rate Limiting| Quota[quota module]
  Daemon --|Spawn via Jailer uid 30000| Jailer[jailer exec chroot]
  Jailer --|cgroup v2 & hardlink rootfs/kernel| VM[firecracker microVM]
  Daemon --|SSH over vsock / NDJSON / VNC / Proxy| VM
```

- **Control Plane & Protocol** — `shinud` is a thread-per-connection HTTP/1.1 daemon listening by default on `127.0.0.1:7878` (configured via `SHINU_LISTEN`). Request routing is handled in `src/bin/shinud.rs:2188-2273`, with HTTP method validation enforced in the `method_allowed` matrix at `src/bin/shinud.rs:2428-2467`. The wire format for standard REST actions is JSON. The `exec` action streams NDJSON chunks via `Transfer-Encoding: chunked`, ending with an explicit exit status line `{"exit": N}` (`src/bin/shinud.rs:4669-4785`). `Req::Exec` carries an optional `session: Option<String>` field (`#[serde(default)]`, so existing clients without it are unaffected) supporting persistent shell sessions where builtins (`cd`, `export`) persist across calls.
  Execution spawns host `ssh` using `ProxyCommand=shinu-vsock <uds> 2222`, tunnelled through Firecracker's AF_VSOCK device to an in-guest `socat` listener (`VSOCK-LISTEN:2222`) forwarding to guest `sshd` (`127.0.0.1:22`). VNC connections tunnel through vsock port `2223` (`VSOCK_VNC_PORT` in `crates/shinu-core/src/lib.rs:20`).
  Data transfer uses `exec` `stdin` for pasting text, or `push` (`POST /v1/spaces/{name}/push?path=...`) and `pull` (`GET /v1/spaces/{name}/pull?path=...`) for streaming binary files up to 256 MiB (`MAX_UPLOAD_BYTES` in `crates/shinu-core/src/lib.rs:22`).
  HTTP proxying (`/v1/spaces/{name}/proxy/{port}[/{path}]`) maps requests into guest-exposed TCP ports over vsock.
  Adding an operation requires touching:
  1. `proto::Req` in `crates/shinu-proto/src/proto.rs:16-101`
  2. CLI `Command` enum in `src/bin/shinu.rs:33-177`
  3. HTTP route parser in `src/bin/shinud.rs:2188-2273`
  4. HTTP method validation matrix `method_allowed` in `src/bin/shinud.rs:2428-2467`
  5. `request_for` mapping and `handle()` dispatcher in `src/bin/shinud.rs:2059-2146`
  6. Quota check points (e.g. `check_space_quota`) in `src/bin/shinud.rs:344`
  7. Usage event logging (`state::record_usage`) in `src/bin/shinud.rs`
  8. `shinu-mcp` tool table and arg validator in `src/bin/shinu-mcp.rs:873-1004` (if exposing to MCP)
  9. Web console `src/console/app.js` UI routes (if console-exposed)

- **Identity & Project Tenant Isolation** — Authentication uses either `Authorization: Bearer <token>` or console session cookies. A Bearer token is always authoritative when present. Tokens map to a **project** name (`crates/shinu-crypto/src/token.rs`). Tokens are stored in `<root>/tokens.json` (mode `0600`) as SHA-256 hashes (`crates/shinu-crypto/src/token.rs:62`) and compared in constant time (`crates/shinu-crypto/src/token.rs:70`, reached from `authenticate` at `crates/shinu-crypto/src/token.rs:85`). Users register and authenticate through the console UI, writing passwords hashed with PBKDF2-HMAC-SHA256 (210,000 iterations, 32-byte salt) to the database, which grants user sessions. Project isolation is strict: spaces, commits, quotas, and usage records belong to a project. Cross-project lookups return `NotFound` (404) to avoid leaking existence.

- **Jailer Sandbox Isolation** — `vm::start` (`crates/shinu-vm/src/vm.rs:988`) launches Firecracker microVMs inside jailer chroot sandboxes (`/usr/bin/jailer`). Process credentials drop to unprivileged `shinu-jail` user/group (`SHINU_JAIL_UID` / `SHINU_JAIL_GID`, default 30000). cgroup v2 resource limits are enforced on each sandbox (`memory.max=<mem>M`, `pids.max=512`). Kernel (`assets/vmlinux`) and rootfs images are hardlinked into the chroot tree at `<root>/jail/firecracker/<uuid>/root/` (`link_resource` in `crates/shinu-vm/src/vm.rs:920-935`).

- **Quotas & Throttling** — Resource ceilings and request throttling are enforced per project (`crates/shinu-store/src/quota.rs`). Limits default to 5 spaces, 10240 MiB disk, 16 vCPUs, 32768 MiB memory, 2 running VMs, and 120 API requests/min (`SHINU_LIMIT_*` env overrides, per-project overrides stored in `projects` table). Throttling uses a 60-second sliding window with automatic expired entry pruning. Exceeding quota or rate limits yields HTTP **429 Too Many Requests** (`Error::Quota`). Rate limiting is evaluated *before* state or database locks are acquired.

- **State Storage & Indexing** — SQLite in WAL mode (`<root>/shinu.db`, mode `0600`) manages state. Database schema (`crates/shinu-store/src/state.rs:70-135`) consists of eight tables:
  - `spaces`: microVM metadata, parent commit, current head, sizing (vcpus, mem_mib, disk_mib), network name, and creation time.
  - `ckpts`: commit records, including auto-commits, full snapshot flag, parent/base commit UUIDs, and `snapshot_version` (nullable; the Firecracker snapshot data format version the guest memory state was captured with, `NULL` for disk-only commits and for commits written before the column existed).
  - `projects`: project-scoped resource limit overrides.
  - `usage_events`: metered usages (disk_mib_hour, vm_seconds, api_call, space_created).
  - `users`: user emails, password hashes, and registration timestamps.
  - `memberships`: maps users to projects with roles.
  - `sessions`: session IDs, user IDs, and expiration times.
  - `sqlite_sequence`: internal autoincrement tracking.
  
  Indexes (`crates/shinu-store/src/state.rs:129-134`):
  - `spaces(project, name)`
  - `ckpts(project)`
  - `ckpts(space)`
  - `usage_events(project, "at")`
  - `sessions(user_id)`
  - `memberships(project)`

- **Usage Metering** — Metering events are captured in the `usage_events` table. A background sweep thread runs every `USAGE_SAMPLE_SECS` (30 seconds) to record `vm_seconds` and `disk_mib_hour` metrics, and purges expired sessions.

- **Concurrency & Locking Discipline** — `shinud` uses thread-per-connection concurrency with `shinu_store::registry::Registry` (`crates/shinu-store/src/registry.rs`). Locking follows a multi-tier model:
  1. Per-space lock (`Arc<Mutex<()>>` via `Registry::space_lock`): serializes long-running VM operations (start, stop, commit, checkout) on a single space.
  2. Global state lock (`Registry::state_lock`): serializes SQLite transactions and state modifications.
  3. Database connection lock (`Mutex<Connection>`): serializes SQLite access.
  
  **Lock Order Invariant**: Always acquire space lock FIRST, then state lock SECOND. Never hold locks across long disk CoW or network/VM execution operations.

## Key Directories

| Path | Purpose |
|---|---|
| `crates/shinu-core/` | Low-level common types and constants: `Error`, `Result`, `Image` enum, path resolution, base layout initialisation, Btrfs CoW helpers, and SSH proxy vsock banner parsing (`crates/shinu-core/src/lib.rs`). |
| `crates/shinu-store/` | State management: SQLite schemas and migrations (`state.rs`), lock registry (`registry.rs`), commit DAG logic (`chain.rs`), and quota checks and rate limiting (`quota.rs`). |
| `crates/shinu-crypto/` | Cryptographic functions: authentication algorithms (`auth.rs`), SHA-256 implementation (`sha2.rs`), and token verification (`token.rs`). |
| `crates/shinu-image/` | Distribution assets: base image building (`build.rs`), OCI fetching (`fetch.rs`), guest network configuration (`configure.rs`), tree diffing (`diff.rs`), and extraction (`extract.rs`). |
| `crates/shinu-vm/` | Execution harness: VM sandbox launcher and state probe (`vm.rs`), network TAP and IP/iptables bridge config (`net.rs`), and VM configuration (`config.rs`). |
| `crates/shinu-proto/` | Wire protocol: HTTP request parsing and responses (`http.rs`) and serialization models (`proto.rs`). |
| `src/lib.rs` | Re-export facade mapping the six workspace crates into a single flat namespace for binaries (`src/lib.rs`). |
| `src/bin/shinu.rs` | Client CLI: Clap CLI parsing, stream parsing, and local token generation (`src/bin/shinu.rs`). |
| `src/bin/shinud.rs` | Control daemon: Route handlers, connection loop, console auth, CSRF pre-checks, and GC (`src/bin/shinud.rs`). |
| `src/bin/shinu-mcp.rs` | MCP Server: Line-delimited JSON-RPC 2.0 interface providing 15 tools for agents (`src/bin/shinu-mcp.rs`). |
| `src/bin/shinu-vsock.rs`| Stdio-to-vsock bridge helper used as SSH ProxyCommand (`src/bin/shinu-vsock.rs`). |
| `src/console/` | Web Console: Framework-free frontend dashboard (`index.html`, `auth.html`, `app.js`, `app.css`). |
| `site/` | Astro-based marketing and documentation site. |
| `packaging/` | Runit configuration (`sv/shinud/run`), reverse proxy config (`caddy/Caddyfile`), and the target installation script (`install.sh`). |

Runtime layout (`crates/shinu-core/src/lib.rs:359-374` `init_layout`):

```
<root>/tokens.json                 0600    hashed Bearer tokens
<root>/shinu.db                    0600    SQLite database (spaces, ckpts, projects, usage_events, etc.)
<root>/state.json.migrated         0600    backup of migrated legacy state JSON (if migrated)
<root>/base-void.ext4              0644    golden base disk image for Void
<root>/spaces/                     0700    dir; space CoW disk images (<id>.ext4)
<root>/ckpts/                      0700    dir; immutable commit disk images (<id>.ext4, <id>.mem, <id>.state)
<root>/vm/<uuid>/                  0700    dir; VM host-side assets: last_used, id_ed25519
<root>/jail/firecracker/<uuid>/    0700    dir; jailer chroot root: root/ (fc.json, fc.sock, vsock.sock, firecracker.pid)
<root>/assets/                     0755    firecracker binary + vmlinux kernel
<root>/cache/                      0755    downloaded rootfs tarballs
```

## Development Commands

```sh
cargo build                          # debug build
cargo build --release                # release build expected by packaging/install.sh
cargo test --workspace               # run full cargo workspace test suite (217 passed)
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
shinu new web --image void           # create space with void image (alternatives: ubuntu, arch, rocky)
shinu resize web --vcpus 4 --mem 2048 # resize CPU or memory allocations (must be stopped)
shinu exec web -- uname -a           # execute command over HTTP chunked stream
shinu commit web --note "v1"         # create cold commit (space must be stopped)
shinu commit web --note "hot" --hot  # create hot commit while running
shinu log web                        # show commit history DAG
shinu reflog web                     # show full reflog history
shinu checkout web <commit-uuid>     # checkout commit (creates auto-commit reflog)
shinu fork <commit-uuid> web-branch  # fork commit into a new space
shinu stop web                       # stop microVM
shinu rm web                         # delete space
shinu rmckpt <commit-uuid>           # delete commit (refused if referenced)
shinu gc --free-below 10737418240    # run garbage collection
shinu usage                          # show project resource usage summary
shinu limits                         # show project resource quota limits
shinu limits set demo --spaces 10    # change resource limits (admin token required)
shinu desktop web                    # launch and hook up guest X11 desktop environment
shinu vnc web --port 5901            # connect to GUI desktop via VNC bridge
shinu proxy web 8080 --path /api     # proxy host requests into guest port 8080
```

HTTP API usage via `curl`:

```sh
# Query project quota limits
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
- `new <name> [--image <img-id>] [--vcpus <n>] [--mem <mib>] [--disk <mib>] [--network <name>]`
- `resize <space> [--vcpus <n>] [--mem <mib>] [--disk <mib>]`
- `images`
- `ls [--json]`
- `network <name>`
- `rm <space>`
- `start <space>`
- `stop <space>`
- `desktop <space>`
- `vnc <space> [--port <port>]`
- `proxy <space> <port> [--path <path>]`
- `exec <space> [--session <id>] [--stdin <file>] -- <cmd...>`
- `push <space> <local-file> <guest-path>`
- `pull <space> <guest-path> <local-file>`
- `commit <space> --note <note> [--hot] [--full|--diff]`
- `log <space> [--json]`
- `reflog <space> [--json]`
- `diff <source> [target] [--all] [--limit <n>]`
- `checkout <space> <commit-uuid>`
- `fork <commit-uuid> <name>`
- `rmckpt <commit-uuid>`
- `gc --free-below <bytes> [--dry-run]`
- `usage [--from <ts>] [--to <ts>] [--json]`
- `limits [set <project> --spaces <n> --disk-mib <mib> --running <n> --api-per-min <n> --inherit <list>] [clear <project>] [--json]`
- `token new --project <project> | ls | rm <hash-prefix>`

## Code Conventions & Common Patterns

- **Quota Check Before Mutation Inside State Lock** — Space and disk quota calculations (`quota::check_space_limit` / `check_disk_limit`) MUST be evaluated atomically inside `update_state_with_quota` before applying database writes. Performing quota checks outside the state lock allows concurrent requests to race past tenant ceilings.
- **Strict Separation of Disk Measurement Metrics** —
  - Quota capacity enforcement uses `btrfs::exclusive` to calculate **instantaneous physical disk usage**.
  - Usage billing tracking uses `disk_mib_hour` in `usage_events` as a **cumulative time series**.
  Do NOT use billing time-series totals for quota capacity checks; doing so causes long-running tenants with small disk footprints to be incorrectly rejected after accumulating historical hours.
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
  - `SHINU_ADMIN_TOKEN`: Deployment admin secret gating `/v1/projects/{project}/limits`; unset fails closed (`src/bin/shinud.rs:84-88`).
  - `SHINU_REFLOG_DAYS`: Reflog auto-commit retention in days (default `7`).
  - `SHINU_SESSION_DAYS`: Console user session expiration in days (default `7`).
  - `SHINU_FULL_EVERY`: Per-base diff cap on the auto degradation path (default `8`, `0` disables).
  - `SHINU_VCPUS`: VM vCPU count (default `2`).
  - `SHINU_MEM_MIB`: VM memory limit in MiB (default `1024`).
  - `SHINU_IDLE_SECS`: Idle timeout before VM shutdown (default `3600`).
  - `SHINU_DISK_MIB`: Base disk size in MiB, read on base build (default `2048`).
  - `SHINU_JAIL_UID`: Unprivileged jailer UID (default `30000`).
  - `SHINU_JAIL_GID`: Unprivileged jailer GID (default `30000`).
  - `SHINU_LIMIT_SPACES`: Max spaces per project (default `5`).
  - `SHINU_LIMIT_DISK_MIB`: Max disk MiB per project (default `10240`).
  - `SHINU_LIMIT_RUNNING`: Max running VMs per project (default `2`).
  - `SHINU_LIMIT_VCPUS`: Max vCPUs per space (default `16`, `crates/shinu-store/src/quota.rs:42`).
  - `SHINU_LIMIT_MEM_MIB`: Max memory MiB per space (default `32768`, `crates/shinu-store/src/quota.rs:43`).
  - `SHINU_LIMIT_API_PER_MIN`: Max API requests per minute per project (default `120`).
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
  - Client side: `SHINU_ENDPOINT`, `SHINU_TOKEN`.
- **Concurrency & Lock Order Discipline** —
  1. Space lock first, state lock second. Never lock state then space.
  2. Lock hold scope must be minimal. Do NOT hold state or database locks during btrfs disk operations, subprocess spawning, or network calls.
- **Claim-before-Delete Pattern (GC & Mutation Discipline)** —
  When modifying shared state and deleting disk files (e.g. during `gc` or commit deletion), atomically claim the record under state lock first (re-verify conditions and remove entry from database), release lock, and then delete files on disk.
- **Automatic Snapshot Degradation Semantics** —
  - A `--full` commit request automatically degrades to Diff when a valid full ancestor exists (`full=1`, same space, `.mem` and `.state` present on disk, `snapshot_version == FC_SNAPSHOT_VERSION`).
  - Ancestor lookup walks back to the nearest *valid* full ancestor, skipping invalid ones rather than stopping at the first full. Stopping at the first full would force Full forever after a single stale pre-upgrade entry, which is exactly what the feature exists to prevent. This is safe because a diff restores from precisely the commit recorded in `ckpts.base` so intervening commits are never consulted.
  - `SHINU_FULL_EVERY` caps the number of diffs hanging off one base on the auto path. When exceeded, the next auto commit becomes a new full base. An explicit `--diff` bypasses the cap and errors only when no valid base exists. Auto degradation only ever moves Full to Diff, never Diff to Full.

## Important Files

- `crates/shinu-store/src/state.rs:204` `state::open` — Opens `shinu.db` SQLite connection with WAL mode and foreign key constraints.
- `crates/shinu-store/src/state.rs:317` `state::migrate_from_json` — Imports legacy `state.json` into SQLite database and renames original file to `state.json.migrated`.
- `crates/shinu-store/src/quota.rs` — Resource limits (`Limits`), rate limiter (`RateLimiter`), and quota check functions.
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

- Total test count: **217 passed tests, 0 failed** across modules and binaries:
  - `src/lib.rs`: 1 facade test (`vsock_handshake_leaves_payload_for_caller`)
  - `src/bin/shinu.rs`: 12 client CLI logic tests
  - `src/bin/shinud.rs`: 57 integration handler, proxy routing, console auth, snapshot-format gate, and dispatch tests
  - `src/bin/shinu-mcp.rs`: 4 MCP JSON-RPC protocol and tool validation tests
  - `crates/shinu-core`: 6 core helper tests
  - `crates/shinu-crypto`: 19 crypto hashing, PBKDF2 password derivation, and token authenticity tests
  - `crates/shinu-image`: 22 OCI pulling, extraction, network resolver filtering, and tree diffing tests
  - `crates/shinu-proto`: 26 HTTP parsing and response framing tests
  - `crates/shinu-store`: 44 SQLite database operations, quota calculations, rate limit sliding window, and cycle-resilient DAG walk tests
  - `crates/shinu-vm`: 26 network IP derivations, iptables egress rule placement, VM jail layout, and snapshot-load body tests
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
3. **Atomic Quota Check Inside State Lock** — Space and disk usage checks MUST be executed inside `update_state_with_quota` under the global state lock prior to performing database writes.
4. **Instantaneous vs. Cumulative Disk Measurement** — Disk quota capacity enforcement MUST use `btrfs::exclusive` instantaneous calculations. Billing time-series totals (`disk_mib_hour`) MUST NEVER be used for quota checks.
5. **Project Tenant Isolation Never Leaks Existence** — Lookups filter strictly by token project name and return `NotFound` (404). A space or commit belonging to another project is indistinguishable from a nonexistent entity.
6. **Tokens are Stored as Hashes & Compared in Constant Time** — Token plaintexts are never persisted; `<root>/tokens.json` stores SHA-256 hashes. Token validation uses `constant_time_eq` to prevent timing side-channel attacks.
7. **Strict Multi-Tier Lock Order** — Space lock first, state lock second. Lock hold time MUST be minimal; never wrap long disk CoW, VM execution, or network calls inside locks.
8. **Atomically Claim Before Disk File Deletion** — State updates and record removals during deletions/GC must be completed inside the state lock before unlinking files from disk to prevent dangling references or race conditions.
9. **Reflink or Fail** — Space and commit creation must use `cp --reflink=always`. Never fall back to plain file copy on non-CoW filesystems.
10. **Reflog Preserves Explicit Commits** — Automatic cleanup (`gc`) or checkout reflogs must never auto-delete explicit user commits (`auto: false`).
11. **DAG Integrity via Multi-Edge Check** — `is_referenced` MUST check `space.parent`, `space.head`, every commit's `ckpt.parent`, and also the dirty memory base `ckpt.base`. Deleting a commit with child dependencies breaks history chains.
12. **State Migration Preserves User Data** — SQLite migration (`migrate_from_json`) MUST NOT delete `state.json`. It renames `state.json` to `state.json.migrated` after successful insertion.
13. **Binary Placement** — `shinu-vsock` MUST reside in the same directory as `shinu` (`current_exe()` resolution in `vsock_helper`).
14. **SSH-Banner Readiness Over Vsock** — `wait_ready` checks for VM boot readiness by connecting to vsock port 2222, executing the handshake, and verifying both the `OK ` vsock bridge response and the `SSH-` daemon banner. The vsock CONNECT handshake alone is insufficient.
15. **Sparseness-Preserving Snapshot Merges** — Merging memory snapshots (`merge_snapshot_memory`) must preserve sparseness by calling `written_extents` using `SEEK_DATA`/`SEEK_HOLE` to read and write only modified regions.
16. **iptables Exception Ordering** — TAP interface iptables ACCEPT rules (such as gateway, net allow, and peer /32 exemptions) MUST be placed in position prior to any blanket private CIDR drops.
17. **TAP Name 15-Byte Limit** — TAP interface names must be formatted to fit within the 15-byte Linux kernel limit (`shinu` prefix followed by the first 10 hex characters of the space UUID).
18. **Auth Order Preference** — Bearer token authentication outranks the console session cookie. Falling back to a cookie if an invalid bearer is present is prohibited.
19. **Rate Limiting Before State Locks** — Rate limits MUST be checked before acquiring state or database locks to prevent denial of service (DoS) attacks from locking resources.
20. **Snapshot Format Version Is Recorded and Enforced** — A commit carrying guest memory state MUST record the Firecracker snapshot data format version it was captured with (`ckpts.snapshot_version`, stamped from `shinu_core::FC_SNAPSHOT_VERSION`). Restore MUST call `ensure_snapshot_loadable` (`src/bin/shinud.rs:781`) and refuse a mismatch with `Error::Invalid` (HTTP 400) rather than letting `PUT /snapshot/load` fail opaquely, and MUST NOT delete the commit's files on refusal — its disk image stays usable. Bumping `FC_VERSION` REQUIRES re-reading `SNAPSHOT_VERSION` in upstream `src/vmm/src/persist.rs` (or running `firecracker --snapshot-version`) and bumping `FC_SNAPSHOT_VERSION` to match; the format went `8.0.0` to `10.0.0` between v1.13.1 and v1.16.1.
21. **Free Page Reporting Does Not Replace Explicit Reclaim** — Cold boot enables `free_page_reporting` in the `fc.json` balloon object. Measured on a v1.16.1 host: a guest that allocated 500 MiB then freed it drove firecracker RSS 102.7 MiB → 596.9 MiB → 105.0 MiB within 5 seconds with no balloon inflate issued, so reporting does work for the anonymous mappings shinu boots with. `vm::reclaim`'s periodic explicit inflate MUST still be kept: reporting only returns pages the guest kernel puts on its free list, so it does nothing for memory held in guest page cache, which is exactly what the idle sweep's inflate targets via `available_memory`. Reporting is an optimisation layered on the inflate, not a replacement for it.
22. **Data-Sized VM API Calls Get Their Own Deadline** — `vm::api` applies `API_TIMEOUT_SECS` (5s) because a control-plane request that does not answer promptly means a wedged VMM. Snapshot creation is not a control-plane request: its duration scales with guest RAM and disk speed, measured at 5.4s for a 1 GiB guest on NVMe, which sat directly on the old shared deadline and made `commit --full` fail with HTTP 500 while Firecracker went on to write the snapshot successfully. `vm::snapshot` MUST therefore use `api_with_timeout` with `SNAPSHOT_TIMEOUT_SECS`. Any future endpoint whose cost scales with guest size, not VMM latency, MUST do the same rather than widening the shared timeout.
23. **Dirty-Page Tracking on Snapshot Restore** — A snapshot restore MUST send `"track_dirty_pages": true` in the `PUT /snapshot/load` body because Firecracker rebuilds the dirty-page bitmap from the load request and does not inherit it from the snapshot; cold boot sets the same flag in `fc.json` via `crates/shinu-vm/src/config.rs`. Omitting it silently leaves a restored VM with no dirty tracking so every later diff becomes a full memory dump (measured 268.2 / 270.1 / 267.8 MiB on an idle restored guest, versus 8.2 and 8.0 MiB after the fix). The first diff after a restore is legitimately large (measured 269.5 MiB) because the bitmap starts empty and every page touched during restore counts dirty, converging from the second diff on. Firecracker's `SnapshotLoadParams` exposes `track_dirty_pages` with `enable_diff_snapshots` as its deprecated alias; shinu uses the current name.
