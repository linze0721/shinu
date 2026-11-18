shinu
=====

[![CI](https://github.com/linze0721/shinu/actions/workflows/ci.yml/badge.svg)](https://github.com/linze0721/shinu/actions/workflows/ci.yml) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Agent-first Firecracker microVM sandboxes with copy-on-write disk states, detached jobs, and git-like snapshot, rollback, and branching workflows.

A **space** is an ext4 guest disk image cloned from a golden base via btrfs reflink, bound to an isolated Firecracker microVM instance. `shinu exec <space> [--stdin <file>] [--session <id>] -- <cmd...>` boots the VM on demand (~1.7 s cold), runs the command over host `ssh` with `shinu-vsock` as `ProxyCommand`, tunnelled through Firecracker's AF_VSOCK device to an in-guest `socat` listener (`VSOCK-LISTEN:2222`) forwarding to guest `sshd` (`127.0.0.1:22`), leaving the VM warm for subsequent calls (~0.4 s hot). Command execution travels strictly over vsock rather than host network interfaces, keeping the guest firewalled from host networks while remaining reachable. Idle VMs release unused host memory via virtio-balloon and shut down automatically after an idle threshold.

`shinud` exposes an HTTP/1.1 REST API where spaces support git-like operation semantics:
- **Four Guest Images**: Selectable guest bases per space (void, ubuntu, arch, rocky).
- **Sizing & Resize**: Per-space vCPU, memory, and disk capacity limits configuration, with offline resize.
- **Named Networks**: Opt-in named network segments allowing direct space-to-space communication.
- **VM Snapshots**: Support for `none`, `full` (memory and CPU state), and `diff` (dirty memory pages relative to a base commit) snapshots.
- **Guest Desktop via VNC**: Desktop environment reachable over VNC (vsock port 2223).
- **HTTP Proxying**: Transparent reverse proxying from host paths to guest ports.
- **Web Console**: An administrative dashboard for user registration, login, and bearer token creation.
- **MCP Server**: Model Context Protocol (MCP) tool integration for programmatic access by agents.
- **Detached Jobs**: Run commands asynchronously with `shinu job run`; inspect status and terminal-rendered logs, wait, or cancel through the CLI, REST API, or MCP. The active-job cap is 64 per project. Jobs default to a 3600-second wall-clock limit, shortened by their host Space lease.
- **Space Leases**: Optional TTLs expose an expiry as RFC3339 data or `null`; spaces without a TTL never expire. Expiry cancels active jobs through their normal final-log pipeline before stopping and cleaning the mutable Space after a grace period; retained checkpoints and templates remain forkable without the source Space.
- **Named Checkpoint Templates**: Immutable, project-scoped names point to concrete checkpoint UUIDs for reuse. Names are 1–64 characters matching `[a-z0-9-]`; at most 256 retained references are allowed per project and 2048 globally, and creation over either cap returns 429. Deleting a template removes only the reference, never checkpoint files. There are no tags, updates, renames, sharing, catalogs, or console UI.
- **`commits`**: CoW ext4 disk state snapshots (`hot` or cold, optionally with memory).
- **`checkout`**: Rewinds space state back to any commit, automatically saving current state before rewind (reflog semantics).
- **`fork`**: Creates new independent spaces branching off any existing commit.
---

## Quick Start

### 1. Build and Install

Build the fork archive described under “Firecracker v1.18 rollout” first. This branch requires the allowlisted `Firecracker v1.18.0-shinu.2` build, whose block flush failures abort snapshot creation; it never downloads stock Firecracker as a fallback.

```sh
cargo build --release
./packaging/install.sh              # Default PREFIX=/usr/local
install -D -m 0600 firecracker-v1.18.0-shinu.2-x86_64.tgz /var/lib/shinu/cache/firecracker-v1.18.0-shinu.2-x86_64.tgz
ln -s /etc/sv/shinud /var/service/  # Enable runit service (or launch manually as root)
```

> **Note:** `shinu-vsock` must reside in the same directory as `shinu` (resolved via `current_exe()`). `install.sh` sets this up automatically.

### 2. Start Service & Mint Bearer Token

Start `shinud` (must run as `root`):

```sh
SHINU_LISTEN=127.0.0.1:7878 shinud --root /var/lib/shinu
```

`shinud` takes only `--root`; the listen address is environment-only.

Mint a bearer token for a project using the host-local CLI tool (requires root access to `<root>/tokens.json`):

```sh
# shinu token subcommands operate directly on local storage (no HTTP network call)
shinu token new --project demo
```

Output:
```text
token: shinu_tok_xxxxxxxxxxxxxxxxxxxxxxxx
```

### 3. Environment Setup & CLI Usage

Set client environment variables:

```sh
export SHINU_ENDPOINT="http://127.0.0.1:7878"
export SHINU_TOKEN="shinu_tok_xxxxxxxxxxxxxxxxxxxxxxxx"
```

Run agent sandbox workflows via CLI:

```sh
# List available guest images
shinu images
# Create a space with sizing, custom image, named network, and a lease
shinu new web --image ubuntu --vcpus 4 --mem 2048 --disk 4096 --network backend-lan --ttl 2h

# Resize space resources (requires space to be stopped; disk can only grow)
shinu stop web
shinu resize web --vcpus 2 --mem 1024 --disk 8192

# Execute command inside VM (boots on demand)
shinu exec web -- uname -a           # synchronous command; streams chunked NDJSON
# Run a detached job; this returns a job ID without waiting for completion
shinu job run web -- sh -c 'echo started; sleep 5; echo done'
shinu job ls
shinu job status <job-uuid>
shinu job logs <job-uuid>
shinu job wait <job-uuid>
# Request cancellation for a running job
shinu job cancel <job-uuid>


# Pass stdin to guest command via exec
shinu exec web --stdin input.txt -- grep -i "pattern"

# Persistent session: builtins and environment persist across calls
shinu exec web --session s1 -- cd /tmp
shinu exec web --session s1 -- pwd                # /tmp
shinu exec web --session s1 -- export FOO=bar123
shinu exec web --session s1 -- echo $FOO          # bar123

# Explicit child processes do not modify the session environment
shinu exec web --session s1 -- sh -c "export BAR=nope"
shinu exec web --session s1 -- echo $BAR          # (empty)

# Omitting --session retains stateless behavior (default cwd /root)
shinu exec web -- pwd                             # /root
# Session IDs allow ASCII alphanumeric, '_', and '-' (max 64 chars); session lifetime matches the VM.

# Push a local file directly to a guest path
shinu push web local_config.json /etc/app/config.json

# Pull a guest file to a local destination
shinu pull web /var/log/app.log local_app.log

# List project spaces and commits
shinu ls

# Save a commit snapshot (snapshot: none, full, or diff; hot or cold)
shinu commit web --note "installed packages" --full
shinu commit web --note "hot snapshot" --hot --diff

# View commit history chain and reflog entries
shinu log web
shinu reflog web

# Compare filesystems (tree diff) between space/commit states
shinu diff web --all --limit 500

# Checkout rewinds space state (automatically creates an auto-commit reflog first)
shinu checkout web <commit-uuid>

# Branch off a commit into a new space
shinu fork <commit-uuid> web-experiment --ttl 30m
# Name a checkpoint with an immutable project-scoped template (up to 256 retained refs/project, 2048 global; over-cap create returns 429)
shinu template create baseline <commit-uuid>
shinu template ls

# Fork the template's concrete checkpoint into a new space
shinu template fork baseline template-demo --ttl 30m

# Remove only the template reference; the checkpoint remains
shinu template rm baseline

# Set or clear a space lease; DURATION uses N{s|m|h|d}
shinu lease web --ttl 2h
shinu lease web --clear

# VNC tunnel setup: start the desktop services and proxy VNC
shinu desktop web
shinu vnc web --port 5901

# Reverse-proxy an HTTP port inside the guest to a local host port
shinu proxy web 8080 --path /api

# Manage named networks
shinu network backend-lan

# Delete an unreferenced commit (template references count as references)
shinu rmckpt <commit-uuid>
# Delete a commit and clear space/commit parent links to it; heads, templates, and memory bases still refuse
shinu rmckpt --detach <commit-uuid>

# Stop VM and flush disk writes
shinu stop web

# Garbage collect unreferenced commits; template targets remain pinned
shinu gc --free-below 10737418240 --dry-run
```
The CLI `--ttl` and `lease --ttl` duration grammar is `N{s|m|h|d}`.

---

## Model Context Protocol (MCP) Server

Shinu features a Model Context Protocol (MCP) server integration implemented in the `shinu-mcp` binary. This enables LLM agents to programmatically control and interact with sandboxes.

### Execution
`shinu-mcp` runs as a line-delimited JSON-RPC 2.0 server over standard input and output (`stdio`). It authenticates against `shinud` using client configuration environment variables:
* `SHINU_ENDPOINT`: The `shinud` HTTP endpoint (must use `http://`, e.g., `http://127.0.0.1:7878`; `https://` is rejected).
* `SHINU_TOKEN`: A valid API bearer token.

### Tools exposed by `shinu-mcp`
* `shinu_list_spaces`: Lists all spaces in the current project namespace including name, status, disk allocation, and active HEAD commit.
* `shinu_list_images`: Lists the four available base guest distributions (`void`, `ubuntu`, `arch`, `rocky`) and their sizes.
* `shinu_create_space`: Creates a new named space. Custom `vcpus`, `mem_mib`, `disk_mib`, `image`, and `network` name can be optionally passed, along with optional `ttl_seconds`.
* `shinu_resize_space`: Resizes an existing space's `vcpus`, `mem_mib`, or `disk_mib` (requires space to be stopped).
* `shinu_start`: Starts a stopped space VM instance.
* `shinu_stop`: Shuts down a running space VM, flushing guest cache and reclaiming memory.
* `shinu_write_file`: Surgical text-only file write to an absolute path inside the space guest.
* `shinu_read_file`: Reads text contents of a guest file by absolute path.
* `shinu_exec`: Synchronously executes a command inside the guest, returning aggregated stdout, stderr, and the exit code.
* `shinu_run_job`: Starts a detached command in a space and returns its job ID.
* `shinu_list_jobs`: Lists detached jobs in the current project.
* `shinu_job_status`: Returns a detached job's lifecycle state and metadata.
* `shinu_job_logs`: Returns the job's terminal-rendered log text.
* `shinu_cancel_job`: Requests cancellation of a detached job.
* `shinu_commit`: Creates an immutable commit checkpoint. Allows specifying `hot: true/false` and snapshot mode (`none`, `full`, `diff`).
* `shinu_log`: Returns the linear HEAD git-like commit log chain of checkpoints for the space.
* `shinu_reflog`: Returns the reflog commit list, containing discarded checkout checkpoints for recovery.
* `shinu_checkout`: Rolls back the space's disk image to the state of a specified commit (automatically stops VM and saves current state to reflog).
* `shinu_fork`: Creates a new independent space cloned from an immutable commit checkpoint; optional `ttl_seconds` can be passed.
- `shinu_create_template`: Creates an immutable project-scoped Template from a full checkpoint UUID (`name`, `checkpoint`); returns the serialized Template. Creation over the 256-per-project or 2048-global retention cap returns quota 429.
- `shinu_list_templates`: Lists project templates with no arguments as `{"templates":[...]}`, bounded to the project's 256 retained-reference cap.
- `shinu_delete_template`: Deletes a template by `name`; returns `{"removed":"...","checkpoint":"..."}` and removes only the reference.
- `shinu_fork_template`: Forks a template into a destination space (`template`, `name`, optional nullable-positive `ttl_seconds`); returns the serialized Space with concrete UUID `parent` and `head`.
* `shinu_set_space_lease`: Sets or clears a space lease; `ttl_seconds` is a positive integer or `null`.
* `shinu_delete_space`: Deletes a space and unlinks its image and VM configurations (refuses if running).

> **Design Limitations**: Binary transfers (`push`, `pull`), GC operations (`gc`), usage queries (`usage`), limits modification (`limits`), desktop toggling (`desktop`), reverse proxying (`proxy`), and VNC bridges (`vnc`) are deliberately **not** exposed over MCP. Detached jobs have no follow or raw log modes, force-stop, reboot survival, artifacts, or web-console controls.

---

## Web Console

`shinud` serves a static, framework-free Web Console directly at `/`, `/login`, `/register`, and `/app` along with stylesheet assets `/assets/app.css` and `/assets/app.js`.

- **Access & Security**: Authenticates using same-origin cookie credentials (`shinu_session`). Password registration requires at least 12 characters, and passwords are hashed using PBKDF2-HMAC-SHA256 (210,000 iterations). 
- **CSRF Protection**: State-changing console routes enforce strict CSRF origin verification on request headers (`Origin` and `Host` matching/validation).
- **Token Management**: The console allows the user to view, mint (generating 32-byte `/dev/urandom` lower-hex tokens), and delete API bearer tokens.
- **Read-Only Context**: Apart from registration, login, logout, and token administration, the console is strictly read-only; it displays project resource usages, limits, space tables, space logs, and lease expiry as read-only data, but does not allow VM lifecycle, command execution, commit modifications, or detached-job controls.

---

## Requirements

Run `packaging/preflight.sh [root-path]` on a candidate host before installing; it checks everything below and exits non-zero naming the specific reason.

- **Hardware virtualisation.** `/dev/kvm` must exist and the CPU must expose `vmx` or `svm`. On bare metal this means VT-x/AMD-V enabled in firmware; on a VPS it means the provider offers nested virtualisation. Most shared VPS plans do not.
- **Reflink-capable filesystem.** The `--root` directory must be on btrfs (or reflink-capable xfs). Spaces are cloned with `cp --reflink=always`, which is what keeps a clone 0 bytes exclusive; a plain copy is never substituted, so any other filesystem fails loudly at space creation.
- **`/dev/vhost-vsock`.** `exec` tunnels over AF_VSOCK, so without the `vhost_vsock` module no command can reach a guest.
- `x86_64` CPU architecture. The guest kernel and Firecracker v1.16.1 binaries are fetched automatically on first boot. The kernel comes from the `firecracker-ci/v1.15` bucket (`vmlinux-6.1.155`) because upstream publishes no `v1.16` CI kernel.
- External binaries required on host: `curl tar mkfs.ext4 e2fsck mount umount truncate ssh ssh-keygen setsid cp chown btrfs df kill ip iptables unshare debugfs losetup`.
- Offline `shinu compact` additionally requires `fstrim`.
- `shinud` daemon **must run as root** to create loop devices, configure NAT network interfaces (`iptables`), and set up tap devices.
- `net.ipv4.ip_forward` must be enabled for guest egress, and cgroup v2 must be mounted for the jailer's resource limits.
- HTTP clients run non-root and require no host group memberships (specifically no `/dev/kvm` or root access required).

---

## Production Deployment & Multi-Tenancy

For multi-tenant hosting, microVM sandboxes require strict isolation, host capacity admission, and TLS termination.

### 1. Jailer Sandboxing (Mandatory Security)
`shinud` executes Firecracker instances inside the Firecracker **jailer** sub-process (`<root>/assets/jailer`), providing:
 **Chroot jail**: MicroVM filesystem root isolated under `<root>/jail/firecracker/<uuid>/root`. Kernel and ext4 space images are hardlinked into the jail.
 **Privilege dropping**: MicroVM process runs under non-root UID/GID (default `30000`).
 **cgroup v2 isolation**: Enforces a host memory ceiling of guest RAM plus `SHINU_VMM_OVERHEAD_MIB` (default 512 MiB) via `memory.max`, and process caps (`cgroup pids.max=512`). The allowance covers Firecracker/VMM overhead without changing guest RAM or project quotas.
 **Seccomp & Namespaces**: MicroVM runs in unshared PID, net, mount, and IPC namespaces.

**TAP ownership and kernel upgrades**: TAP creation sets both `user SHINU_JAIL_UID` and `group SHINU_JAIL_GID`, so unprivileged Firecracker can attach under Linux 6.12.117's stricter `tun_permitted` rules. Fresh creation does not scan procfs. Only EEXIST/EBUSY collisions inspect sysfs owner/group and `/proc/*/fdinfo` holders; an unused mismatched legacy TAP is rebuilt, while an occupied TAP is left intact. A root-owned, nonblocking file claim at `/run/shinu-tap-locks/<tap>.lock` spans inspection, recreation, VMM attachment and failure cleanup across cooperating daemon processes; the existing per-Space lock still serializes lifecycle threads. Zero-byte lock files stay linked after release and Space removal to prevent split-inode locks. Loaded restore network reconfiguration never recreates the TAP already held by its VMM. TAP contention returns HTTP **409** with `code:"tap_busy"`; CLI start prints `shinu: tap_busy` and exits **73**, distinct from capacity-watermark exit 75.

**Host Prerequisite**:
Create the non-privileged jailer user and group (handled automatically by `./packaging/install.sh`):
```sh
groupadd -g 30000 -r shinu-jail
useradd -u 30000 -g 30000 -r -s /usr/sbin/nologin -d /nonexistent shinu-jail
```
Host kernel must have cgroup v2 unified hierarchy mounted at `/sys/fs/cgroup`.

### 2. Physical Capacity & Request Limits

Create, fork, start and resume check actual store free space and host `MemAvailable` before new admission. There are no per-project Space, disk, or running-VM quotas and no nominal/reserve pre-charge. Concurrent admissions are not reservations: a passing check does not promise a future allocation.

| Variable | Default | Description |
|---|---|---|
| `SHINU_MIN_STORE_FREE_MIB` | `1024` | Minimum actual store free MiB; exact floor is admitted. `0` disables this floor. |
| `SHINU_MIN_MEM_AVAILABLE_MIB` | `512` | Minimum host MemAvailable MiB; exact floor is admitted. `0` disables this floor. |
| `SHINU_LIMIT_VCPUS` | `0` | Explicit optional per-VM vCPU ceiling; `0` is unlimited. |
| `SHINU_LIMIT_MEM_MIB` | `0` | Explicit optional per-VM guest RAM ceiling; `0` is unlimited. |
| `SHINU_LIMIT_API_PER_MIN` | `0` | Optional per-project request rate ceiling; `0` is unlimited. |

Watermark rejection returns HTTP **429** with `{"code":"capacity_watermark","error":"capacity_watermark: ..."}`. CLI lifecycle/fork requests print exactly `shinu: capacity_watermark` to stderr and exit **75**, distinct from other failures (exit 1).

**Migration:** `SHINU_LIMIT_SPACES`, `SHINU_LIMIT_DISK_MIB`, `SHINU_LIMIT_RUNNING`, `SHINU_SPACE_RESERVE_MIB`, and `SHINU_SPACE_WRITE_CAP_MIB` are ignored with a startup warning. Historical project Space/disk/running limits no longer constrain admission. A schema-versioned one-time migration clears all unproven legacy Space write caps and cap-stop reasons; legacy JSON import does the same. Old rows never recorded whether a cap was inherited or explicit, so **old explicit protections must be specified again after upgrading**. Newly explicit `fork --write-cap-mib N` protection persists across future restarts. Limits reporting returns `0` for removed project quotas; admin PATCH fields for them return **400** with an obsolete-quota explanation. Admin `api_per_min` PATCH and DELETE to clear legacy overrides remain supported. Explicit per-VM sizing, request-rate limits, registration throttling, and bounded job/template retention remain supported.

### 3. TLS Termination & Network Binding
`shinud` listens strictly on cleartext HTTP on `127.0.0.1:7878` (loopback only) to keep the core daemon dependency tree minimal and simple.

**Never expose `shinud` directly to the internet.**
Deploy Caddy (or Nginx) in front of `shinud` to terminate TLS. A ready-to-use Caddyfile is provided at `packaging/caddy/Caddyfile`:

```caddy
api.example.com {
    reverse_proxy 127.0.0.1:7878 {
        flush_interval -1
    }
    transport http {
        response_header_timeout 10m
    }
}
```
> **CRITICAL**: `flush_interval -1` disables response buffering. `shinu exec` uses chunked NDJSON streaming; proxy response buffering delays terminal output streams until execution completes.


## Usage Metering & State Storage

### Usage Accounting
`shinud` records granular usage metrics into the database during background sweeps (every 30s):
 `vm_seconds`: Active microVM uptime in wall-clock seconds.
 `disk_mib_hour`: Exclusive host disk allocation measured via btrfs reflink accounting (`btrfs::exclusive`).
 `spaces_created`: Total count of created spaces.
 `api_calls`: Total API invocations.

Query aggregated usage via CLI or HTTP API:
```sh
shinu usage [--json] [--from <timestamp>] [--to <timestamp>]
```
or `GET /v1/usage?from=<ts>&to=<ts>`:
```json
{
  "project": "demo",
  "spaces_created": 3,
  "vm_seconds": 1800,
  "disk_mib_hour": 10240,
  "api_calls": 42
}
```

### State Storage (`shinu.db`)
State is stored in SQLite at `<root>/shinu.db` (`0600` permissions, WAL mode enabled for concurrent reads without blocking writes).

The schema has ten tables: `spaces`, `ckpts`, `projects`, `usage_events`, `users`, `memberships`, `sessions`, `jobs`, `templates`, and SQLite's `sqlite_sequence`. Space records include optional `expires_at` serialized as RFC3339 or `null`. The project-scoped `templates` table stores immutable Template references with logical fields `{name, checkpoint, created_at}` and a project tenant key. Names are unique per project and must be 1–64 characters matching `[a-z0-9-]`; retained references are capped at 256 per project and 2048 globally, so list results are bounded to 256 for the project and creation over either cap returns quota 429. Deleting a template removes only this reference. The `jobs` table has columns `id`, `project`, `space`, `command`, `state`, `created_at`, `started_at`, `finished_at`, `exit_code`, `error`, `log_bytes`, and `log_truncated`; states are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`.

Checkpoint rows capture nullable `vcpus`, `mem_mib`, and `disk_mib` sizing. Existing SQLite rows are backfilled once from surviving source spaces; orphan legacy checkpoints retain NULL fields and fork using the documented fallback below.

Indexes include `spaces(project, name)`, `ckpts(project)`, `ckpts(space)`, `usage_events(project, "at")`, `sessions(user_id)`, `memberships(project)`, `jobs_project_created(project, created_at DESC, id DESC)`, `jobs_project_space_state(project, space, state)`, `jobs_project_state(project, state)`, `templates_project_checkpoint`, and `spaces_project_expires`.

**Automatic Migration**: On startup, if `<root>/state.json` exists and `<root>/shinu.db` is empty, `shinud` automatically migrates spaces, checkpoints, and tokens into SQLite and renames `<root>/state.json` to `<root>/state.json.migrated` (preserving old state files without deletion).
### Concurrency & Detached-Job Invariants

Space-scoped operations acquire locks in this order: space → optional job/checkpoint → state → database connection. Job-monitor paths use job → state → database connection. Template create/delete/fork mutations resolve and update project-scoped references while holding state/database locks; template fork releases those locks before CoW/VM work. Lock hold scope stays minimal; state and database locks do not span disk CoW, subprocess, VM, or network work. Active jobs refresh VM idle use and block space stop/remove; VM loss yields job state `lost`.
- Lease expiry is optional: `expires_at` is RFC3339 or `null`; existing spaces and spaces created without a TTL use `null` and never expire. Expired leases reject new starts, auto-starts, and jobs.
- The expiry sweep stops a VM after active jobs finish their lease-capped cancellation pipeline and, after `SHINU_LEASE_GRACE_SECS`, deletes the mutable Space using claim-before-delete. Active jobs still postpone cleanup; renewal under the Space lock wins over expiry cleanup. Checkpoints, their archived snapshot SSH credentials, and templates remain usable without the source Space.



## HTTP REST API

All API routes require authentication header: `Authorization: Bearer <token>`.

### Route Matrix

| Method | Path | Request Body | Response Body / Status | Description |
|---|---|---|---|---|
| `GET` | `/` | — | `302 Found` (redirect to `/login` or `/app`) | Serve console dashboard login/redirect |
| `GET` | `/login` | — | `200 OK` (HTML) | Serve console login page |
| `GET` | `/register` | — | `200 OK` (HTML) | Serve console registration page |
| `GET` | `/app` | — | `200 OK` (HTML) | Serve console app dashboard if authenticated, else redirect |
| `GET` | `/assets/app.css` | — | `200 OK` (CSS) | Serve console stylesheet |
| `GET` | `/assets/app.js` | — | `200 OK` (JS) | Serve console client application bundle |
| `POST` | `/console/register` | `{"email":"...","password":"..."}` | `200 OK` + `Set-Cookie` | Register user account with 12+ char password |
| `POST` | `/console/login` | `{"email":"...","password":"..."}` | `200 OK` + `Set-Cookie` | Log in console session |
| `POST` | `/console/logout` | — | `200 OK` + Clear `Set-Cookie` | Log out console session |
| `GET` | `/console/me` | — | `200 OK` `{"email":"...","projects":[...]}` | Get logged in user details |
| `GET` | `/console/tokens` | — | `200 OK` `[{"hash":"...","project":"...","created_at":"..."}]` | List API tokens for user's active project |
| `POST` | `/console/tokens` | — | `201 Created` `{"token":"..."}` | Mint new 32-byte API token for active project |
| `DELETE` | `/console/tokens/{prefix}` | — | `200 OK` | Delete matching token prefix |
| `POST` | `/v1/spaces` | `{"name":"web","image":"ubuntu","vcpus":2,"mem_mib":1024,"disk_mib":2048,"network":"lan","ttl_seconds":3600}` | `201 Created` | Create space with sizing, network, and optional `ttl_seconds` options |
| `GET` | `/v1/spaces` | — | `200 OK` `{"spaces":[...],"ckpts":[...]}` | List spaces and commits in project namespace; space records include `expires_at` as RFC3339 or `null` |
| `DELETE` | `/v1/spaces/{name}` | — | `200 OK` `{"removed":"..."}` | Stop VM and delete space and its images |
| `GET` | `/v1/templates` | — | `200 OK` `{"templates":[...]}` | List immutable project-scoped checkpoint templates, bounded to 256 retained references for the project and sorted by `name`, `created_at`, and `checkpoint` |
| `POST` | `/v1/templates` | `{"name":"baseline","checkpoint":"<checkpoint-uuid>"}` | `201 Created` serialized Template | Create an immutable template reference to a same-project checkpoint; over the 256-per-project or 2048-global retention cap returns `429 Too Many Requests` |
| `DELETE` | `/v1/templates/{name}` | — | `200 OK` `{"removed":"...","checkpoint":"..."}` | Remove only the named template reference; checkpoint files remain |
| `POST` | `/v1/templates/{name}/fork` | `{"name":"web2","ttl_seconds":3600}` | `201 Created` serialized Space | Fork the template's concrete checkpoint UUID into a destination space with optional TTL |
| `PATCH` | `/v1/spaces/{name}` | `{"vcpus":4,"mem_mib":2048,"disk_mib":4096}` | `200 OK` | Resize VM limits (space must be stopped, disk only grows) |
| `PATCH` | `/v1/spaces/{space}/lease` | `{"ttl_seconds":3600}` or `{"ttl_seconds":null}` | `200 OK` | Set a lease with a positive integer number of seconds or clear it with `null` |
| `POST` | `/v1/spaces/{name}/start` | optional `{"load_only":false,"track_dirty":true}` | `200 OK` `{"booted":true,"state":"running"}` | Start, or load a Full generation paused with `load_only:true` (state `loaded`) |
| `POST` | `/v1/spaces/{name}/resume` | — | `200 OK` `{"booted":true,"state":"running"}` | Resume a loaded Space and wait for fresh application readiness |
| `POST` | `/v1/commits/{id}/warm` | — | `200 OK` `{"checkpoint":"<id>","warmed":true}` | Warm a non-diff Full checkpoint in the dedicated cache cgroup |
| `POST` | `/v1/spaces/{name}/stop` | — | `200 OK` `{"stopped":"...","was_running":true}` | Stop VM, flush disk, release memory |
| `POST` | `/v1/spaces/{name}/exec` | `{"cmd":["..."],"stdin":"...","session":"..."}` | `200 OK` Chunked NDJSON stream | Execute a command synchronously inside VM (optional persistent `session` id) |
| `POST` | `/v1/spaces/{space}/jobs` | JSON command | Job record | Start a detached command without waiting for completion |
| `GET` | `/v1/jobs` | — | `200 OK` `{"jobs":[...],"truncated":...}` | List the newest 64 detached jobs in the project |
| `GET` | `/v1/jobs/{id}` | — | `200 OK` job record | Get detached job state and metadata |
| `GET` | `/v1/jobs/{id}/logs` | — | `200 OK` `{"id":"...","data":"...","log_bytes":N,"log_truncated":false,"terminal":false}` | Get the bounded terminal-rendered job log in a JSON envelope |
| `POST` | `/v1/jobs/{id}/cancel` | — | `200 OK` job record | Request cancellation of a detached job |
| `POST` | `/v1/spaces/{name}/push?path=<path>` | Raw bytes (up to 256 MiB) | `200 OK` `{"path":"...","bytes":N}` | Stream binary data directly into guest file |
| `GET` | `/v1/spaces/{name}/pull?path=<path>` | — | `200 OK` Raw bytes (`application/octet-stream`) | Stream binary file out of guest |
| `GET` | `/v1/spaces/{name}/vnc` | — | `200 OK` raw TCP tunnel | VNC Vsock bridge to port 2223 (VNC port) |
| `GET` | `/v1/spaces/{name}/proxy/{port}[/{path}]` | — / Method body | `200 OK` / Method status | HTTP proxying to guest port |
| `POST` | `/v1/spaces/{name}/commits` | `{"note":"...","hot":false,"snapshot":"full"}` | `201 Created` | Create CoW disk checkpoint. Snapshot can be `none`, `full` or `diff`. JSON responses include `snapshot` mode. |
| `GET` | `/v1/spaces/{name}/log` | — | `200 OK` `{"commits":[...]}` | Fetch commit history chain starting from `head` |
| `GET` | `/v1/spaces/{name}/reflog` | — | `200 OK` `{"entries":[...]}` | Fetch full reflog history (including discarded checkouts) |
| `GET` | `/v1/spaces/{name}/diff` | `?from=<id>&to=<id>&all=1&limit=N` | `200 OK` `{"entries":[...]}` | File tree diff comparing space HEAD or commits |
| `POST` | `/v1/spaces/{name}/checkout` | `{"commit":"<id>"}` | `200 OK` `{"head":"...","auto_commit":"..."}` | Rewind space to commit (auto-commits state first) |
| `POST` | `/v1/commits/{id}/fork` | `{"name":"web2","ttl_seconds":3600}` | `201 Created` | Fork space from existing commit with optional `ttl_seconds` |
| `DELETE` | `/v1/commits/{id}` | — or `{"detach":true}` | `200 OK` `{"removed":"..."}` (with `detach`: plus `"detached":[...]`) | Delete unreferenced commit; `detach` clears lineage-only `parent` links instead of refusing |
| `GET` | `/v1/images` | — | `200 OK` `{"images":[...]}` | List available guest images |
| `GET` | `/v1/usage[?from=&to=]` | — | `200 OK` | Query usage summary metrics for project |
| `GET` | `/v1/limits` | — | `200 OK` | Query project quota limits and current resource usage |
| `GET` | `/v1/projects/{project}/limits` | — | `200 OK` | Query quota limits for a project |
| `PATCH` | `/v1/projects/{project}/limits` | `{"api_per_min":120}` | `200 OK`; obsolete spaces/disk/running fields return `400` | Set project request-rate override (requires admin token) |
| `DELETE` | `/v1/projects/{project}/limits` | — | `200 OK` | Clear quota overrides for project (requires admin token) |
| `POST` | `/v1/gc` | `{"free_below":...,"dry_run":false}` | `200 OK` | Run garbage collection on unreferenced commits |
### Data Transfer Mechanisms

Shinu provides three mechanisms to move data into and out of guest spaces:

1. **Synchronous `exec` `stdin` & `session`**: Paste text strings directly into commands via `{"cmd":[...], "stdin":"...", "session":"..."}` on `POST /v1/spaces/{name}/exec`. This rides the standard 1 MiB JSON request body limit and closes stdin upon writing so the guest command receives clean EOF. When `session` is provided, commands execute in a persistent shell session within the VM.
2. **`push` / `pull`**: Stream binary files up to 256 MiB directly to or from absolute guest paths (`POST /v1/spaces/{name}/push?path=...` with raw request body, and `GET /v1/spaces/{name}/pull?path=...` returning `application/octet-stream`). `push` streams socket bytes to guest `cat > <quoted path>`, while `pull` checks file existence (`test -f`) before responding and streams `cat <quoted path>`. Both endpoints auto-start stopped VMs and record usage events. Directories return 400.
3. **`tar` over `exec`**: Transfer directories or multi-file trees by piping `tar` archives through `exec` with stdin or stdout.

### Synchronous `exec` Streaming Format (NDJSON)

The `POST /v1/spaces/{name}/exec` endpoint is synchronous. It uses `Transfer-Encoding: chunked` and returns newline-delimited JSON (NDJSON) messages:

```json
{"stream":"stdout","data":"Linux guest 6.1.102 #1 SMP ...\n"}
{"stream":"stderr","data":""}
{"exit":0}
```

Every execution stream guarantees a final `{"exit": N}` payload terminating the response. Detached jobs use a separate lifecycle: `POST /v1/spaces/{space}/jobs` returns a job record while the command runs, and `GET /v1/jobs/{id}/logs` returns a JSON envelope whose `data` field contains the terminal-rendered log, capped at 1 MiB. Job logs are not chunked NDJSON and have no follow or raw mode. Job states are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`.

### Error Handling & Response Format

Errors return JSON responses with standard HTTP status codes:

```json
{
  "error": "space \"web\" not found"
}
```

Status Code Mapping (`http::status_for`):
 `401 Unauthorized`: Missing, malformed, or invalid `Authorization: Bearer <token>`.
`400 Bad Request`: Invalid JSON body, malformed command, invalid request payload, invalid template name, or duplicate template name.
`404 Not Found`: Target space, commit, or template does not exist within caller's project scope; a template's missing or foreign checkpoint target also returns 404.
 `405 Method Not Allowed`: Unrecognized HTTP verb for path.
 `409 Conflict`: TAP ownership/attachment is busy (`{"code":"tap_busy","error":"tap_busy: ..."}`); the existing interface is not deleted.
 `429 Too Many Requests`: A physical capacity watermark (`code: capacity_watermark`), explicit request sizing/rate limit, or metadata retention limit rejects the request.
 `500 Internal Server Error`: Host I/O errors, btrfs reflink failure, or process execution failures.

### cURL Example

Walk through space creation, execution, committing, log viewing, checkout, naming a checkpoint template, forking it, and removing the template reference via cURL:

```sh
TOKEN="shinu_tok_xxxxxxxxxxxxxxxxxxxxxxxx"
API="http://127.0.0.1:7878"

# 1. Create space
curl -s -X POST "$API/v1/spaces" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-space"}'

# 2. Execute command
curl -s -N -X POST "$API/v1/spaces/demo-space/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cmd":["echo","hello agent"]}'

# 3. Create a commit snapshot
COMMIT_RESP=$(curl -s -X POST "$API/v1/spaces/demo-space/commits" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"note":"snapshot 1"}')
COMMIT_ID=$(echo "$COMMIT_RESP" | jq -r .id)

# 4. View log history
curl -s "$API/v1/spaces/demo-space/log" \
  -H "Authorization: Bearer $TOKEN"

# 5. Rewind space to commit (checkout)
curl -s -X POST "$API/v1/spaces/demo-space/checkout" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"commit\":\"$COMMIT_ID\"}"
# 6. Name the checkpoint with an immutable template reference
curl -s -X POST "$API/v1/templates" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"baseline\",\"checkpoint\":\"$COMMIT_ID\"}"

# 7. Fork the template into a new space; parent/head store the concrete UUID
curl -s -X POST "$API/v1/templates/baseline/fork" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"template-space","ttl_seconds":1800}'

# 8. Remove only the template reference; checkpoint files remain
curl -s -X DELETE "$API/v1/templates/baseline" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Git-like Workspace Semantics

Shinu implements explicit version control semantics over guest ext4 image states:

- **`Space { project, parent, head, expires_at, readiness }`**: Represents an active working branch. `head` points to the latest commit ID (or `None` for a fresh space); `expires_at` is an RFC3339 expiry or `null` for spaces without a TTL. Nullable `readiness` is the application admission policy.
- **`Ckpt { project, space, parent, auto, note, full, base, snapshot_version, vcpus, mem_mib, disk_mib, readiness }`**: Represents an immutable disk image commit snapshot. `parent` points to the prior commit ID; nullable sizing and readiness capture the Space's policy when committed, independently of its source Space.
  - **Snapshot Modes**:
    - `none`: Captures the guest disk CoW state only.
    - `full`: Captures the disk, guest memory and CPU state using Firecracker v1.18.0 snapshot format `12.0.0`. `--full` can degrade to `diff` only when the known live dirty epoch is exactly the selected full base.
    - `diff`: Stores dirty memory pages against a full checkpoint recorded in `base`. Firecracker resets dirty tracking on every successful create, not on publication: uncertain epochs (failed capture, restart, restore) and a second consecutive Diff request force a new Full, including explicit `--diff`. This prevents missing prior modifications when restoring against the full base.
  - **Auto-Degradation & Cap**: `SHINU_FULL_EVERY=0` disables automatic Full-to-Diff degradation; positive values cap it. The dirty-epoch safety rule is stricter: currently at most one Diff follows each Full. Commit, log, reflog, and ls JSON report the actual `snapshot` mode.
  - **Snapshot Format Version**: Loading `10.0.0`, unrecorded, or other incompatible memory state is refused with a clear version error. Fork, checkout and pending restore instead use the existing disk-only cold-boot path, preserving source checkpoint files. Running processes/connections are intentionally not preserved by this fallback; spaces must cold restart to negotiate discard.
  - **Memory Snapshot Credentials**: Full and diff commits archive the source SSH private key as `<root>/ckpts/<id>.key` and public key as `<id>.pub`, both mode `0600`. These survive mutable Space/lease cleanup and are unlinked with checkpoint assets by `rmckpt` and GC. A memory fork prefers archived credentials, then a surviving source keypair, and returns a clear **400 Bad Request** if neither remains; disk-only forks still install a fresh keypair.
  - **Commit Deletion Guard**: A commit checkpoint cannot be deleted via `rmckpt` (or `DELETE /v1/commits/{id}`) if it is currently referenced as a parent of any space or checkpoint, as a `base` for any diff checkpoint, or as the target of a template reference. `rmckpt --detach` (body `{"detach":true}`) treats `parent` edges as lineage only: every checkpoint image is an independent reflink, so it clears those edges and deletes the commit, while a space `head`, a template, or a diff `base` still refuses.
  - **File Tree Diff (`shinu diff`)**: Entirely distinct from memory/diff snapshots, this is a *filesystem tree comparison* between loop-mounted read-only guest ext4 images. By default, it ignores standard guest runtime churn directories (such as `/dev`, `/proc`, `/run`, `/sys`, `/tmp`, `/var/log`, `/etc/machine-id`, `/etc/ssh/ssh_host_*`).
- **`Template {name, checkpoint, created_at}`**: An immutable project-scoped reference to a concrete checkpoint UUID. `name` is 1–64 chars matching `[a-z0-9-]`; retained references are capped at 256 per project and 2048 globally, with list results bounded to 256 for the project. Creation over either cap returns 429. Duplicate or invalid names return 400, and missing or foreign checkpoint targets return 404.
  - `template fork` resolves the stored checkpoint UUID and creates a new `Space` with both `parent` and `head` set to that UUID; optional `ttl_seconds` applies to the destination. The source Space need not exist.
  - Templates are references only: `rmckpt` and GC treat the target as referenced; deleting a template removes the reference and never its checkpoint files. There is no update, rename, tags, sharing, catalog, or console UI.
- **`commit` (`POST /v1/spaces/{name}/commits`)**:
  - Sets `parent = space.head`, creates a btrfs reflink snapshot under `<root>/ckpts/<id>.ext4`, and updates `space.head = new_id`.
  - **Cold Commit (`hot: false`)**: Requires an already stopped Space. It records `consistency: "crash"`, because stopped status is not proof of a clean application shutdown.
  - **Hot Commit (`hot: true`)**: Runs executable `/etc/shinu/freeze.d/*` hooks in lexical order with `freeze`, then `fsfreeze -f` once per writable block-backed superblock in the guest's initial mount namespace (root last); pauses the VM; creates memory/state (when requested, draining block IO); reflinks the disk while still paused; resumes; unfreezes mounts and calls hooks with `thaw` in reverse order. Cleanup runs after every failure, and freezing failure never silently downgrades consistency. A guest `flock` fences cleanup even if the control connection disappears or the resident worker dies while a monitored script is still running. Resume has bounded retries and state confirmation. Captured RAM includes the freeze ledger, so restore thaws before declaring the Space ready; thaw failure rejects startup. Hooks must be synchronous, bounded and idempotent, must not detach untracked background work, and must cover every application that needs coordinated flushing, including databases; external storage is outside the guarantee. `/run` must be executable tmpfs; guest `timeout`, `flock`, `findmnt`, `fsfreeze`, `sort`, and standard shell tools are required. Each hook has 20 seconds, each filesystem operation 10 seconds, each script 110 seconds, lock acquisition 115 seconds, and the SSH process group 250 seconds. Unsupported escaped mount paths fail closed.
  - **Snapshot generation metadata**: `<root>/ckpts/<id>.json` binds disk, optional memory/state, `fc_build_id` (SHA-256 of the running `/proc/<pid>/exe` inode, or `none` for cold cuts), `snapshot_format`, `parent_generation`, `consistency`, `created_unix_ns`, `pause_ms`, `freeze_ms`, and `thaw_ms`. It is written before database publication and removed with failed captures, checkpoint deletion or GC. `shinu ls --json` checkpoints expose `consistency`; legacy checkpoints are conservatively `crash`. Hot commit responses also expose timing fields. `pause_ms` includes pause/create/reflink/resume, not application freeze/thaw.
  - **Resident snapshot control**: `shinud` installs the matching static `shinu-snapshot-agent` into guest `/run/shinu-snapshot` at cold start (or lazily on the first hot capture of an already-running Space). Build the helper with `cargo build --release --target x86_64-unknown-linux-musl -p shinu-vm --bin shinu-snapshot-agent` (use `aarch64-unknown-linux-musl` on aarch64; install the Rust target and matching musl C toolchain for bundled SQLite). `packaging/install.sh` requires a static ELF advertising `SHINU-SNAPSHOT-1 READY-1` via `--capabilities` and installs it beside `shinud` and `shinu-vsock`. Ship daemon and helper together; CI builds both host binaries and the musl helper.
  - The resident process locks its memory, runs at nice -20, and accepts authenticated `status`, `freeze`, `thaw`, `capabilities`, and `ready` over guest vsock port 2224, reachable through the daemon-only Firecracker socket. A root-only nonce rotates before each snapshot generation and is archived in mode-0600 generation JSON as `guest_snapshot_nonce`; freeze phases reject replay, while thaw remains idempotent. This protects against non-root guest processes, not compromised guest root. Writable ext4 superblocks are frozen once even when bind-mounted repeatedly; Docker overlay upper directories are protected by freezing their ext4 backing filesystem. Native thaw uses pre-opened mount descriptors and `FITHAW` without post-resume SSH authentication or fork/exec; configured thaw hooks still run in reverse order with deadlines. Missing/crashed workers and legacy generations fall back to bounded SSH thaw. Neither adapter's failure permits startup or checkpoint publication.
  - The installer requires `file(1)` and rejects helpers that are not statically linked ELF artifacts. `SHINU_SNAPSHOT_PRECONNECT=1` (or `true`) optionally authenticates and parks a thaw connection after freeze but before pause; it is **off by default**, pending real-host comparison. The agent applies no idle/read deadline to that authenticated channel, accepts only `thaw` on it, and also watches its listener so a fresh restore connection can replace a captured stale peer. Hot cleanup closes a broken parked connection and uses normal native/SSH thaw; restores always establish a fresh connection because Firecracker does not preserve host connection tables. Preconnect setup is included in `freeze_ms`, not hidden from the timing report.
  - **Filesystem coverage is fail-closed**: The native helper must run in the initial mount namespace. Before any application freeze hook, it reads `/proc/1/mountinfo` to plan one representative per writable block-backed filesystem, then inspects `/proc/*/mountinfo` once per distinct mount namespace. A writable block-backed mount (ext4, XFS, Btrfs and other block devices) whose major:minor is absent from that plan rejects the application-consistent capture with an `unsupported private writable block filesystem` error; it does not downgrade to crash consistency. Read-only private mounts and private bind mounts sharing an already covered superblock are allowed. Cross-namespace freezing is not implemented. Nonce setup uses private stdin, never process arguments; monitored freeze/thaw scripts inherit their flock so worker death or nested timeout groups cannot overtake cleanup.
  - After hooks and filesystem freeze, the helper repeats namespace inspection and compares the exact device/path plan before acknowledging freeze. Detected private mounts or plan changes refuse capture; `vm::snapshot` completes thaw cleanup before returning that error. Configured hooks must keep mount topology stable until pause, just as they must keep application writes quiescent. Restores quarantine the TAP before memory load, attempt thaw even after an ambiguous load failure or unsuccessful SSH-banner probe, and only then wait for SSH and rebuild the guest MAC/address, routes and ARP state. The final activation reasserts host forwarding/NAT/INPUT policy without recreating the TAP already owned by Firecracker; failures leave it unexposed.

### Loaded Spaces and shared Full memory

```sh
shinu fork CHECKPOINT pooled
shinu start --load-only --track-dirty false pooled
shinu resume pooled
shinu ckpt warm CHECKPOINT
```

`load_only` requires a stopped, loadable Full memory generation. It prepares the jail, TAP and host network, then loads Firecracker with `resume_vm:false`, leaving the TAP quarantined and vCPUs paused. No guest command, thaw, or application readiness runs yet. `GET /v1/spaces` exposes `state: loaded` and `running:false`. `resume` alone resumes vCPUs, thaws the captured ledger, fixes guest clock/network identity, exposes networking, and performs the normal fresh restore challenge/READY transaction before returning. Ordinary start/exec/jobs never silently resume a loaded Space. Repeated load-only start of the same loaded generation is idempotent; resume of a non-loaded Space is rejected.

The root-owned lifecycle record (`vm/<id>/loaded.json`) names a phase and the host boot it was written in (`/proc/sys/kernel/random/boot_id`), and records pending → loading → loaded → resuming. Full forks and checkouts write `pending` once their never-run memory/state is materialized. Startup and every start settle a stopped space's pending files before they can be loaded: only a `pending`, `loading` or `loaded` record of the **current** boot proves the vCPUs never ran and keeps them. Anything else consumes them and logs `event=pending_consumed vm_id=<UUID> reason=boot_mismatch|missing|resuming|invalid`: `resuming`, a record from another boot, a missing record (including forks made by a version without records), or unparsable content. `resuming` is recorded before anything can run vCPUs (the direct-restore launch with `resume_vm=true`, or `PATCH Resumed`); the guest may then write disk, so reusing the old memory would mix generations. Subsequent load-only is rejected; ordinary start may cold-boot, or the caller can destroy and re-fork. Destruction always removes pending files. Already admitted running VMs keep existing restart survival.

**No fsync, on purpose.** Records are renamed into place without fsync, on the handout path and everywhere else; do not add one. A daemon crash keeps the page cache, so the restarted daemon always sees the latest rename. A host crash changes the boot id, so any record that survives it, at whatever version reached the disk, names the old boot and is consumed; a missing record is consumed too. Durability only decides what a host crash leaves behind, and nothing it leaves behind is ever reused. The cost is that a host reboot discards all pending memory: loaded pools are refilled and stopped Full forks cold-boot. Cleanup uses bounded guest flush where applicable, then TERM and TAP/jail cleanup; an unresponsive VMM returns an error rather than being SIGKILLed.

Non-diff Full memory forks and checkouts hard-link the checkpoint's read-only `.mem` inode; disk images still reflink, and diff-memory merges still materialize a private sparse file. Memory/state capture files are root-owned, jail-group-readable **0440**, never writable by the jailed uid. Firecracker's File backend opens memory read-only ([`guest_memory_from_file`](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/persist.rs)) and maps it **MAP_PRIVATE** ([`snapshot_file`](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/src/vmm/src/vstate/memory.rs)); guest writes remain private CoW. Restore links are unlinked after load, so a later hot capture creates new files instead of truncating a checkpoint inode. A live fork's HEAD still blocks checkpoint deletion (including `--detach`); delete the fork before removing the checkpoint. Inode lifetime is additionally protected by hard links and live mappings.

`track_dirty` defaults to **true** for cold and memory starts. Pool consumers can pass false to reduce restore overhead; Full hot capture still works, but subsequent Diff requests safely degrade to Full when dirty tracking is disabled. MCP mirrors these choices through `shinu_start`, `shinu_resume`, and `shinu_warm_checkpoint`.

`ckpt warm` accepts only a same-project non-diff Full checkpoint. It syncs its memory file, asks the kernel to discard reclaimable old cache pages, then reads it in `/sys/fs/cgroup/shinu-ckpt-cache`. The empty dedicated cgroup is intentionally retained to own its page-cache charges instead of charging every VMM. Warm **before** loading worlds; cache already pinned by mappings cannot necessarily be recharged, and warmed pages remain reclaimable under memory pressure. Warming is opt-in and reports cgroup/read errors rather than silently succeeding.

Real-host regression (root + KVM + btrfs + approved assets and a prebuilt Void base; use a short root parent for Unix socket limits):

```sh
cargo build --bins
cargo build -p shinu-vm --target x86_64-unknown-linux-musl --bin shinu-snapshot-agent
cp target/x86_64-unknown-linux-musl/debug/shinu-snapshot-agent target/debug/shinu-snapshot-agent
python3 packaging/fast-ready-smoke.py --assets-root /path/to/approved-store \
  --base /path/to/base-void.ext4 --bin-dir target/debug --root-parent /data
```

### Application readiness admission

A Space can opt into a guest command that must complete successfully before a cold start, restored start, checkout auto-start, or execution auto-start is admitted:

```sh
shinu new example --readiness-json '{"command":["/usr/local/bin/application-ready","--check"],"timeout_seconds":90}'
shinu fork CHECKPOINT_UUID branch --readiness-json '{"command":["/usr/local/bin/application-ready"],"timeout_seconds":90}'
# Deploy the command first, then configure an existing stopped Space:
shinu stop example
shinu resize example --readiness-json '{"command":["/usr/local/bin/application-ready"],"timeout_seconds":90}'
shinu start example
```

The HTTP create/fork bodies and stopped-only PATCH accept the same `readiness` object. `command` is 1–256 NUL-free argv elements, at most 8192 aggregate UTF-8 bytes, with an absolute executable; `timeout_seconds` is an integer in 1–900. No shell is used unless explicitly named in argv. New omission/null means platform readiness only. Fork omission/null inherits the checkpoint's policy; an explicit object overrides it. Template forks inherit as well. Resize omission/null leaves policy unchanged, `{}` is invalid, and no clear operation is provided. A policy-only resize does not resize disks or CPU/memory. Every capture, including the automatic pre-checkout checkpoint, retains its current policy; checkout restores the target's policy. Legacy nullable SQLite columns and serde defaults mean old records remain nonconfigured. Source Space deletion never discards checkpoint policy.

Restored starts remain quarantined through load → thaw → base SSH/clock/network setup; then the existing TAP/NAT policy is enabled **before** the application command. A single pre-admission hook reconciles both directions of same-project, same-network peer rules and bounded guest hosts setup, without taking peer Space locks or holding state/database locks during I/O. Failure cleanup reconciles departed peer exceptions after removing the failed boot. Cold starts likewise establish platform connectivity first. Application readiness never refreezes/requarantines the running guest while waiting. Nonconfigured Spaces retain their platform SSH-banner readiness contract.

The command receives a fresh host-generated UUID in `SHINU_RESTORE_ID`, overwriting any captured/inherited value. On a fresh VM-scoped vsock port 2224 connection, framing is LF-terminated UTF-8: Firecracker `CONNECT 2224`, its `OK <port>` response, guest greeting `SHINU-SNAPSHOT-1`, then `capabilities <snapshot-auth-nonce>` → `READY-1`. A separate fresh connection uses `ready <snapshot-auth-nonce> <restore-UUID> <compact ReadySpec JSON>` → **`READY <exact restore-UUID>`** only after exit zero. The complete request is capped at 65536 bytes; replies at 256 bytes. Snapshot authentication nonces are not restore UUIDs. No ready files, captured OK messages, old UUIDs, command stdout/stderr, elapsed-time heuristics, or connection-only successes establish admission.

The guest bounds the command's process group, fences descendants on exit/timeout/disconnect, and returns only a sanitized failure. The host independently applies one monotonic admission deadline to peer setup, helper negotiation/upgrade, connection, handshake, write and response. Hosts SSH calls consume that shared remaining budget (at most 30 seconds each), not a new full budget per peer. Unsupported/missing helpers are upgraded only after thaw, under the existing guest flock: TERM only the exact resident executable, prove it exited, then replace/start and authenticate the capability. A worker that cannot be safely replaced fails closed; an old listener's `OK` is never upgrade evidence. A failed opted-in start removes only its verified VM generation and TAP, preserving the primary error. Deploy the matching static helper even when restoring an older checkpoint.

Admission is **not ongoing health monitoring**. A daemon-local receipt is reusable only for the same root/Space, verified Firecracker PID and `/proc` starttime, host boot ID, and complete policy; reuse skips both the guest command and peer hosts SSH setup. New boot/restore, stop/remove, checkout, policy change, uncertain identity, and daemon restart invalidate reuse; no receipt is persisted in a file or snapshot. A later application failure or external lease expiry is not continuously monitored by this admission hook. Sanitized stderr records `event=guest_readiness vm_id=<UUID> restore_id=<UUID> stage=requested|ready|failed elapsed_ms=<host monotonic milliseconds>` (terminal records include a safe code); authentication nonces, argv and guest output are never logged.

Memory restores (restored start and `resume`) also record one sanitized line per transaction step, `event=restore_step vm_id=<UUID> step=Resume|Quarantine|Load|Thaw|Ready|Configure|Expose|ApplicationReady elapsed_ms=<host monotonic milliseconds> ok=true|false`, so the cost between the resume request and `stage=requested` can be attributed without tracing the daemon. `Resume` is the Firecracker `PATCH /vm` call of `resume` only. The steps run strictly in that order: overlapping the `Ready` SSH wait with later steps measured no gain on 4-vCPU nested guests (step11; its extra socat/sshd forks slowed `Configure` and `ApplicationReady`), so it is no longer enabled. Finer `event=restore_substep vm_id=<UUID> step=<name> elapsed_ms=<ms> …` lines split the slow steps: `ReadyProbe attempt=<n> ok=` for every SSH-banner probe of `Ready` (each makes the guest fork socat/sshd); inside `ApplicationReady`, `NetworkState members=`, `PeerRules ok=` and `HostsSync members_updated=` (named-network hook; `members_updated=0` means no SSH ran), then `NetworkReady`, `HelperCapability`, `HelperInstall` (only when the helper lacks READY-1), `HelperConnect`, `ReadyRequestSent` and `ReadyReply` (request sent to the guest's reply line: the guest command's run time plus vsock delivery), the latter carrying `restore_id` so they pair with `event=guest_readiness`.

Restored-generation identity (guest wall clock, eth0 MAC/address/default route) is applied by the resident guest helper's separate `setup` action on vsock port 2224, not by an SSH session. `setup` is authenticated by the helper nonce, accepted only after thaw, validates every field (decimal nanoseconds, MAC, IPv4 CIDR, gateway) and applies them with `clock_settime` and one `ip -batch`; it runs no policy argv and its only success reply, `SETUP-OK`, can never satisfy a `READY <restore_id>` readiness transaction. Helpers or guests without `setup` (captured before this change) fall back to the old SSH setup; hot capture replaces a helper that lacks the `capabilities <nonce> setup` → `SETUP-1` answer, so re-captured generations use the helper path. The TAP stays down until `Expose`: its address and NAT/FORWARD/INPUT policy are reasserted concurrently with `Thaw`, and `Expose` only brings the link up.

`start --load-only` (pool fill) prefaults the paused VM's guest memory before it reports `loaded`. shinud reads one byte per 64 KiB window of Firecracker's private `snap.mem` mappings with `process_vm_readv`, and only for windows that had a page in the checkpoint's page cache when it was sampled (`mincore`). This is best effort: windows not resident at sampling time are skipped, but a page evicted between sampling and the read is read back from disk. Remote reads fault without `FOLL_WRITE`: they map shared page-cache pages read-only and never copy-on-write; guest writes still CoW after resume. Fault-around maps the window's other cached pages. Locally, 8 GiB took 280–410 ms and 14 GiB ~4.4–7.6 s; failure only logs `event=prefault vm_id=<UUID> elapsed_ms=<ms> ok=false error=<message>` and the VM is still handed out. Success logs `event=prefault vm_id=<UUID> mapped_mib=<guest mapping> cached_windows_mib=<prefaulted windows> elapsed_ms=<ms> ok=true`. It does not prefill KVM EPT/NPT entries, which still fault once per page on first guest touch. The page-table pages it creates (about 2 MiB per GiB populated) are charged to **shinud's** memory cgroup (kernel PTE allocation uses `__GFP_ACCOUNT` against the faulting task, here shinud), not to the VM's jail cgroup `memory.max`. They are ordinary kernel memory, so host `MemAvailable` and the physical admission watermark still see them.

The load-only `PUT /snapshot/load` also sends `freeze_clock_until_resume: true`. Firecracker records kvmclock and vCPU 0's TSC right after the load; on the first `PATCH /vm Resumed` it moves every vCPU's TSC offset back by the same cycle count and sets kvmclock back to the recorded value before any vCPU runs. The guest therefore sees the load happen at handout: the pool dwell no longer advances `CLOCK_MONOTONIC`, so guest timers (Docker healthchecks, connection-pool keepalives) do not all expire at once on handout. Configure still sets the wall clock. Both clocks move together, because the guest's clocksource watchdog compares them. A KVM failure never fails the resume: the clocks keep running as before. The `step=Resume` log line reports `clock_frozen=<bool> dwell_ms=<ms>` from Firecracker's thaw line; `clock_frozen=false` without `dwell_ms` means no thaw line was found. A direct restore (`resume_vm: true`) and pause/resume of a running VM are unchanged.

### Firecracker v1.18 rollout

Writable rootfs drives explicitly use `io_engine: "Sync"` and `discard: true`. Guest `fstrim /` punches holes in the backing sparse image; `fstrim`'s reported bytes are not reclaimed physical bytes (compare host `stat` allocated blocks). The default download is FC-CI `6.18.62` in immutable set `20261111-778a26c0594c-0`; there is no `firecracker-ci/v1.18` prefix. **Docker/LeapCore deployments must use the custom 6.18.62-shinu kernel built from `packaging/kernel-6.18.62.config`**, which supplements the FC-CI config with the existing 6.1.155 kernel's built-in netfilter feature set (nft inet/IPv6, masquerade, xt comment/mark/multiport, raw tables, IPVS and related dependencies). The stock CI kernel omits those capabilities; booting to SSH alone is not adequate compatibility proof.

The fork build recipe is `docs/shinu-v1.18-build.md` on `linze0721/firecracker` branch `shinu/v1.18` (`v1.18.0-shinu.2` adds the load-only clock freeze on `feat/freeze-clock-load-only`). Package the marked FC and jailer binaries plus `SHA256SUMS` in `release-v1.18.0-shinu.2-x86_64/`, then place its tarball at `<root>/cache/firecracker-v1.18.0-shinu.2-x86_64.tgz` as root, not group/world-writable, **before** daemon startup. Stock FC is never auto-downloaded: its snapshot prepare path suppresses block flush errors. Installation and matching-manifest verification require an allowlisted `--version` build label, and each hot capture repeats that check on `/proc/<running-pid>/exe`; replacing an asset cannot bless an old running binary. The fork propagates device-preparation failure through `Vmm::save_state` without changing format 12; shinu then resumes/thaws and rejects publication. Disk-only hot cuts explicitly fsync the paused Sync backing inode as they do not request FC memory capture. For the custom kernel set `SHINU_KERNEL_FILE` to a root-owned readable regular file (no symlink or group/world write) and `SHINU_KERNEL_SHA256` to its verified digest. An already matching manifest is verified, not overwritten; stage intended assets during the maintenance window.

For 109, deploy only during a coordinated maintenance window: stop/cold-restart every Space (including the nightly candidate), install the new shinu binaries together with `shinu-vsock`, stage FC/jailer/kernel with verified hashes, update the nightly `SHINUD_LIFECYCLE_SHA256` pin to the deployed `shinud` SHA-256, and then restart the daemon. Keep old checkpoint disks; their old memory falls back to cold boot. Re-capture format-12 generations before expecting warm restores. No production rollout is performed by this change.

Upgrade effect of boot-bound pending records: Full forks created by an earlier version but never loaded, and after any host reboot all pending memory, cold-boot instead of restoring (logged as `event=pending_consumed`). The 109 procedure above already stops or cold-restarts every Space, so this adds no maintenance step.

#### Rebuilding the Docker-compatible guest kernel

Source: `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.62.tar.xz`;
SHA-256 `490a7aedf1b355c565d3a6c05333ccccb5da82064eca46b590448a7099d7d651` (matches kernel.org's published `sha256sums.asc`). Start with the FC-CI config, enable the union of the old Docker-compatible kernel's `=y` netfilter settings, then normalize with `olddefconfig`. `CONFIG_NF_CT_PROTO_DCCP` is the only old netfilter built-in not retained: that option no longer exists in 6.18 source. `NFT_CHAIN_NAT` is not a 6.18 config symbol either; `NFT_NAT`, `NFT_CT`, `NFT_COMPAT`, inet/IPv6 tables and their real dependencies are built in.

The exact build used a disposable `debian:trixie` container, with the unpacked source mounted at `/src`, an output directory at `/build`, and this repository's `packaging/` mounted at `/config`:

```sh
apt-get update -qq
apt-get install -y --no-install-recommends gcc make bc bison flex libssl-dev libelf-dev ca-certificates
export KCONFIG_CONFIG=/config/kernel-6.18.62.config
export KBUILD_BUILD_USER=shinu KBUILD_BUILD_HOST=shinu
export KBUILD_BUILD_TIMESTAMP="2026-11-15 00:00:00 UTC" KBUILD_BUILD_VERSION=1
make -C /src O=/build LOCALVERSION=-shinu olddefconfig
make -C /src O=/build LOCALVERSION=-shinu -j4 vmlinux
```

Result: `vmlinux` SHA-256 `423c1ddb2f265b460b7b7a6abd37f21d1b03acf5c0c07470247b75455f0675d4`;
normalized config SHA-256 `8ab6cdca47da451376755a16bf0b659306126e9d8def6b3a8e5299369647e8c2`.
Set `SHINU_KERNEL_FILE` to that vmlinux and `SHINU_KERNEL_SHA256` to its digest when seeding assets. This is a build fingerprint, not a claim of reproducibility across compiler/container updates. Runtime acceptance additionally requires guest NAT listing, comment/multiport/mark rule creation, Docker network/container connectivity, and the full LeapCore health inventory.


- **`checkout` (`POST /v1/spaces/{name}/checkout`)**:
  - Target space must be stopped.
  - Automatically creates a cold **auto-commit** (`auto: true`) capturing current space state before rewinding `head` to the target commit (reflog safety mechanism). An agent will never lose experimental state when switching branches or rewinding.
  - Replaces space ext4 image with a reflink copy of the target commit image, retaining the space's VM directory and SSH key identity.
- **`fork` (`POST /v1/commits/{id}/fork`)**:
  - Creates a brand new `Space` whose initial image is a reflink clone of the specified commit, setting `parent = target_commit_id` and `head = target_commit_id`.
  - Resolves each sizing field from the checkpoint first, then a surviving same-project source Space, then the checkpoint image's logical size for disk or `SHINU_VCPUS` / `SHINU_MEM_MIB` defaults for CPU/memory. Missing source Space rows do not prevent fork; foreign checkpoints still return 404. Image kind and network metadata are inherited only while the source Space exists; otherwise the destination uses `void` metadata and no named network (the checkpoint disk contents are unchanged).
- **`rmckpt` (`DELETE /v1/commits/{id}`)**:
  - Refuses deletion if the commit is currently referenced by any space's `parent`, any space's `head`, any other commit's `parent`, any other commit's `base`, or any template's `checkpoint` (`is_referenced` check). GC applies the same reference guard and removes only eligible checkpoint files.
  - With `{"detach":true}` (`shinu rmckpt --detach`), only a space `head`, a template `checkpoint`, or another commit's `base` refuses, and the error lists just those. Otherwise every space and commit `parent` equal to the id is set to `null` in the same state claim, the row is removed, files are unlinked, and the response is `{"removed":"<id>","detached":["<space names or short commit ids>"]}`. Any other body field or a non-boolean `detach` returns **400 Bad Request**.
---

## Configuration

Daemon configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SHINU_ROOT` | `/var/lib/shinu` | Root data directory (or `--root` CLI flag). Must be on btrfs (or reflink-capable xfs). |
| `SHINU_LISTEN` | `127.0.0.1:7878` | Network address and port for HTTP server binding. |
| `SHINU_ADMIN_TOKEN` | — | Global administrator authorization token for managing quotas. Unset secret fails closed. |
| `SHINU_REFLOG_DAYS` | `7` | Retention period in days for unreferenced `auto` checkout commits during GC. |
| `SHINU_JOB_RETENTION_DAYS` | `7` | Retention period in days for archived detached-job logs. |
| `SHINU_JOB_MAX_SECS` | `3600` | Wall-clock limit for detached jobs from submission; `0` disables this cap, but the current host Space lease expiry still applies. |
| `SHINU_FULL_EVERY` | `8` | Maximum diff checkpoints per full base before auto-promoting to a new full base (0 disables cap). |
| `SHINU_SESSION_DAYS` | `7` | Default longevity of cookie sessions issued by the console. |
| `SHINU_VCPUS` | `2` | Default number of virtual CPUs per microVM. |
| `SHINU_MEM_MIB` | `1024` | Default maximum RAM limit (MiB) per VM. Memory is allocated on demand. |
| `SHINU_VMM_OVERHEAD_MIB` | `512` | Fixed host-only VMM allowance added to guest RAM for jailer `memory.max` on cold boot and snapshot restore. Read at each new launch from the daemon environment. Unsigned decimal MiB (surrounding whitespace trimmed); invalid/empty/non-Unicode/out-of-range values reject the launch. The guest-plus-allowance sum must fit `u32` MiB; the cgroup receives exact bytes. Explicit `0` disables the allowance and restores the guest-only ceiling/OOM risk. Does not resize guests or alter quotas. Restart the daemon to change its environment; already-running VMs need stop/start for a new ceiling. |
| `SHINU_IDLE_SECS` | `3600` | Inactivity timeout (seconds). Reclaims memory at 1/10th timeout; shuts down VM at full value. |
| `SHINU_IDLE_RECLAIM` | `true` | Startup-parsed boolean controlling automatic stopped-image `e2fsck -E discard -fp` repair/compaction. Set `0` or `false` to disable all such mutations, e.g. for evidence retention and read-only precommit checks. `1`/`true` enable; surrounding whitespace/case accepted, invalid/empty/non-Unicode values fail daemon startup. Does not disable live guest balloon memory reclaim or idle shutdown. Restart the daemon to activate changes. |
| `SHINU_LEASE_GRACE_SECS` | `300` | Grace period in seconds after lease expiry before mutable-space cleanup. |
| `SHINU_DISK_MIB` | `2048` | Guest disk capacity (MiB). Only read when a golden `base-<image>.ext4` is first built. |
| `SHINU_JAIL_UID` | `30000` | Unprivileged UID under which Firecracker microVM runs inside jailer. |
| `SHINU_JAIL_GID` | `30000` | Unprivileged GID under which Firecracker microVM runs inside jailer. |
| `SHINU_NET_ENABLE` | `true` | Enable guest network interfaces. Set to `false` or `0` to disable networking. |
| `SHINU_NET_BASE` | `172.31` | First two octets for per-VM `/30` NAT IP allocations. |
| `SHINU_NET_ALLOW` | — | Semicolon-delimited list of host CIDRs or peer destinations the guest VM is allowed to reach. |
| `SHINU_HOST_ALLOW` | — | Comma-separated list of host ports (e.g. `tcp:23000`, `udp:5353`, or `tcp:23000@127.0.0.1`) that the guest is allowed to contact. |
| `SHINU_NET_UPLINK` | Default route | Host egress network interface for NAT forwarding. |
| `SHINU_GUEST_DNS` | `1.1.1.1` | Default DNS nameserver baked into the guest's `/etc/resolv.conf`. |
| `SHINU_MIRROR` | — | Custom mirror URL for fetching packages during guest rootfs generation. |
| `SHINU_ARCH` | `uname -m` | Target guest CPU architecture (e.g., `x86_64`). |
| `SHINU_ROOTFS_TARBALL` | — | Local path to pre-built rootfs tarball for offline image generation. |
| `SHINU_PAYLOAD` | — | Comma-separated list of local files/paths to inject into the guest base image (format `src` or `src=dst`). |
| `SHINU_PAYLOAD_SERVICE` | — | runit service name to enable inside the guest, executing the run script injected via payload. |
| `SHINU_MIN_STORE_FREE_MIB` | `1024` | Host-wide actual store free-space admission floor. |
| `SHINU_MIN_MEM_AVAILABLE_MIB` | `512` | Host-wide MemAvailable admission floor. |
| `SHINU_LIMIT_VCPUS` | `0` | Optional per-VM vCPU ceiling (`0` unlimited). |
| `SHINU_LIMIT_MEM_MIB` | `0` | Optional per-VM guest memory ceiling (`0` unlimited). |
| `SHINU_LIMIT_API_PER_MIN` | `0` | Optional request rate limit per project (`0` unlimited). |

Client environment variables:

| Variable | Description |
|---|---|
| `SHINU_ENDPOINT` | HTTP server base URL (e.g., `http://127.0.0.1:7878`). |
| `SHINU_TOKEN` | Bearer token string obtained from token commands or console token minting. |
---

## Operating Notes

**Boot Readiness SSH vsock handshake**: When starting a VM, `shinud` performs boot readiness checking. It does not simply return success as soon as the Firecracker process starts or the vsock connection opens. Instead, it repeatedly probes vsock port 2222 (`VSOCK_SSH_PORT`), establishes the handshake, reads bytes one by one to avoid swallowing any banners, and verifies both the `OK ` vsock handshake prefix and a second line beginning with `SSH-`. Only a failed connection (no socket yet, CONNECT refused, EOF) is retried, every 50 ms; once CONNECT is answered `OK`, the probe waits on that same connection for the banner (up to 10 s, never past the 30 s total readiness budget) instead of dropping it and making the guest fork sshd again. This prevents subsequent VM executions from failing with connection issues during guest boot.

**Detached jobs**: `shinu job run` and `POST /v1/spaces/{space}/jobs` start an asynchronous command; existing `exec` remains synchronous. Job states are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`. Jobs survive client disconnect and daemon restart only while the VM stays running. Active jobs refresh idle use and block `stop` and space removal; VM loss yields `lost`. Each job has one terminal-rendered text log capped at 1 MiB, archived with mode `0600` at `<root>/jobs/<uuid>.log` and retained for 7 days by default (`SHINU_JOB_RETENTION_DAYS`). The active cap is 64 jobs per project. There is no follow or raw log mode, force-stop, reboot survival, artifact support, or console control.
**Detached job limits and control**: Detached commands accept at most 256 argv elements and 8192 total argument bytes. Job retention caps are 64 active jobs per project, 1024 total jobs per project, and 8192 total jobs globally. `GET /v1/jobs` returns the newest 64 jobs and includes `truncated` when older jobs are omitted. Bounded control SSH kills its local process group on deadline or overflow; cancellation fences the command before final capture, archive, and cleanup. VM stops flush guest durability with a finite 60-second process-group deadline before Firecracker receives TERM; a VMM that does not terminate causes an error, not SIGKILL.

**Detached job deadlines**: The monitor uses the earlier of submission time plus `SHINU_JOB_MAX_SECS` and the current host Space's `expires_at`. An expired deadline durably requests `canceling`, then reuses the existing fence → final capture → archive → cleanup path; a canceled job's `error` identifies the deadline. Natural completion already recorded in the guest still wins. Renewal or clearing a lease before cancellation updates this bound, but cannot revive a durably canceling job. The monitor polls every two seconds; existing bounded SSH control calls and retryable archive/fence failures govern cancellation completion. No second process-killing path is introduced.

**Upgrading Firecracker strands existing memory snapshots.** Firecracker validates the snapshot data format version on load, and that format went `8.0.0` (v1.13.1) to `10.0.0` (v1.16.1). Every `full` and `diff` checkpoint captured by a pre-v1.14 binary is therefore no longer restorable as running VM state. `shinud` records the format version per checkpoint and refuses the restore with **400 Bad Request** naming both versions, instead of letting the load fail opaquely.

Nothing is deleted. The checkpoint's disk image remains usable, and disk-only checkpoints, `ls`, `log`, `reflog`, plus `checkout` and `fork` of disk-only checkpoints are all unaffected. There is no in-place snapshot converter; the remedy is to take a fresh commit after upgrading.

**Dirty-page tracking on snapshot restore.** Firecracker does not inherit the dirty bitmap across restore. Starts default to `track_dirty:true`; `track_dirty:false` is an explicit per-start choice for pool worlds, with Diff captures forced to Full while tracking is disabled.

**Memory is a ceiling, not a reservation.** A VM starts at ~100 MiB host RSS footprint and expands as the guest accesses memory pages. Cold boot enables virtio-balloon **free page reporting**, so a cooperating guest hands freed pages back continuously instead of holding them until the sweep intervenes. Measured on v1.16.1: a guest allocating 500 MiB then freeing it drove host RSS 102.7 MiB → 596.9 MiB → 105.0 MiB within 5 seconds, unaided. Reporting only covers pages the guest kernel has actually freed, so `shinud` still inflates the balloon explicitly after `SHINU_IDLE_SECS / 10` (default reclaim starts at 360 seconds under the 3600-second idle default) to force an idle guest to drop page cache it is still nominally using. `exec` re-inflates balloon memory transparently. Plan host capacity based on *sum of active VM page working sets*, not `SHINU_MEM_MIB × VM count`.

Reporting also shrinks `ckpts/<id>.mem`: a Full snapshot no longer captures pages the guest already freed. Usage accounting records actual exclusive extents, without a project disk quota.

**Disk space grows permanently.** Firecracker block devices lack discard/TRIM support (still true at v1.16.1; upstream issue #2708 is parked). Deleting files inside guest OS does not release host ext4 backing blocks (`fstrim` reports "discard operation is not supported"). A space that once wrote 1.5 GiB retains host disk allocation indefinitely until offline compaction, which the idle sweep performs automatically on stopped images.

Set `SHINU_IDLE_RECLAIM=0` and restart the daemon when stopped images must remain unmodified. When enabled, the idle sweep holds the same per-space lifecycle lock as request handlers from liveness inspection through repair/discard, so boot/commit/stop cannot race its mutation. A successful `stop` alone is not a clean-filesystem certificate: guest sync/remount is best effort and the VMM is ultimately terminated by signals. For an orderly cold capture, stop application writers, verify guest `sync`, request guest `systemctl reboot --no-block` (Firecracker x86 terminates on guest reboot rather than rebooting in place), await actual VMM exit, then use Shinu stop only for stale runtime cleanup and run an explicit read-only filesystem check before commit.

`commit` + `fork` does **not** shrink images; cloned reflinks inherit sparse page allocations.

To reclaim host disk blocks, punch out unused space while the target space is stopped:

```sh
shinu stop web
e2fsck -E discard -fp <root>/spaces/<uuid>.ext4
```

**Expanding space capacity**: In-band online expansion is unsupported. To grow a space disk offline, stop the VM (`shinu stop <space>`), then manually run `truncate -s <size> <root>/spaces/<uuid>.ext4` and `resize2fs <root>/spaces/<uuid>.ext4`.

**Updating base image**: Base images are built on first demand if missing in `<root>/base-<image>.ext4`. To upgrade a base image, stop `shinud`, rename or delete `<root>/base-<image>.ext4`, and restart `shinud`. Existing spaces remain unaffected as independent btrfs reflink copies.

**Daemon restart safety**: Firecracker VM processes run under `setsid` detached from the daemon's process tree. Restarting `shinud` does not interrupt running VMs; the daemon reattaches via saved PID files (in `<root>/jail/firecracker/<uuid>/root/firecracker.pid` or through `/proc` cmdline scanning matching `--id` or config path) on startup. Unintentionally terminated VMs (e.g., OOM or `kill -9`) are marked `stopped` and automatically restarted on the next `exec` call.

**Log management**:
- `shinud` daemon outputs connection logs and background garbage collection events to `stderr`.
- Guest serial console logs write to `<root>/vm/<uuid>/console.log`. Console logs truncate on VM boot but grow unbounded during active VM uptime.

---

## Storage & Path Layout

```text
<root>/shinu.db                         SQLite database containing tables: spaces, ckpts, projects,
                                        usage_events, users, memberships, sessions, jobs, templates,
                                        sqlite_sequence (mode 0600)
<root>/tokens.json                      JSON array containing hashed bearer tokens (mode 0600)
<root>/base-<image>.ext4                golden rootfs images (e.g., base-void.ext4, base-ubuntu.ext4,
                                        base-arch.ext4, base-rocky.ext4, mode 0600)
<root>/spaces/<uuid>.ext4               CoW guest disk images (mode 0700 dir)
<root>/ckpts/<uuid>.ext4                immutable checkpoint disk images (mode 0700 dir)
<root>/ckpts/<uuid>.mem                 immutable checkpoint guest memory states (for full/diff, mode 0700 dir)
<root>/ckpts/<uuid>.state               immutable checkpoint Firecracker CPU/VM states (for full/diff, mode 0700 dir)
<root>/ckpts/<uuid>.key                 retained snapshot SSH private key (mode 0600)
<root>/ckpts/<uuid>.pub                 retained snapshot SSH public key (mode 0600)
<root>/jobs/                             root-owned detached-job log directory (mode 0700)
<root>/jobs/<uuid>.log                   archived terminal-rendered job log (mode 0600)
<root>/jail/firecracker/<uuid>/root/    chroot jail directory for the space jailer container (mode 0700):
                                          fc.json               Firecracker runtime configuration
                                          fc.sock               Firecracker control UDS socket
                                          vsock.sock            vsock multiplexer UDS socket
                                          firecracker.pid       Firecracker pid file inside jail
                                          vmlinux               hardlinked guest kernel
                                          rootfs.ext4           hardlinked guest CoW ext4 image
                                          snap.mem              temporary memory snapshot state file
                                          snap.state            temporary guest CPU snapshot state file
<root>/vm/<uuid>/                       per-VM host-side metadata state directory (mode 0700):
                                          id_ed25519            per-space private SSH key
                                          id_ed25519.pub        per-space public SSH key
                                          last_used             timestamp file for VM idle sweeper
                                          loaded.json           durable paused-restore transaction phase, absent after admission
                                          track-dirty           current boot's dirty-tracking choice
                                          console.log           guest console and serial logs
<root>/assets/                          jailer and firecracker binaries + golden guest kernel (mode 0755)
<root>/cache/                           downloaded image bootstrap tarballs and cache files (mode 0755)
```

Direct host path permissions on `<root>/spaces/`, `<root>/ckpts/`, `<root>/jobs/`, `<root>/jail/`, and `<root>/vm/` are strictly restricted to `0700` owned by `root`. Clients interact exclusively over HTTP API endpoints or via the MCP server.

- **Host Path Isolation**: Control sockets, state directories, and ext4 image files are secured at mode `0700` owned by `root`. Non-root clients communicate solely over the `shinud` HTTP daemon proxy and cannot directly access or tamper with host disk files.
- **MCP Server Integration**: `shinu-mcp` exposes Model Context Protocol (MCP) tools for agents. Because MCP is a JSON protocol, file tools (`shinu_write_file` and `shinu_read_file`) operate strictly on text payloads; binary file transfers should use the `shinu push` and `shinu pull` CLI commands or HTTP endpoints.
- **Bearer Token Authentication**: Authentication uses `Authorization: Bearer <token>`. `shinud` validates tokens against hashes in `<root>/tokens.json` in constant time to prevent timing attacks. Token creation and management (`shinu token new/ls/rm`) must run host-locally as `root` and cannot be invoked over HTTP.
- **Project Scope Isolation**: Every token maps to a single `project`. All space and commit lookup operations are strictly project-scoped. Accessing a space or commit belonging to another project returns `404 Not Found`, preventing project resource enumeration or existence leakage.
- **Jailer & Cgroup Sandboxing**: MicroVMs execute under `jailer` with chroot jails, dropped privileges (UID/GID `30000`), and cgroup v2 resource bounds (`memory.max`, `pids.max`).
- **Network Isolation**: Every VM receives an isolated host-guest `/30` subnet derived from its UUID (host `.1`, guest `.2`). Guest traffic is NAT'd through host egress interfaces (`iptables`). Networking can be disabled by setting `SHINU_NET_ENABLE=0`.
- **Cleartext HTTP Warning**: `shinud` listens by default on `127.0.0.1:7878`. Tokens travel in cleartext HTTP headers. **When exposing `shinud` across an external network, deploy a reverse proxy providing TLS termination (such as Caddy) in front of `shinud`.**

### SaaS Demo Boundaries & Non-Goals

This release provides a **managed SaaS Demo** for early customer testing and monetization signal validation. The following architectural trade-offs apply:

1. **Single-Host Daemon**: `shinud` manages microVMs on a single physical host. Multi-host scheduling or cross-node VM migration is not implemented.
2. **No Integrated Billing/Payment Processing**: `shinud` provides granular usage accounting (`vm_seconds`, `disk_mib_hour`, `api_calls`), but payment gateway integration (e.g. Stripe) must be handled by an upstream control plane.
3. **Monotonic In-Flight Disk Growth & Commercial Implication**: Firecracker block devices do not support TRIM/discard (unchanged at v1.16.1; upstream issue #2708 is parked). While a space runs, deleting files inside the guest does not release host ext4 blocks, so its footprint only grows. `shinud` compensates offline: the idle sweep runs `e2fsck -E discard` on stopped images once they have grown past a threshold, releasing unshared extents while reflinked checkpoint blocks stay protected by COW. Long-running spaces that never stop therefore hold their peak allocation, which remains a cost parameter for hosting providers.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor guide, [AGENTS.md](AGENTS.md) for the authoritative architecture and invariants, and [SECURITY.md](SECURITY.md) to report security issues.

---

## License

Copyright 2026 shinu contributors.

Licensed under the Apache License, Version 2.0 (Apache-2.0). See [LICENSE](LICENSE).

## Exclusive storage accounting and offline compaction

All Space and checkpoint accounting uses sampled **Btrfs exclusive bytes**, rounded up to MiB. Nominal disk sizes, reservations and cumulative billing totals are not capacity charges. A missing sample reports zero until measured; it never reserves nominal capacity. The daemon warms the extent cache before accepting requests and refreshes it in the 30-second usage sweep without state/DB locks around Btrfs subprocesses. Samples can lag a sweep plus scan time; physical admission independently checks store free space and MemAvailable.

`SHINU_SPACE_WRITE_CAP_MIB` is obsolete and ignored with a startup warning. New Spaces and template forks are uncapped unless the caller explicitly supplies `shinu fork CHECKPOINT NAME --write-cap-mib N`; `0` disables that protection. Schema version 1 and legacy JSON import clear unproven pre-upgrade caps once, because the old format cannot identify inherited versus explicit settings. **Re-specify any old explicit protection after upgrading.** Newly explicit caps survive reopen and state updates. Effective `write_cap_mib` and `stopped_reason` appear in `shinu ls --json`. A sweep stops an over-cap Space with reason
`write_cap_exceeded`; starts and auto-starts measure that image freshly and
refuse while it remains over cap. Busy lifecycle operations postpone enforcement.
This cap uses the same exclusive-byte notion as `ls`, not guest filesystem use
or cumulative bytes written, and is sampled rather than a block-device hard cap.

`shinu compact SPACE [--json]` uses authenticated
`POST /v1/spaces/{space}/compact`. It immediately refuses running or locked spaces.
Under the existing space lifecycle lock it attaches a writable loop device,
mounts ext4 with `nosuid,nodev,noexec`, runs `LC_ALL=C fstrim --verbose`, unmounts
and detaches, then runs `btrfs filesystem defragment -czstd -f IMAGE`.
Failures leave state metadata unchanged; host cleanup is attempted on every exit,
and a failed unmount never permits loop detachment. No filesystem repair runs.
JSON returns `space`, `id`, `physical_before_bytes`, `physical_after_bytes`,
`trimmed_bytes`, `elapsed_ms`. Physical bytes use `stat.st_blocks * 512`, including
shared extents as reported by Btrfs; this is not exclusive quota usage or a
compsize compression-ratio measurement. Trimmed bytes are discard submissions,
not guaranteed net physical savings. A later compression failure can leave an
already-trimmed image: compaction is not an atomic file rewrite.

**Defragmentation breaks reflink sharing and can increase exclusive usage and
physical peak substantially.** Compact a stopped nightly candidate immediately
before commit, not every product-world fork. Subsequent checkpoint/fork clones
share the compressed extents. Merely enabling mount compression affects new
writes, not already-written extents. Refer to the
[Btrfs defragmentation warnings](https://btrfs.readthedocs.io/en/latest/btrfs-filesystem.html).
