shinu
=====

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
- **Detached Jobs**: Run commands asynchronously with `shinu job run`; inspect status and terminal-rendered logs, wait, or cancel through the CLI, REST API, or MCP. The active-job cap is 64 per project.
- **Space Leases**: Optional TTLs expose an expiry as RFC3339 data or `null`; spaces without a TTL never expire, and expired mutable spaces are stopped and cleaned up after a grace period while checkpoints and templates remain.
- **Named Checkpoint Templates**: Immutable, project-scoped names point to concrete checkpoint UUIDs for reuse. Names are 1–64 characters matching `[a-z0-9-]`; at most 256 retained references are allowed per project and 2048 globally, and creation over either cap returns 429. Deleting a template removes only the reference, never checkpoint files. There are no tags, updates, renames, sharing, catalogs, or console UI.
- **`commits`**: CoW ext4 disk state snapshots (`hot` or cold, optionally with memory).
- **`checkout`**: Rewinds space state back to any commit, automatically saving current state before rewind (reflog semantics).
- **`fork`**: Creates new independent spaces branching off any existing commit.
---

## Quick Start

### 1. Build and Install

```sh
cargo build --release
./packaging/install.sh              # Default PREFIX=/usr/local
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
- `shinud` daemon **must run as root** to create loop devices, configure NAT network interfaces (`iptables`), and set up tap devices.
- `net.ipv4.ip_forward` must be enabled for guest egress, and cgroup v2 must be mounted for the jailer's resource limits.
- HTTP clients run non-root and require no host group memberships (specifically no `/dev/kvm` or root access required).

---

## Production Deployment & Multi-Tenancy

For multi-tenant SaaS hosting, running microVM sandboxes securely requires strict isolation, quota limits, and TLS termination.

### 1. Jailer Sandboxing (Mandatory Security)
`shinud` executes Firecracker instances inside the Firecracker **jailer** sub-process (`<root>/assets/jailer`), providing:
 **Chroot jail**: MicroVM filesystem root isolated under `<root>/jail/firecracker/<uuid>/root`. Kernel and ext4 space images are hardlinked into the jail.
 **Privilege dropping**: MicroVM process runs under non-root UID/GID (default `30000`).
 **cgroup v2 isolation**: Enforces strict memory ceilings (`cgroup memory.max`) and process caps (`cgroup pids.max=512`).
 **Seccomp & Namespaces**: MicroVM runs in unshared PID, net, mount, and IPC namespaces.

**Host Prerequisite**:
Create the non-privileged jailer user and group (handled automatically by `./packaging/install.sh`):
```sh
groupadd -g 30000 -r shinu-jail
useradd -u 30000 -g 30000 -r -s /usr/sbin/nologin -d /nonexistent shinu-jail
```
Host kernel must have cgroup v2 unified hierarchy mounted at `/sys/fs/cgroup`.

### 2. Quota & Rate Limits
Resource consumption is bounded per project via environment variables or DB overrides:

| Variable | Default | Description |
|---|---|---|
| `SHINU_LIMIT_SPACES` | `5` | Maximum active or stopped spaces per project. |
| `SHINU_LIMIT_DISK_MIB` | `10240` | Maximum total exclusive disk allocation (MiB) per project across all spaces. |
| `SHINU_LIMIT_RUNNING` | `2` | Maximum concurrently running Firecracker VMs per project. |
| `SHINU_LIMIT_API_PER_MIN` | `120` | Maximum API requests per minute per project (sliding window). |

When a project exceeds a quota, API calls return `429 Too Many Requests` with `{"error":"quota: ..."}`.
Per-project quota overrides can be stored directly in `<root>/shinu.db`.

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

Indexes include `spaces(project, name)`, `ckpts(project)`, `ckpts(space)`, `usage_events(project, "at")`, `sessions(user_id)`, `memberships(project)`, `jobs_project_created(project, created_at DESC, id DESC)`, `jobs_project_space_state(project, space, state)`, `jobs_project_state(project, state)`, `templates_project_checkpoint`, and `spaces_project_expires`.

**Automatic Migration**: On startup, if `<root>/state.json` exists and `<root>/shinu.db` is empty, `shinud` automatically migrates spaces, checkpoints, and tokens into SQLite and renames `<root>/state.json` to `<root>/state.json.migrated` (preserving old state files without deletion).
### Concurrency & Detached-Job Invariants

Space-scoped operations acquire locks in this order: space → optional job/checkpoint → state → database connection. Job-monitor paths use job → state → database connection. Template create/delete/fork mutations resolve and update project-scoped references while holding state/database locks; template fork releases those locks before CoW/VM work. Lock hold scope stays minimal; state and database locks do not span disk CoW, subprocess, VM, or network work. Active jobs refresh VM idle use and block space stop/remove; VM loss yields job state `lost`.
- Lease expiry is optional: `expires_at` is RFC3339 or `null`; existing spaces and spaces created without a TTL use `null` and never expire. Expired leases reject new starts, auto-starts, and jobs.
- The expiry sweep stops a VM at expiry and, after `SHINU_LEASE_GRACE_SECS`, deletes the mutable Space using claim-before-delete. Active jobs postpone cleanup; renewal under the Space lock wins over expiry cleanup. Checkpoints and templates remain.



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
| `POST` | `/v1/spaces/{name}/start` | — | `200 OK` `{"booted":true}` | Start Firecracker VM for space |
| `POST` | `/v1/spaces/{name}/stop` | — | `200 OK` `{"stopped":"...","was_running":true}` | Stop VM, flush disk, release memory |
| `POST` | `/v1/spaces/{name}/exec` | `{"cmd":["..."],"stdin":"...","session":"..."}` | `200 OK` Chunked NDJSON stream | Execute a command synchronously inside VM (optional persistent `session` id) |
| `POST` | `/v1/spaces/{space}/jobs` | JSON command | Job record | Start a detached command without waiting for completion |
| `GET` | `/v1/jobs` | — | `200 OK` `{"jobs":[...],"truncated":...}` | List the newest 64 detached jobs in the project |
| `GET` | `/v1/jobs/{id}` | — | `200 OK` job record | Get detached job state and metadata |
| `GET` | `/v1/jobs/{id}/logs` | — | `200 OK` terminal-rendered text (max 1 MiB) | Get the job log |
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
| `DELETE` | `/v1/commits/{id}` | — | `200 OK` `{"removed":"..."}` | Delete unreferenced commit |
| `GET` | `/v1/images` | — | `200 OK` `{"images":[...]}` | List available guest images |
| `GET` | `/v1/usage[?from=&to=]` | — | `200 OK` | Query usage summary metrics for project |
| `GET` | `/v1/limits` | — | `200 OK` | Query project quota limits and current resource usage |
| `GET` | `/v1/projects/{project}/limits` | — | `200 OK` | Query quota limits for a project |
| `PATCH` | `/v1/projects/{project}/limits` | `{"max_spaces":5,"max_disk_mib":10240,"max_running":2,"api_per_min":120}` | `200 OK` | Set overrides for project quotas (requires admin token) |
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

Every execution stream guarantees a final `{"exit": N}` payload terminating the response. Detached jobs use a separate lifecycle: `POST /v1/spaces/{space}/jobs` returns a job record while the command runs, and `GET /v1/jobs/{id}/logs` returns one terminal-rendered text stream capped at 1 MiB. Job logs are not chunked NDJSON and have no follow or raw mode. Job states are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`.

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
 `429 Too Many Requests`: Project resource quota, template retention cap, or API rate limit exceeded (`{"error":"quota: ..."}`).
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

- **`Space { project, parent, head, expires_at }`**: Represents an active working branch. `head` points to the latest commit ID (or `None` for a fresh space); `expires_at` is an RFC3339 expiry or `null` for spaces without a TTL.
- **`Ckpt { project, space, parent, auto, note, full, base, snapshot_version }`**: Represents an immutable disk image commit snapshot. `parent` points to the prior commit ID.
  - **Snapshot Modes**:
    - `none`: Captures the guest disk CoW state only.
    - `full`: Captures both the guest disk CoW state and running guest memory + CPU state files (`ckpt_mem` as `.mem` and `ckpt_state` as `.state`). A `--full` request automatically degrades to `diff` when a valid full ancestor exists. Validity requires: `full=1`, same space, `.mem` and `.state` present on disk, and `snapshot_version` matching current `FC_SNAPSHOT_VERSION` (`10.0.0`). Search walks back to the nearest valid full ancestor, skipping invalid ones.
    - `diff`: Captures guest disk CoW state alongside dirty memory pages relative to the nearest valid full checkpoint base in the space history. The base commit's UUID is recorded in the checkpoint's `base` field. Commit, log, reflog, and ls JSON include the `snapshot` mode field (`none`, `full`, or `diff`).
  - **Auto-Degradation & Cap**: `SHINU_FULL_EVERY` caps how many diffs may hang off one full base on the auto path. On exceeding the cap, the next auto commit becomes a new full base. The cap governs the auto path only; an explicit `--diff` bypasses it and errors only when no valid base exists. Auto-degradation only moves Full to Diff, never Diff to Full. Measured live: first Full 1.0 GiB exclusive, next degraded Diff 8.4 MiB (restored correctly). With `SHINU_FULL_EVERY=2`, the observed chain was c1 to the prior base, c2 promoted to a new base, then c3 and c4 hanging off c2. Note: diff size tracks guest activity rather than a fixed ratio; diffs taken after heavy guest memory activity measured 745 MiB to 1002 MiB in testing.
  - **Snapshot Format Version**: `snapshot_version` records the Firecracker snapshot data format version the guest memory state was captured with (`10.0.0` for the pinned v1.16.1 binaries). It is `null` for disk-only commits and for commits written before the field existed. Restoring a memory-carrying commit whose recorded version differs from the running binary is refused with **400 Bad Request** naming both versions; the commit's files are left on disk and its disk image stays usable.
  - **Commit Deletion Guard**: A commit checkpoint cannot be deleted via `rmckpt` (or `DELETE /v1/commits/{id}`) if it is currently referenced as a parent of any space or checkpoint, as a `base` for any diff checkpoint, or as the target of a template reference.
  - **File Tree Diff (`shinu diff`)**: Entirely distinct from memory/diff snapshots, this is a *filesystem tree comparison* between loop-mounted read-only guest ext4 images. By default, it ignores standard guest runtime churn directories (such as `/dev`, `/proc`, `/run`, `/sys`, `/tmp`, `/var/log`, `/etc/machine-id`, `/etc/ssh/ssh_host_*`).
- **`Template {name, checkpoint, created_at}`**: An immutable project-scoped reference to a concrete checkpoint UUID. `name` is 1–64 chars matching `[a-z0-9-]`; retained references are capped at 256 per project and 2048 globally, with list results bounded to 256 for the project. Creation over either cap returns 429. Duplicate or invalid names return 400, and missing or foreign checkpoint targets return 404.
  - `template fork` resolves the stored checkpoint UUID and creates a new `Space` with both `parent` and `head` set to that UUID; optional `ttl_seconds` applies to the destination.
  - Templates are references only: `rmckpt` and GC treat the target as referenced; deleting a template removes the reference and never its checkpoint files. There is no update, rename, tags, sharing, catalog, or console UI.
- **`commit` (`POST /v1/spaces/{name}/commits`)**:
  - Sets `parent = space.head`, creates a btrfs reflink snapshot under `<root>/ckpts/<id>.ext4`, and updates `space.head = new_id`.
  - **Cold Commit (`hot: false`)**: Stops the VM first, flushing all guest page caches and ensuring complete filesystem consistency on disk before taking the snapshot.
  - **Hot Commit (`hot: true`)**: Runs `sync` inside guest OS over SSH without stopping the VM or remounting read-only, then immediately performs `cp --reflink=always`. **This is not a crash-consistent snapshot**: disk writes occurring between `sync` returning and reflink completion are not captured in the image. Use hot commits when an agent is awaiting tool response and will not issue concurrent disk writes. When the space is stopped, hot and cold commit paths behave identically.
- **`checkout` (`POST /v1/spaces/{name}/checkout`)**:
  - Target space must be stopped.
  - Automatically creates a cold **auto-commit** (`auto: true`) capturing current space state before rewinding `head` to the target commit (reflog safety mechanism). An agent will never lose experimental state when switching branches or rewinding.
  - Replaces space ext4 image with a reflink copy of the target commit image, retaining the space's VM directory and SSH key identity.
- **`fork` (`POST /v1/commits/{id}/fork`)**:
  - Creates a brand new `Space` whose initial image is a reflink clone of the specified commit, setting `parent = target_commit_id` and `head = target_commit_id`.
- **`rmckpt` (`DELETE /v1/commits/{id}`)**:
  - Refuses deletion if the commit is currently referenced by any space's `parent`, any space's `head`, any other commit's `parent`, any other commit's `base`, or any template's `checkpoint` (`is_referenced` check). GC applies the same reference guard and removes only eligible checkpoint files.
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
| `SHINU_FULL_EVERY` | `8` | Maximum diff checkpoints per full base before auto-promoting to a new full base (0 disables cap). |
| `SHINU_SESSION_DAYS` | `7` | Default longevity of cookie sessions issued by the console. |
| `SHINU_VCPUS` | `2` | Default number of virtual CPUs per microVM. |
| `SHINU_MEM_MIB` | `1024` | Default maximum RAM limit (MiB) per VM. Memory is allocated on demand. |
| `SHINU_IDLE_SECS` | `3600` | Inactivity timeout (seconds). Reclaims memory at 1/10th timeout; shuts down VM at full value. |
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
| `SHINU_LIMIT_SPACES` | `5` | Default maximum active or stopped spaces per project. |
| `SHINU_LIMIT_DISK_MIB` | `10240` | Default maximum exclusive disk quota limit (MiB) per project. |
| `SHINU_LIMIT_VCPUS` | `16` | Default maximum aggregate vCPUs limit per project. |
| `SHINU_LIMIT_MEM_MIB` | `32768` | Default maximum aggregate memory limit (MiB) per project. |
| `SHINU_LIMIT_RUNNING` | `2` | Default maximum concurrent active microVM limit per project. |
| `SHINU_LIMIT_API_PER_MIN` | `120` | Default API rate limit per minute per project. |

Client environment variables:

| Variable | Description |
|---|---|
| `SHINU_ENDPOINT` | HTTP server base URL (e.g., `http://127.0.0.1:7878`). |
| `SHINU_TOKEN` | Bearer token string obtained from token commands or console token minting. |
---

## Operating Notes

**Boot Readiness SSH vsock handshake**: When starting a VM, `shinud` performs boot readiness checking. It does not simply return success as soon as the Firecracker process starts or the vsock connection opens. Instead, it repeatedly probes vsock port 2222 (`VSOCK_SSH_PORT`), establishes the handshake, reads bytes one by one to avoid swallowing any banners, and verifies both the `OK ` vsock handshake prefix and a second line beginning with `SSH-`. This prevents subsequent VM executions from failing with connection issues during guest boot.

**Detached jobs**: `shinu job run` and `POST /v1/spaces/{space}/jobs` start an asynchronous command; existing `exec` remains synchronous. Job states are `starting`, `running`, `canceling`, `exited`, `canceled`, and `lost`. Jobs survive client disconnect and daemon restart only while the VM stays running. Active jobs refresh idle use and block `stop` and space removal; VM loss yields `lost`. Each job has one terminal-rendered text log capped at 1 MiB, archived with mode `0600` at `<root>/jobs/<uuid>.log` and retained for 7 days by default (`SHINU_JOB_RETENTION_DAYS`). The active cap is 64 jobs per project. There is no follow or raw log mode, force-stop, reboot survival, artifact support, or console control.
**Detached job limits and control**: Detached commands accept at most 256 argv elements and 8192 total argument bytes. Job retention caps are 64 active jobs per project, 1024 total jobs per project, and 8192 total jobs globally. `GET /v1/jobs` returns the newest 64 jobs and includes `truncated` when older jobs are omitted. Bounded control SSH kills its local process group on deadline or overflow; cancellation fences the command before final capture, archive, and cleanup. Automatic and manual VM stops flush guest durability with a finite 60-second process-group deadline before Firecracker receives TERM then KILL.

**Upgrading Firecracker strands existing memory snapshots.** Firecracker validates the snapshot data format version on load, and that format went `8.0.0` (v1.13.1) to `10.0.0` (v1.16.1). Every `full` and `diff` checkpoint captured by a pre-v1.14 binary is therefore no longer restorable as running VM state. `shinud` records the format version per checkpoint and refuses the restore with **400 Bad Request** naming both versions, instead of letting the load fail opaquely.

Nothing is deleted. The checkpoint's disk image remains usable, and disk-only checkpoints, `ls`, `log`, `reflog`, plus `checkout` and `fork` of disk-only checkpoints are all unaffected. There is no in-place snapshot converter; the remedy is to take a fresh commit after upgrading.

**Dirty-page tracking on snapshot restore.** Firecracker does not inherit the dirty-page bitmap across a restore; it must be rebuilt from the load request. `PUT /snapshot/load` sends `"track_dirty_pages":true` so restored VMs track dirty pages for subsequent diff snapshots. Without this, a restored VM lacked dirty tracking and every later diff degraded to a full memory dump (measured: three successive diffs of an idle restored guest were 268.2 / 270.1 / 267.8 MiB). With dirty tracking enabled, the same idle-guest measurement gave 269.5 MiB for the first diff after restore (as the bitmap starts empty and pages touched during restore count dirty), converging to 8.2 MiB and 8.0 MiB from the second diff on.

**Memory is a ceiling, not a reservation.** A VM starts at ~100 MiB host RSS footprint and expands as the guest accesses memory pages. Cold boot enables virtio-balloon **free page reporting**, so a cooperating guest hands freed pages back continuously instead of holding them until the sweep intervenes. Measured on v1.16.1: a guest allocating 500 MiB then freeing it drove host RSS 102.7 MiB → 596.9 MiB → 105.0 MiB within 5 seconds, unaided. Reporting only covers pages the guest kernel has actually freed, so `shinud` still inflates the balloon explicitly after `SHINU_IDLE_SECS / 10` (default reclaim starts at 360 seconds under the 3600-second idle default) to force an idle guest to drop page cache it is still nominally using. `exec` re-inflates balloon memory transparently. Plan host capacity based on *sum of active VM page working sets*, not `SHINU_MEM_MIB × VM count`.

Reporting also shrinks `ckpts/<id>.mem`: a full snapshot no longer captures pages the guest already freed. That is billing-visible, because a checkpoint's `.ext4`, `.mem` and `.state` files all count toward the project disk quota.

**Disk space grows permanently.** Firecracker block devices lack discard/TRIM support (still true at v1.16.1; upstream issue #2708 is parked). Deleting files inside guest OS does not release host ext4 backing blocks (`fstrim` reports "discard operation is not supported"). A space that once wrote 1.5 GiB retains host disk allocation indefinitely until offline compaction, which the idle sweep performs automatically on stopped images.

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
