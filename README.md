# shinu

Agent-first Firecracker microVM sandboxes with copy-on-write disk states and git-like snapshot, rollback, and branching workflows.

A **space** is an ext4 guest disk image cloned from a golden base via btrfs reflink, bound to an isolated Firecracker microVM instance. `shinu exec <space> -- <cmd>` boots the VM on demand (~1.7 s cold), runs the command over SSH over vsock, and leaves the VM warm for subsequent calls (~0.4 s hot). Idle VMs release unused host memory via virtio-balloon and shut down automatically after an idle threshold.

`shinud` exposes a HTTP/1.1 REST API where spaces support git-like operation semantics:
- **`commits`** store CoW ext4 disk state snapshots (`hot` or cold).
- **`checkout`** rewinds space state back to any commit, automatically saving current state before rewind (reflog semantics).
- **`fork`** creates new independent spaces branching off any existing commit.

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
# Create a space (~0.14 s, ~84 KiB on host disk)
shinu new web

# Execute command inside VM (boots on demand)
shinu exec web -- uname -a

# List project spaces and commits
shinu ls

# Save a commit snapshot
shinu commit web --note "installed dependencies"

# View commit history chain
shinu log web

# Checkout rewinds space state (automatically creates an auto-commit reflog first)
shinu checkout web <commit-id>

# Branch off a commit into a new space
shinu fork <commit-id> web-experiment

# Delete an unreferenced commit
shinu rmckpt <commit-id>

# Stop VM and flush disk writes
shinu stop web

# Garbage collect unreferenced commits older than 7 days
shinu gc
```

---

## Requirements

- `/dev/kvm` and the `SHINU_ROOT` directory **must be on a btrfs filesystem**. Spaces are instantiated via `cp --reflink=always`. Any non-btrfs filesystem fails loudly during space creation (`Operation not supported`).
- `x86_64` CPU architecture. The guest kernel and Firecracker v1.13.1 binaries are fetched automatically on first boot.
- External binaries required on host: `curl tar mkfs.ext4 e2fsck mount umount truncate ssh ssh-keygen setsid cp chown btrfs df kill ip iptables`.
- `shinud` daemon **must run as root** to create loop devices, configure NAT network interfaces (`iptables`), and set up tap devices.
- HTTP clients run non-root and require no host group memberships (specifically no `/dev/kvm` or root access required).

---

## HTTP REST API

All API routes require authentication header: `Authorization: Bearer <token>`.

### Route Matrix

| Method | Path | Request Body | Response Body / Status | Description |
|---|---|---|---|---|
| `POST` | `/v1/spaces` | `{"name":"web"}` | `201 Created` | Create new space cloned from base image |
| `GET` | `/v1/spaces` | — | `200 OK` `{"spaces":[...],"ckpts":[...]}` | List all spaces and commits in token's project |
| `DELETE` | `/v1/spaces/{name}` | — | `200 OK` | Delete space and stop its VM if running |
| `POST` | `/v1/spaces/{name}/start` | — | `200 OK` | Start Firecracker VM for space |
| `POST` | `/v1/spaces/{name}/stop` | — | `200 OK` | Stop VM, flush disk, release memory |
| `POST` | `/v1/spaces/{name}/exec` | `{"cmd":["sh","-c","..."]}` | `200 OK` Chunked NDJSON stream | Execute command inside VM, streaming output |
| `POST` | `/v1/spaces/{name}/commits` | `{"note":"...","hot":false}` | `201 Created` | Create CoW disk snapshot commit |
| `GET` | `/v1/spaces/{name}/log` | — | `200 OK` `[{"id":"...","parent":...}]` | Fetch commit history chain starting from `head` |
| `POST` | `/v1/spaces/{name}/checkout` | `{"commit":"<id>"}` | `200 OK` `{"head":"...","auto_commit":"..."}` | Rewind space to commit (auto-commits state first) |
| `POST` | `/v1/commits/{id}/fork` | `{"name":"web2"}` | `201 Created` | Fork space from existing commit |
| `DELETE` | `/v1/commits/{id}` | — | `200 OK` | Delete unreferenced commit |
| `POST` | `/v1/gc` | `{"free_below":...,"dry_run":false}` | `200 OK` | Run garbage collection on unreferenced commits |

### Streaming `exec` Format (NDJSON)

The `POST /v1/spaces/{name}/exec` endpoint uses `Transfer-Encoding: chunked` returning newline-delimited JSON (NDJSON) messages:

```json
{"stream":"stdout","data":"Linux guest 6.1.102 #1 SMP ...\n"}
{"stream":"stderr","data":""}
{"exit":0}
```

Every execution stream guarantees a final `{"exit": N}` payload terminating the response.

### Error Handling & Response Format

Errors return JSON responses with standard HTTP status codes:

```json
{
  "error": "space \"web\" not found"
}
```

Status Code Mapping (`http::status_for`):
- `401 Unauthorized`: Missing, malformed, or invalid `Authorization: Bearer <token>`.
- `400 Bad Request`: Invalid JSON body, malformed command, or invalid request payload.
- `404 Not Found`: Target space or commit does not exist within caller's project scope.
- `405 Method Not Allowed`: Unrecognized HTTP verb for path.
- `500 Internal Server Error`: Host I/O errors, btrfs reflink failure, or process execution failures.

### cURL Example

Walk through space creation, execution, committing, log viewing, and checkout via cURL:

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
```

---

## Git-like Workspace Semantics

Shinu implements explicit version control semantics over guest ext4 image states:

- **`Space { project, parent, head }`**: Represents an active working branch. `head` points to the latest commit ID (or `None` for a fresh space).
- **`Ckpt { project, parent, auto, note }`**: Represents an immutable disk image commit snapshot. `parent` points to the prior commit ID.
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
  - Refuses deletion if the commit is currently referenced by any space's `parent`, any space's `head`, or any other commit's `parent` (`is_referenced` check).

---

## Configuration

Daemon configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SHINU_ROOT` | `/var/lib/shinu` | Root data directory (or `--root` CLI flag). Must be on btrfs. |
| `SHINU_LISTEN` | `127.0.0.1:7878` | Network address and port for HTTP server binding. |
| `SHINU_REFLOG_DAYS` | `7` | Retention period in days for unreferenced `auto` checkout commits during GC. |
| `SHINU_VCPUS` | `2` | Number of virtual CPUs per microVM. |
| `SHINU_MEM_MIB` | `1024` | Maximum RAM limit (MiB) per VM. Memory is allocated on demand. |
| `SHINU_IDLE_SECS` | `600` | Inactivity timeout (seconds). Reclaims memory at 1/10th timeout; shuts down VM at full value. |
| `SHINU_DISK_MIB` | `2048` | Guest disk capacity (MiB). **Only read when `base.ext4` is first built.** |
| `SHINU_MIRROR` | — | Ubuntu mirror URL for guest rootfs generation. |
| `SHINU_ARCH` | `uname -m` | Target architecture (`x86_64`). |
| `SHINU_ROOTFS_TARBALL` | — | Local path to pre-built rootfs tarball for offline installations. |
| `SHINU_NET_ENABLE` | `true` | Enable guest network interfaces. Set to `0` or `false` to disable networking. |
| `SHINU_NET_BASE` | `172.31` | First two octets for per-VM `/30` NAT IP allocations. |
| `SHINU_NET_UPLINK` | Default route | Host egress network interface for NAT forwarding. |

Client environment variables:

| Variable | Description |
|---|---|
| `SHINU_ENDPOINT` | HTTP server base URL (e.g., `http://127.0.0.1:7878`). |
| `SHINU_TOKEN` | Bearer token string obtained from `shinu token new`. |

---

## Operating Notes

**Memory is a ceiling, not a reservation.** A VM starts at ~99 MiB host RSS footprint and expands as the guest accesses memory pages. Firecracker does not return pages automatically; `shinud` triggers guest memory deflation via `virtio-balloon` after `SHINU_IDLE_SECS / 10` (measured reduction: 595 MiB → 100 MiB). `exec` re-inflates balloon memory transparently. Plan host capacity based on *sum of active VM page working sets*, not `SHINU_MEM_MIB × VM count`.

**Disk space grows permanently.** Firecracker v1.13.1 block devices lack discard/TRIM support. Deleting files inside guest OS does not release host ext4 backing blocks (`fstrim` reports "discard operation is not supported"). A space that once wrote 1.5 GiB retains host disk allocation indefinitely (measured: space returning to 26% internal usage retained 1.9 GiB host allocation).

`commit` + `fork` does **not** shrink images; cloned reflinks inherit sparse page allocations (measured: forked clone retains 1.9 GiB host allocation).

To reclaim host disk blocks, punch out unused space while the target space is stopped:

```sh
shinu stop web
e2fsck -E discard -fp <root>/spaces/<uuid>.ext4
```

*Measured compaction:* 1.9 GiB → 534 MiB host block usage, guest data and boot integrity fully intact.

**Expanding space capacity**: In-band online expansion is unsupported. To grow a space disk offline, stop the VM (`shinu stop <space>`), then manually run `truncate -s <size> <root>/spaces/<uuid>.ext4` and `resize2fs <root>/spaces/<uuid>.ext4`.

**Updating base image**: `ensure_base` runs only when `<root>/base.ext4` is missing. To upgrade the base image, stop `shinud`, rename or delete `<root>/base.ext4`, and restart `shinud`. Existing spaces remain unaffected as independent btrfs reflink copies.

**Daemon restart safety**: Firecracker VM processes run under `setsid` attached to `init`. Restarting `shinud` does not interrupt running VMs; the daemon reattaches via saved PID files on startup. Unintentionally terminated VMs (e.g., OOM or `kill -9`) are marked `stopped` and automatically restarted on the next `exec` call.

**Log management**:
- `shinud` daemon outputs connection logs and background garbage collection events to `stderr`.
- Guest serial console logs write to `<root>/vm/<uuid>/console.log`. Console logs truncate on VM boot but grow unbounded during active VM uptime.

---

## Storage & Path Layout

```text
<root>/base.ext4          golden rootfs image (mode 0600)
<root>/spaces/<uuid>.ext4 ext4 space disk image (mode 0700 dir)
<root>/ckpts/<uuid>.ext4  immutable commit snapshot images (mode 0700 dir)
<root>/tokens.json        hashed bearer tokens (mode 0600)
<root>/vm/<uuid>/         per-VM directory (mode 0700):
                          fc.json, fc.sock (root only), vsock.sock,
                          fc.pid, id_ed25519, last_used, console.log
<root>/assets/            firecracker binary + guest kernel (mode 0755)
<root>/cache/             downloaded assets and rootfs cache (mode 0755)
```

Direct host path permissions on `<root>/spaces/`, `<root>/ckpts/`, and `<root>/vm/` are strictly restricted to `0700` owned by `root`. Clients interact exclusively over HTTP API endpoints.

---

## Security Model

- **Bearer Token Authentication**: Authentication uses `Authorization: Bearer <token>`. `shinud` stores only SHA-256 hashes of tokens in `<root>/tokens.json` (mode `0600`). Hashes are validated in constant time to prevent timing attacks. Token creation and management (`shinu token new/ls/rm`) must run host-locally as `root` and cannot be invoked over HTTP.
- **Project Scope Isolation**: Every token maps to a single `project`. All space and commit lookup operations are strictly project-scoped. Accessing a space or commit belonging to another project returns `404 Not Found`, preventing project resource enumeration or existence leakage.
- **Host Path Isolation**: VM control sockets (`fc.sock`), state directories (`<root>/vm/`), and ext4 image files (`<root>/spaces/`) are secured at mode `0700` owned by `root`. Non-root clients communicate solely over the `shinud` HTTP daemon proxy and cannot directly access or tamper with host disk files.
- **Network Isolation**: Every VM receives an isolated host-guest `/30` subnet derived from its UUID (host `.1`, guest `.2`). Guest traffic is NAT'd through host egress interfaces (`iptables`). Networking can be disabled by setting `SHINU_NET_ENABLE=0`.
- **Cleartext HTTP Warning**: `shinud` listens by default on `127.0.0.1:7878`. Tokens travel in cleartext HTTP headers. **If exposing `shinud` across a external network, you must deploy a reverse proxy providing TLS termination (e.g. nginx or Caddy) in front of `shinud`.**

**Non-goals**: `shinu` does not enforce per-project disk or memory quotas. Any project with a valid token can allocate spaces and boot VMs up to total host capacity. Multi-tenant host environments must enforce resource bounds at the host container or cgroup level outside `shinu`.
