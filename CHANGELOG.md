# Changelog

Changes are recorded in the Keep a Changelog format.

## [Unreleased]

### Added

- Firecracker microVM spaces backed by copy-on-write reflink disk images.
- Git-like commit DAG workflows with checkout, fork, and reflog recovery.
- Four guest images: Void, Ubuntu, Arch, and Rocky.
- Full and diff guest memory snapshots.
- Detached jobs with status and terminal-rendered logs.
- Space leases with TTLs and named checkpoint templates.
- Usage metering and optional request-rate limiting.
- An MCP server and web console.
- A VNC desktop bridge, guest HTTP proxying, and named networks.
- `shinu rmckpt --detach` (`DELETE /v1/commits/{id}` with `{"detach":true}`) deletes a commit that other spaces or commits only name as `parent`, clearing those lineage links; space heads, templates, and diff memory bases still refuse.
- Explicit per-Space write protection and `shinu compact` for stopped-image trim followed by Btrfs zstd recompression.
- Firecracker v1.18.0 / snapshot format 12.0.0 with writable Sync virtio-blk discard and a pinned FC-CI 6.18.62 guest kernel.
- Application-consistent hot snapshot generations with bounded guest hooks/fsfreeze, pause/create/reflink/resume/thaw ordering, restore-time thaw, generation provenance and freeze/pause/thaw timings; checkpoint listings expose consistency.
- A tracked Docker-compatible `6.18.62-shinu` kernel config and checksum-pinned local kernel installation via `SHINU_KERNEL_FILE` / `SHINU_KERNEL_SHA256`, retaining the existing guest's built-in netfilter features.
- Optional checkpoint-owned application readiness policies, configured with `new`, `fork`, or stopped-only `resize --readiness-json`; cold/hot starts and auto-starts require a fresh authenticated guest READY challenge before admission, with same-boot host-memory receipts and fail-closed cleanup.
- Paused Full restores through `start --load-only` / `load_only:true`, persisted loading/loaded/resuming phases, and explicit `resume` across HTTP, CLI and MCP; interrupted paused restores are stopped on daemon restart before request admission.
- Per-start `track_dirty` (default true) and `ckpt warm` / checkpoint warm HTTP/MCP interfaces using a persistent dedicated page-cache cgroup.
- Physical store/MemAvailable admission floors with HTTP `capacity_watermark` errors and stable CLI exit 75.

### Changed

- Remove project Space, disk and running-VM quotas, including historical database values. Legacy count/disk/reserve environment variables now warn and are ignored; admin quota PATCH fields are explicitly rejected. Optional single-VM sizing and request-rate limits default to unlimited when unset.
- Charge only sampled Btrfs exclusive storage; remove nominal/reserve pre-charge. Full non-diff memory forks share read-only checkpoint inodes, with root-owned 0440 jail access and private guest CoW; restore links are removed before any later hot capture. Existing live HEAD/template/base deletion guards remain authoritative.
- Stop failed/inactive VMMs with TERM and bounded cleanup; report an unresponsive VMM instead of sending SIGKILL.

### Breaking

- `SHINU_SPACE_WRITE_CAP_MIB` no longer assigns a default quota. Schema version 1 and legacy JSON import clear all old Space caps and cap-stop reasons once, since historical state cannot prove whether they were inherited or explicit. **Old explicit protections must be specified again after upgrading.** New explicit `fork --write-cap-mib N` protections remain supported and persistent; inherited legacy caps can no longer stop running Spaces.
- Loading/loaded recovery preserves pending Full memory/state for safe reload. Resuming/failed-resume recovery discards pending memory before clearing the phase, preventing stale memory from being paired with a disk already written by the guest.

### Fixed

- Give jailed Firecracker processes a fixed 512 MiB host-memory allowance above guest RAM, configurable with `SHINU_VMM_OVERHEAD_MIB`, without changing guest sizing or project quotas. Invalid settings and MiB addition overflow reject new launches before jail or TAP setup.
- Make automatic stopped-image repair/discard opt-out via startup-validated `SHINU_IDLE_RECLAIM=0`, and serialize idle reclamation with the same per-space lifecycle lock used by boot, stop, and checkpoint handlers.
- Preserve checkpoint CPU, memory, and disk sizing with an idempotent legacy SQLite backfill; checkpoint and template forks no longer require the source Space row.
- Retain full/diff snapshot SSH credentials with checkpoint assets so source Space or lease cleanup does not strand memory forks; remove archived keys with checkpoint GC/deletion.
- Bound detached jobs by `SHINU_JOB_MAX_SECS` (default 3600 seconds, 0 disables the cap) and the host Space lease, reusing normal cancellation and final-log archival with a deadline-specific error.
- Cold-boot incompatible memory checkpoints from their retained disk images instead of attempting to load old Firecracker state.
- Reject stock/unapproved Firecracker builds for application snapshots: require the `v1.18.0-shinu.1` marker at asset admission and on the actual running executable; use a mandatory local patched archive rather than downloading stock.
- Fail hot captures on block drain/flush errors, including an explicit backing-file fsync for disk-only hot cuts, while preserving resume/thaw cleanup.
- Guard Diff creation with the actual live dirty epoch: failed captures, restarts and consecutive Diff requests force Full rather than dropping dirty pages from earlier captures.
- Replace snapshot-time SSH reconnects with a memory-locked, nonce-authenticated resident guest helper; thaw restored guests through the same fixed protocol, retain SSH cleanup on helper failure, and batch restored clock/network setup into one SSH session.
- Freeze each writable block-backed superblock visible in the initial guest mount namespace once, including bind mounts; refuse application consistency when a private namespace adds an uncovered writable block filesystem, while preserving reverse thaw/hook cleanup and the no-exposure-before-thaw gate.
- Add opt-in `SHINU_SNAPSHOT_PRECONNECT=1` to park an authenticated thaw channel before pause; it remains off by default pending real-host comparison, and restored generations always establish a fresh connection.
- Keep monitored guest scripts fenced across worker crashes and nested timeout groups, cancel pending scripts when cleanup wins, and stream setup nonces privately rather than exposing them in process arguments.

[Unreleased]: https://github.com/linze0721/shinu/compare/main...HEAD
