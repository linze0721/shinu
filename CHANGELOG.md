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
- Per-project quotas, usage metering, and API rate limiting.
- An MCP server and web console.
- A VNC desktop bridge, guest HTTP proxying, and named networks.
- `shinu rmckpt --detach` (`DELETE /v1/commits/{id}` with `{"detach":true}`) deletes a commit that other spaces or commits only name as `parent`, clearing those lineage links; space heads, templates, and diff memory bases still refuse.
- Opt-in exclusive-byte quota reservations, persisted per-space write caps with sweep enforcement, and `shinu compact` for stopped-image trim followed by Btrfs zstd recompression.
- Firecracker v1.18.0 / snapshot format 12.0.0 with writable Sync virtio-blk discard and a pinned FC-CI 6.18.62 guest kernel.
- Application-consistent hot snapshot generations with bounded guest hooks/fsfreeze, pause/create/reflink/resume/thaw ordering, restore-time thaw, generation provenance and freeze/pause/thaw timings; checkpoint listings expose consistency.
- A tracked Docker-compatible `6.18.62-shinu` kernel config and checksum-pinned local kernel installation via `SHINU_KERNEL_FILE` / `SHINU_KERNEL_SHA256`, retaining the existing guest's built-in netfilter features.

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

[Unreleased]: https://github.com/linze0721/shinu/compare/main...HEAD
