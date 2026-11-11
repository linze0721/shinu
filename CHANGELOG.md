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

### Fixed

- Preserve checkpoint CPU, memory, and disk sizing with an idempotent legacy SQLite backfill; checkpoint and template forks no longer require the source Space row.
- Retain full/diff snapshot SSH credentials with checkpoint assets so source Space or lease cleanup does not strand memory forks; remove archived keys with checkpoint GC/deletion.
- Bound detached jobs by `SHINU_JOB_MAX_SECS` (default 3600 seconds, 0 disables the cap) and the host Space lease, reusing normal cancellation and final-log archival with a deadline-specific error.

[Unreleased]: https://github.com/linze0721/shinu/compare/main...HEAD
