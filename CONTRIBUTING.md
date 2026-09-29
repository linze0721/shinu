# Contributing

Use this guide to build, check, and prepare a contribution to shinu.

## Build

```sh
cargo build
cargo build --release
```

## Local gates

Before opening a pull request, run all three gates:

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test --workspace
```

The suite currently contains 314 tests across 20 suites (see [`AGENTS.md`](AGENTS.md), Testing & QA). CI runs the same gates on pushes and pull requests; see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Host requirements

The test suite is hermetic: it uses temporary directories, configures `NetConfig { enabled: false, .. }`, does not spawn real Firecracker or Jailer processes, does not perform btrfs reflink operations, and does not require root privileges (see [`AGENTS.md`](AGENTS.md), Testing & QA).

Running `shinud` on a real host is different. It requires root, `/dev/kvm`, cgroup v2 at `/sys/fs/cgroup`, and the `shinu-jail` user and group at uid/gid `30000`. The data root needs a btrfs mount for reflink disks (the README and preflight also accept reflink-capable XFS); space images use `cp --reflink=always` and do not fall back to copying (see [`README.md`](README.md), Requirements).

The host scripts cover separate steps:

- [`packaging/preflight.sh`](packaging/preflight.sh) checks host prerequisites, including KVM access, an actual reflink operation, required commands, root, cgroup v2, and `/dev/vhost-vsock`.
- [`packaging/install.sh`](packaging/install.sh) installs the release binaries and runit service, and validates or creates the `shinu-jail` user/group identity.
- [`packaging/host-smoke.sh`](packaging/host-smoke.sh) runs destructive host integration scenarios on a real KVM/reflink/cgroup-v2 host. It uses its own temporary root and loopback listener rather than an operator's shinu root.

## Lint posture

The root [`Cargo.toml`](Cargo.toml) denies `clippy::all` and warns on `pedantic` and `nursery`. Its pinned allow-list carries explicit hit counts (see [`AGENTS.md`](AGENTS.md), Compiler Lints Baseline). Do not widen that allow-list to silence a lint without a specific justification.

## Architecture orientation

Start with [`AGENTS.md`](AGENTS.md), the authoritative architecture and invariants guide. Adding an operation touches these nine places ([`AGENTS.md`, Control Plane & Protocol](AGENTS.md#L36-L45)):

1. `proto::Req` in `crates/shinu-proto/src/proto.rs`.
2. The CLI `Command` enum in `src/bin/shinu.rs`.
3. The HTTP route parser in `src/bin/shinud.rs`.
4. The `method_allowed` HTTP method matrix in `src/bin/shinud.rs`.
5. The `request_for` mapping and `handle()` dispatcher in `src/bin/shinud.rs`.
6. Quota check points, such as `check_space_quota`.
7. Usage event logging through `state::record_usage`.
8. The `shinu-mcp` tool table when exposing the operation through MCP.
9. The console routes in `src/console/app.js` when exposing the operation in the console.

### Invariants

The 26 invariants in [`AGENTS.md`](AGENTS.md#invariants-worth-guarding) ("Invariants Worth Guarding") are load-bearing security and correctness properties. A pull request that changes one must say so explicitly. Headline invariants include mandatory jailer sandboxing; hardlink-not-copy for the kernel and rootfs; quota checks inside the state lock; lock order discipline; claim-before-delete; reflink-or-fail; project tenant isolation that never leaks existence; and hashed tokens compared in constant time.

## Commits and CI

The history uses Conventional Commit prefixes such as `feat:`, `test:`, and `fix:`. Follow it. A sign-off or DCO is not required.
