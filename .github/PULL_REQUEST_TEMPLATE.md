## Summary

<!-- What this change does. -->

## Motivation

<!-- Why it is needed. Link issues. -->

## Surfaces changed

<!-- CLI, REST API, MCP, web console, daemon internals, guest image, packaging. -->

---

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets`
- [ ] `cargo test --workspace`
- [ ] Manual host smoke verification, if the change touches paths CI cannot cover
      (real jailer/Firecracker boot, cgroup v2 limits, btrfs reflink, TAP/iptables,
      named networks, VNC, HTTP proxy, snapshots, base image build). Describe what was run:
      <!-- or "not needed" and why -->
- [ ] `AGENTS.md` invariants and `README.md` updated, or confirmed unaffected
