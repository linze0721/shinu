//! Facade over the workspace crates.
//!
//! The binaries were written against a single `shinu::` namespace, and the
//! split is meant to change how the code is organised rather than how it is
//! called. Re-exporting here keeps every existing call site valid, so the
//! restructuring can be reviewed as a move rather than as a rewrite of four
//! binaries at the same time.

pub use shinu_core::{
    btrfs, DEFAULT_ROOT, Error, FC_URL, FC_VERSION, GUEST_BLOCKED_CIDRS, Image, KERNEL_URL,
    MAX_UPLOAD_BYTES, Result, USAGE_SAMPLE_SECS, VSOCK_SSH_PORT, assets_dir, avail_bytes,
    base_path, cache_dir, chown_tree, ckpt_image, env_u32, firecracker_bin, init_layout,
    is_blocked_guest_destination, is_rfc1918, jailer_bin, kernel_path, migrate_base, parse_ipv4,
    parse_ipv4_cidr, parse_net_base, resolve_root, shell_quote, shell_quote_word, space_image,
    vm_dir, vsock_helper,
};

// sha2 itself stays private to shinu-crypto, as it was private here; only the
// one hashing helper the daemon calls is surfaced.
pub use shinu_crypto::{auth, sha256_hex, token};

pub use shinu_store::{
    find, find_ckpt, is_referenced, log_chain, quota, reflog_entries, registry, state,
};

pub use shinu_image::{
    BaseConfig, ensure_assets, ensure_base, filter_guest_nameservers, guest_resolv_needs_repair,
    repair_base_resolv, seed_resolv,
};

pub use shinu_proto::{http, proto};

pub use shinu_vm::{NetConfig, NetSpec, VmConfig, exec_in_vm, net_spec, tap_name, vm};
pub use shinu_vm::{net_slot, parse_net_allow, vm_config_json};
