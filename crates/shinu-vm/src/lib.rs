/// microVM lifecycle. Everything here runs in the root daemon: it spawns
/// Firecracker, owns `/dev/kvm` access, and hands the unprivileged client
/// nothing but a socket and a key it already owns.
pub mod vm;
pub mod config;
pub mod net;

pub use config::{vm_config_json, VmConfig};
pub use net::{net_slot, net_spec, parse_net_allow, tap_name, NetConfig, NetSpec};
pub use shinu_core::is_rfc1918;
pub use shinu_image::{filter_guest_nameservers, guest_resolv_needs_repair};
pub use vm::exec_in_vm;
