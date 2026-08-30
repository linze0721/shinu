pub mod config;
pub mod net;
/// microVM lifecycle. Everything here runs in the root daemon: it spawns
/// Firecracker, owns `/dev/kvm` access, and hands the unprivileged client
/// nothing but a socket and a key it already owns.
pub mod vm;

pub use config::{VmConfig, vm_config_json};
pub use net::{NetConfig, NetSpec, net_slot, net_spec, parse_net_allow, tap_name};
pub use shinu_core::is_rfc1918;
pub use vm::exec_in_vm;
