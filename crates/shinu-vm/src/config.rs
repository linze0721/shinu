use crate::net::NetSpec;
use shinu_core::{Image, env_u32};
use std::path::Path;

/// Per-VM sizing, jail identity, and lifetime, read from the environment.
#[derive(Debug, Clone, Copy)]
pub struct VmConfig {
    /// `SHINU_VCPUS`
    pub vcpus: u32,
    /// `SHINU_MEM_MIB`
    pub mem_mib: u32,
    /// `SHINU_IDLE_SECS` — a VM with no `Touch` for this long is shut down.
    /// The default leaves detached guest work alive across caller pauses.
    pub idle_secs: u64,
    /// `SHINU_JAIL_UID` — non-root uid used by Firecracker inside the jail.
    pub jail_uid: u32,
    /// `SHINU_JAIL_GID` — non-root gid used by Firecracker inside the jail.
    pub jail_gid: u32,
}

impl VmConfig {
    pub fn from_env() -> Self {
        Self {
            vcpus: env_u32("SHINU_VCPUS", 2),
            mem_mib: env_u32("SHINU_MEM_MIB", 1024),
            idle_secs: u64::from(env_u32("SHINU_IDLE_SECS", 3600)),
            jail_uid: env_u32("SHINU_JAIL_UID", 30_000),
            jail_gid: env_u32("SHINU_JAIL_GID", 30_000),
        }
    }
}

/// Firecracker's `--config-file` body. The init path follows the selected
/// image because Arch's usr-merged `/sbin/init` symlink is not kernel-safe.
/// The ext4 image boots without an initrd, so the guest kernel must include
/// virtio-blk and ext4.
pub fn vm_config_json(
    kernel: &Path,
    rootfs: &Path,
    image: Image,
    vsock_uds: &Path,
    vcpus: u32,
    mem_mib: u32,
    net: Option<&NetSpec>,
) -> String {
    let mut boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init={}",
        image.init_path()
    );
    if let Some(net) = net {
        boot_args.push_str(" shinu.ip=");
        boot_args.push_str(&net.guest_cidr);
        boot_args.push_str(" shinu.gw=");
        boot_args.push_str(&net.gateway);
    }
    let mut config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": kernel.to_string_lossy(),
            "boot_args": boot_args
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": rootfs.to_string_lossy(),
            "is_root_device": true,
            "is_read_only": false
        }],
        // Every VM has a private vsock UDS, so guest CID 3 is safe to reuse.
        "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": vsock_uds.to_string_lossy() },
        // The balloon starts empty. Deflate-on-OOM lets the guest reclaim
        // memory while the host holds an inflated balloon.
        // Free-page reporting returns guest-free pages; explicit reclaim is
        // still needed for page cache and shared or memfd-backed mappings.
        "balloon": {
            "amount_mib": 0,
            "deflate_on_oom": true,
            "stats_polling_interval_s": 1,
            "free_page_reporting": true
        },
        // Firecracker must enable dirty-page tracking before the VM boots.
        "machine-config": { "vcpu_count": vcpus, "mem_size_mib": mem_mib, "track_dirty_pages": true }
    });
    if let Some(net) = net {
        config["network-interfaces"] = serde_json::json!([{
            "iface_id": "eth0",
            "host_dev_name": net.tap,
            "guest_mac": net.mac,
        }]);
    }
    config.to_string()
}
