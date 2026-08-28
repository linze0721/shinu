use crate::net::NetSpec;
use shinu_core::{env_u32, Image};
use std::path::Path;


/// Per-VM sizing, jail identity, and lifetime, read from the environment.
#[derive(Debug, Clone, Copy)]
pub struct VmConfig {
    /// `SHINU_VCPUS`
    pub vcpus: u32,
    /// `SHINU_MEM_MIB`
    pub mem_mib: u32,
    /// `SHINU_IDLE_SECS` — a VM with no `Touch` for this long is shut down.
    /// One hour: an agent often pauses mid-task while a caller thinks, and a
    /// shorter window kills detached work such as a tmux session or a build.
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
/// The ext4 image boots directly with no initrd, so the guest kernel must have
/// virtio-blk and ext4 built in.
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
        // Every VM owns a private vsock UDS, so the guest CID never has to be
        // unique across VMs.
        "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": vsock_uds.to_string_lossy() },
        // Balloon starts empty and only ever inflates while the VM sits idle.
        // `deflate_on_oom` is what makes that safe: if the guest needs the
        // memory back before the daemon deflates, the balloon yields instead
        // of letting the OOM killer run.
        // Free-page reporting arrived in Firecracker v1.14.0 (PR #5491): it
        // lets the guest report freed pages continuously so the host can
        // release them, shrinking resident memory and memory captured in full
        // snapshots. Upstream marks it as a developer preview, and it does
        // not replace `vm::reclaim`: `vstate/memory.rs` still discards via
        // `madvise(MADV_DONTNEED)`, which upstream notes is ineffective for
        // shared/memfd mappings, so periodic explicit inflate remains the
        // fallback.
        "balloon": { "amount_mib": 0, "deflate_on_oom": true, "stats_polling_interval_s": 1, "free_page_reporting": true },
        // Diff snapshots depend on Firecracker's dirty-page bitmap, which cannot be enabled after boot.
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

