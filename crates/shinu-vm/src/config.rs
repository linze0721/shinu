use crate::net::NetSpec;
use shinu_core::{Error, Image, Result, env_u32};
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
    /// `SHINU_IDLE_RECLAIM` — automatically repair/discard stopped images.
    pub idle_reclaim: bool,
    /// `SHINU_JAIL_UID` — non-root uid used by Firecracker inside the jail.
    pub jail_uid: u32,
    /// `SHINU_JAIL_GID` — non-root gid used by Firecracker inside the jail.
    pub jail_gid: u32,
}

impl VmConfig {
    pub fn from_env() -> Result<Self> {
        let invalid = || Error::Invalid("SHINU_IDLE_RECLAIM must be 0/false or 1/true".to_owned());
        let idle_reclaim = match std::env::var("SHINU_IDLE_RECLAIM") {
            Ok(value) => {
                let value = value.trim();
                if value == "0" || value.eq_ignore_ascii_case("false") {
                    false
                } else if value == "1" || value.eq_ignore_ascii_case("true") {
                    true
                } else {
                    return Err(invalid());
                }
            }
            Err(std::env::VarError::NotPresent) => true,
            Err(std::env::VarError::NotUnicode(_)) => return Err(invalid()),
        };
        Ok(Self {
            vcpus: env_u32("SHINU_VCPUS", 2),
            mem_mib: env_u32("SHINU_MEM_MIB", 1024),
            idle_secs: u64::from(env_u32("SHINU_IDLE_SECS", 3600)),
            idle_reclaim,
            jail_uid: env_u32("SHINU_JAIL_UID", 30_000),
            jail_gid: env_u32("SHINU_JAIL_GID", 30_000),
        })
    }
}

/// Host cgroup memory ceiling in bytes; guest sizing and quotas stay unchanged.
/// `SHINU_VMM_OVERHEAD_MIB` defaults to 512 only when absent; explicit 0 opts out.
pub fn jailer_memory_limit_bytes(mem_mib: u32) -> Result<u64> {
    let invalid = || {
        Error::Invalid(
            "SHINU_VMM_OVERHEAD_MIB must be an unsigned decimal MiB value in 0..=4294967295 (0 explicitly disables the VMM allowance)"
                .to_owned(),
        )
    };
    let overhead_mib = match std::env::var("SHINU_VMM_OVERHEAD_MIB") {
        Ok(value) => {
            let value = value.trim();
            if value.starts_with('+') {
                return Err(invalid());
            }
            value.parse::<u32>().map_err(|_| invalid())?
        }
        Err(std::env::VarError::NotPresent) => 512,
        Err(std::env::VarError::NotUnicode(_)) => return Err(invalid()),
    };
    let total_mib = mem_mib.checked_add(overhead_mib).ok_or_else(|| {
        Error::Invalid(format!(
            "guest memory ({mem_mib} MiB) plus SHINU_VMM_OVERHEAD_MIB ({overhead_mib} MiB) overflows the u32 MiB range (maximum 4294967295 MiB)"
        ))
    })?;
    // The checked u32 MiB sum fits in u64 bytes without multiplication overflow.
    Ok(u64::from(total_mib) * 1024 * 1024)
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
            "is_read_only": false,
            "io_engine": "Sync",
            "discard": true
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

#[cfg(test)]
mod memory_limit_tests {
    use super::{jailer_memory_limit_bytes, vm_config_json};
    use shinu_core::Image;
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const OVERHEAD_ENV: &str = "SHINU_VMM_OVERHEAD_MIB";

    struct OverheadEnv(Option<OsString>);

    impl OverheadEnv {
        fn set(value: Option<&std::ffi::OsStr>) -> Self {
            let saved = Self(std::env::var_os(OVERHEAD_ENV));
            unsafe {
                match value {
                    Some(value) => std::env::set_var(OVERHEAD_ENV, value),
                    None => std::env::remove_var(OVERHEAD_ENV),
                }
            }
            saved
        }
    }

    impl Drop for OverheadEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.0 {
                    Some(value) => std::env::set_var(OVERHEAD_ENV, value),
                    None => std::env::remove_var(OVERHEAD_ENV),
                }
            }
        }
    }

    #[test]
    fn writable_rootfs_negotiates_discard_with_sync_engine() {
        let config: serde_json::Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Ubuntu,
            Path::new("/vsock"),
            2,
            4096,
            None,
        ))
        .expect("guest config");
        assert_eq!(config["drives"][0]["discard"], true);
        assert_eq!(config["drives"][0]["io_engine"], "Sync");
        assert_eq!(config["drives"][0]["is_read_only"], false);
    }

    #[test]
    fn jailer_memory_limit_defaults_to_fixed_overhead_without_resizing_guest() {
        let _lock = ENV_LOCK.lock().expect("overhead env lock");
        let _env = OverheadEnv::set(None);
        assert_eq!(
            jailer_memory_limit_bytes(14_336).expect("default memory limit"),
            15_569_256_448
        );
        let config: serde_json::Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Void,
            Path::new("/vsock"),
            2,
            14_336,
            None,
        ))
        .expect("guest config");
        assert_eq!(config["machine-config"]["mem_size_mib"], 14_336);
    }

    #[test]
    fn jailer_memory_limit_accepts_explicit_allowance_and_zero() {
        let _lock = ENV_LOCK.lock().expect("overhead env lock");
        for (value, expected) in [
            ("1024", 16_106_127_360),
            (" 512 ", 15_569_256_448),
            ("0", 15_032_385_536),
        ] {
            let _env = OverheadEnv::set(Some(value.as_ref()));
            assert_eq!(
                jailer_memory_limit_bytes(14_336).expect("configured memory limit"),
                expected
            );
        }
    }

    #[test]
    fn jailer_memory_limit_rejects_invalid_environment() {
        use std::os::unix::ffi::OsStringExt;

        let _lock = ENV_LOCK.lock().expect("overhead env lock");
        for value in ["", " ", "-1", "+1", "1.5", "512MiB", "4294967296"] {
            let _env = OverheadEnv::set(Some(value.as_ref()));
            let error = jailer_memory_limit_bytes(14_336).expect_err("invalid overhead");
            assert!(matches!(error, shinu_core::Error::Invalid(_)));
            assert!(error.to_string().contains(OVERHEAD_ENV));
        }
        let non_unicode = OsString::from_vec(vec![0xff]);
        let _env = OverheadEnv::set(Some(&non_unicode));
        let error = jailer_memory_limit_bytes(14_336).expect_err("non-Unicode overhead");
        assert!(matches!(error, shinu_core::Error::Invalid(_)));
        assert!(error.to_string().contains(OVERHEAD_ENV));
    }

    #[test]
    fn jailer_memory_limit_checks_sum_before_converting_to_bytes() {
        let _lock = ENV_LOCK.lock().expect("overhead env lock");
        let env_guard = OverheadEnv::set(Some("4294967295".as_ref()));
        let error = jailer_memory_limit_bytes(1).expect_err("MiB addition overflow");
        assert!(error.to_string().contains(OVERHEAD_ENV));
        assert!(error.to_string().contains("overflows"));
        drop(env_guard);

        let env_guard = OverheadEnv::set(None);
        assert!(jailer_memory_limit_bytes(u32::MAX).is_err());
        drop(env_guard);

        let _env = OverheadEnv::set(Some("4294967294".as_ref()));
        assert_eq!(
            jailer_memory_limit_bytes(1).expect("largest supported MiB sum"),
            4_503_599_626_321_920
        );
    }
}
