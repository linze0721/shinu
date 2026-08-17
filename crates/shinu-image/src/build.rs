use std::path::Path;

use shinu_core::{base_path, env_u32, migrate_base, Error, Image, Result};

use super::configure::{
    chroot_run, configure_image, filter_guest_nameservers, guest_dns_fallback,
    guest_resolv_needs_repair, install_payload,
};
use super::extract::{extract_rootfs, mount_image, umount};
use super::fetch::{fetch_tarball, BaseConfig};

fn build_base(root: &Path, base: &Path, image: Image, cfg: &BaseConfig) -> Result<()> {
    let tarball = fetch_tarball(root, image, cfg)?;

    // Build beside the published name so a failed or interrupted build can
    // never be mistaken for a usable base by a later space request.
    let staging = base.with_extension("ext4.part");
    let _ = std::fs::remove_file(&staging);
    let result = (|| -> Result<()> {
        let disk_mib = env_u32("SHINU_DISK_MIB", 2048);
        let status = std::process::Command::new("truncate")
            .arg("-s")
            .arg(format!("{disk_mib}M"))
            .arg(&staging)
            .status()?;
        if !status.success() {
            return Err(Error::Invalid("truncate failed for base image".to_owned()));
        }
        let output = std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F"])
            .arg(&staging)
            .output()?;
        if !output.status.success() {
            return Err(Error::Invalid(format!(
                "mkfs.ext4 failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let mnt = root.join(format!("build-{image}.mnt"));
        mount_image(&staging, &mnt)?;
        let mounted_result = (|| -> Result<()> {
            extract_rootfs(root, image, &tarball, &mnt)?;
            // This first pass must seed DNS before any package-manager command.
            configure_image(&mnt, image)?;
            match image {
                Image::Void => {
                    // The shipped xbps refuses to install anything until it updates
                    // itself, so -S is required before both package operations.
                    chroot_run(&mnt, "xbps-install -y -S -u xbps")?;
                    chroot_run(&mnt, "xbps-install -y -S socat openssh iproute2 git tmux")?;
                }
                // ca-certificates is not pulled in by --no-install-recommends, and
                // without it every HTTPS clone or download in the guest fails with
                // "server certificate verification failed".
                Image::Ubuntu => chroot_run(
                    &mnt,
                    "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 socat openssh-server systemd-sysv tmux",
                )?,
                Image::Arch => {
                    chroot_run(&mnt, "pacman-key --init && pacman-key --populate archlinux")?;
                    chroot_run(&mnt, "pacman -Sy --noconfirm socat openssh tmux")?;
                }
                Image::Rocky => chroot_run(
                    &mnt,
                    "dnf install -y --setopt=install_weak_deps=False socat openssh-server systemd iproute tmux",
                )?,
            }
            // Package installation can create or replace service/config files, so
            // reapply the boot wiring after packages and before key generation.
            configure_image(&mnt, image)?;
            chroot_run(&mnt, "ssh-keygen -A")?;
            install_payload(&mnt, image)?;
            Ok(())
        })();
        let unmount = umount(&mnt);
        let _ = std::fs::remove_dir(&mnt);
        match (mounted_result, unmount) {
            (Err(error), _) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }

        // The loop mount normally flushes on unmount, but make the backing file
        // durable before checking or publishing it. Without this, a fast build
        // can expose journaled metadata that a fresh loop reader cannot see.
        std::fs::File::open(&staging)?.sync_all()?;
        let check = std::process::Command::new("e2fsck")
            .args(["-fn"])
            .arg(&staging)
            .output()?;
        if !check.status.success() {
            return Err(Error::Invalid(format!(
                "e2fsck rejected the new base image: {}",
                String::from_utf8_lossy(&check.stdout).trim()
            )));
        }
        std::fs::rename(&staging, base)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&staging);
    result
}

pub fn ensure_base(root: &Path, image: Image, cfg: &BaseConfig) -> Result<()> {
    // Migration is shared by all image requests. Serialize it separately so
    // two first-use requests cannot both race on the legacy filename.
    static MIGRATION_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
    let migration_lock = &*MIGRATION_LOCK;
    let migration_guard = migration_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    migrate_base(root)?;
    drop(migration_guard);

    // Match Registry::space_lock: each image gets its own lock, while two
    // requests for one image share the same guard across the full build.
    static BASE_LOCKS: std::sync::LazyLock<
        std::sync::Mutex<
            std::collections::HashMap<Image, std::sync::Arc<std::sync::Mutex<()>>>,
        >,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let locks = &*BASE_LOCKS;
    let build_lock = {
        let mut locks = locks.lock().unwrap_or_else(|error| error.into_inner());
        locks
            .entry(image)
            .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
            .clone()
    };
    let _build_guard = build_lock.lock().unwrap_or_else(|error| error.into_inner());

    let base = base_path(root, image);
    if base.exists() {
        return Ok(());
    }
    match build_base(root, &base, image, cfg) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&base);
            Err(error)
        }
    }
}

/// Repairs the resolver baked into existing base images after the guest
/// egress policy changes. Returns whether any `/etc/resolv.conf` was
/// rewritten; callers should treat failures as warnings because a busy or
/// damaged base must not prevent the daemon from starting.
///
/// Every built image is repaired, not just the default: a stale private
/// nameserver breaks package installs in whichever guest inherits it, and
/// each image carries its own copy.
pub fn repair_base_resolv(root: &Path) -> Result<bool> {
    let mut changed = false;
    for image in Image::all() {
        changed |= repair_one_base_resolv(root, image)?;
    }
    Ok(changed)
}

fn repair_one_base_resolv(root: &Path, image: Image) -> Result<bool> {
    let base = base_path(root, image);
    if !base.exists() {
        return Ok(false);
    }
    // Per-image mount point: repairing several images must not collide on one
    // directory, and a leaked mount would pin the wrong base.
    let mnt = root.join(format!("base-resolv-{image}.mnt"));
    if let Err(error) = mount_image(&base, &mnt) {
        let _ = std::fs::remove_dir(&mnt);
        return Err(error);
    }
    let result = (|| -> Result<bool> {
        let path = mnt.join("etc/resolv.conf");
        let resolv = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        if !guest_resolv_needs_repair(&resolv) {
            return Ok(false);
        }
        let fallback = guest_dns_fallback();
        let filtered = filter_guest_nameservers(&resolv, &fallback);
        // Ubuntu and Rocky ship /etc/resolv.conf as a symlink into a runtime
        // directory that does not exist in a cold image. Writing through it
        // would create the link target and leave the resolver unfixed, so the
        // link is replaced by a regular file.
        if std::fs::symlink_metadata(&path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            std::fs::remove_file(&path)?;
        }
        std::fs::write(path, filtered)?;
        Ok(true)
    })();
    let unmount = umount(&mnt);
    let _ = std::fs::remove_dir(&mnt);
    match (result, unmount) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(changed), Ok(())) => Ok(changed),
    }
}
