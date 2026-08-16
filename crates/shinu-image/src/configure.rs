use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use shinu_core::{is_blocked_guest_destination, Error, Image, Result, VSOCK_SSH_PORT};

pub(super) fn guest_dns_fallback() -> String {
    std::env::var("SHINU_GUEST_DNS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "1.1.1.1".to_owned())
}

/// Filters host resolver entries before baking them into the guest image.
/// Private and link-local host resolvers cannot be reached after guest egress
/// filtering, so copying one would make xbps unable to resolve package mirrors.
pub fn filter_guest_nameservers(resolv: &str, fallback: &str) -> String {
    let fallback = if fallback.trim().is_empty() {
        "1.1.1.1"
    } else {
        fallback.trim()
    };
    let filtered = resolv
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some("nameserver"), Some(address)) => {
                    !is_blocked_guest_destination(address) && !address.starts_with("127.")
                }
                (Some("nameserver"), None) => false,
                _ => true,
            }
        })
        .collect::<Vec<_>>();
    let has_nameserver = filtered.iter().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("nameserver") && fields.next().is_some()
    });
    if has_nameserver {
        format!("{}\n", filtered.join("\n"))
    } else {
        format!("nameserver {fallback}\n")
    }
}

/// Returns whether a baked resolver file contains an unusable or missing
/// nameserver. Formatting alone does not trigger a repair, so a public file
/// remains untouched on every daemon restart.
pub fn guest_resolv_needs_repair(resolv: &str) -> bool {
    let mut has_nameserver = false;
    for line in resolv.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            return true;
        };
        has_nameserver = true;
        if is_blocked_guest_destination(address) || address.starts_with("127.") {
            return true;
        }
    }
    !has_nameserver
}

pub fn seed_resolv(mnt: &Path) -> Result<()> {
    let fallback = guest_dns_fallback();
    let contents = match std::fs::read("/etc/resolv.conf") {
        Ok(resolv) => filter_guest_nameservers(&String::from_utf8_lossy(&resolv), &fallback),
        Err(_) => format!("nameserver {fallback}\n"),
    };
    let path = mnt.join("etc/resolv.conf");
    if std::fs::symlink_metadata(&path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        // Distro archives often ship a dangling systemd-resolved link; writing
        // through it would fail before the package manager has created /run.
        std::fs::remove_file(&path)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}
/// Runs a shell command inside the mounted image. Only ever called by the
/// root daemon while building the base: the mounts live in a private
/// namespace that dies with the child, so nothing leaks into the host.
pub(super) fn chroot_run(mnt: &Path, command: &str) -> Result<()> {
    let script = r#"mount -t proc proc "$1/proc" && (mount --rbind /dev "$1/dev" || :) && (mount --rbind /sys "$1/sys" || :) && exec chroot "$1" /bin/sh -c "$2""#;
    let status = std::process::Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            "--",
            "sh",
            "-c",
            script,
            "_",
        ])
        .arg(mnt)
        .arg(command)
        .status()?;
    if !status.success() {
        return Err(Error::Invalid(format!(
            "in-image command failed ({}): {command}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Turns the extracted rootfs into a bootable cloud image: root login, serial
/// console, sshd, and the vsock bridge sshd cannot provide itself (OpenSSH
/// has no AF_VSOCK listener, so socat forwards the guest vsock port to it).
pub(super) fn configure_image(mnt: &Path, image: Image) -> Result<()> {
    // Package managers resolve mirrors during this build, before a guest has
    // a runtime network interface; a baked public resolver is the only DNS
    // path available inside the chroot.
    seed_resolv(mnt)?;

    // Passwordless root for the serial console. Key auth is what `exec` uses;
    // this only matters when a human attaches to ttyS0 to debug a boot.
    let shadow = mnt.join("etc/shadow");
    if let Ok(contents) = std::fs::read_to_string(&shadow) {
        let patched = contents
            .lines()
            .map(|line| match line.strip_prefix("root:") {
                Some(rest) => match rest.split_once(':') {
                    Some((_, tail)) => format!("root::{tail}"),
                    None => line.to_owned(),
                },
                None => line.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&shadow, format!("{patched}\n"))?;
    }

    let ssh_dir = mnt.join("etc/ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    // `UseDNS no` keeps login independent of guest network readiness; the
    // bridge peer is always socat on 127.0.0.1 while eth0 is booting.
    let required = [
        "PermitRootLogin prohibit-password",
        "PubkeyAuthentication yes",
        "UseDNS no",
        "GSSAPIAuthentication no",
    ];
    let sshd_config = ssh_dir.join("sshd_config");
    let mut contents = std::fs::read_to_string(&sshd_config).unwrap_or_default();
    for line in required {
        if !contents.lines().any(|existing| existing.trim() == line) {
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(line);
            contents.push('\n');
        }
    }
    std::fs::write(&sshd_config, contents)?;

    let network_script = "#!/bin/sh\nexec 2>&1\nIP=$(sed -n 's/.*shinu\\.ip=\\([^ ]*\\).*/\\1/p' /proc/cmdline)\nGW=$(sed -n 's/.*shinu\\.gw=\\([^ ]*\\).*/\\1/p' /proc/cmdline)\n[ -n \"$IP\" ] || { echo \"no shinu.ip on cmdline\"; exec sleep infinity; }\nip addr add \"$IP\" dev eth0 2>/dev/null\nip link set eth0 up\n[ -n \"$GW\" ] && ip route add default via \"$GW\" 2>/dev/null\necho \"configured $IP via $GW\"\nexec sleep infinity\n";

    if image == Image::Arch {
        let pacman = mnt.join("etc/pacman.conf");
        let contents = std::fs::read_to_string(&pacman).unwrap_or_default();
        let mut in_options = false;
        let mut found_options = false;
        let mut found_check_space = false;
        let mut found_disable_sandbox = false;
        let mut lines = Vec::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                if in_options && !found_disable_sandbox {
                    lines.push(
                        "# The guest kernel lacks Landlock, so pacman's default sandbox cannot initialize."
                            .to_owned(),
                    );
                    lines.push("DisableSandbox".to_owned());
                    found_disable_sandbox = true;
                }
                in_options = trimmed == "[options]";
                found_options |= in_options;
            }
            if in_options
                && !trimmed.starts_with('#')
                && trimmed.split_whitespace().next() == Some("DisableSandbox")
            {
                found_disable_sandbox = true;
            }
            let line = if trimmed.starts_with("CheckSpace") {
                found_check_space = true;
                format!("#{line}")
            } else {
                line.to_owned()
            };
            lines.push(line);
        }
        if in_options && !found_disable_sandbox {
            lines.push(
                "# The guest kernel lacks Landlock, so pacman's default sandbox cannot initialize."
                    .to_owned(),
            );
            lines.push("DisableSandbox".to_owned());
        }
        if !found_options {
            lines.push("[options]".to_owned());
            lines.push(
                "# The guest kernel lacks Landlock, so pacman's default sandbox cannot initialize."
                    .to_owned(),
            );
            lines.push("DisableSandbox".to_owned());
        }
        if !found_check_space {
            lines.push("#CheckSpace".to_owned());
        }
        let mut patched = lines.join("\n");
        patched.push('\n');
        std::fs::write(pacman, patched)?;
        let mirrorlist = mnt.join("etc/pacman.d/mirrorlist");
        if let Some(parent) = mirrorlist.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            mirrorlist,
            "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n",
        )?;
    }

    match image {
        Image::Void => {
            let default = mnt.join("etc/runit/runsvdir/default");
            std::fs::create_dir_all(&default)?;
            // A microVM has one serial port and no virtual terminals; leaving
            // tty1-6 gettys enabled just burns boot time on devices that do not exist.
            for n in 1..=6 {
                let _ = std::fs::remove_file(default.join(format!("agetty-tty{n}")));
            }

            let bridge = mnt.join("etc/sv/vsock-sshd");
            std::fs::create_dir_all(&bridge)?;
            std::fs::write(
                bridge.join("run"),
                format!(
                    "#!/bin/sh\nexec 2>&1\nexec socat VSOCK-LISTEN:{VSOCK_SSH_PORT},fork,reuseaddr TCP:127.0.0.1:22\n"
                ),
            )?;
            std::fs::set_permissions(bridge.join("run"), std::fs::Permissions::from_mode(0o755))?;
            let network = mnt.join("etc/sv/shinu-net");
            std::fs::create_dir_all(&network)?;
            std::fs::write(network.join("run"), network_script)?;
            std::fs::set_permissions(network.join("run"), std::fs::Permissions::from_mode(0o755))?;

            for service in ["agetty-ttyS0", "sshd", "vsock-sshd", "shinu-net"] {
                let link = default.join(service);
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(format!("/etc/sv/{service}"), &link)?;
            }
        }
        Image::Ubuntu | Image::Arch | Image::Rocky => {
            let sshd = match image {
                Image::Arch => "/usr/bin/sshd",
                Image::Ubuntu | Image::Rocky => "/usr/sbin/sshd",
                Image::Void => unreachable!(),
            };
            let systemd = mnt.join("etc/systemd/system");
            std::fs::create_dir_all(&systemd)?;
            let machine_id = mnt.join("etc/machine-id");
            if std::fs::symlink_metadata(&machine_id)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
            {
                std::fs::remove_file(&machine_id)?;
            }
            // Keep this file empty instead of baking a UUID into the base:
            // systemd fills a fresh id during early boot, so cloned spaces do
            // not share one identity. A future image that loses this file is
            // also protected from an interactive firstboot prompt below.
            std::fs::write(&machine_id, b"")?;
            let firstboot = systemd.join("systemd-firstboot.service");
            let _ = std::fs::remove_file(&firstboot);
            std::os::unix::fs::symlink("/dev/null", firstboot)?;
            std::fs::write(
                systemd.join("shinu-sshd.service"),
                format!(
                    "[Unit]\nAfter=network.target\n\n[Service]\nExecStart={sshd} -D -e\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            std::fs::write(
                systemd.join("shinu-vsock.service"),
                format!(
                    "[Unit]\nAfter=shinu-sshd.service\n\n[Service]\nExecStart=/usr/bin/socat VSOCK-LISTEN:{VSOCK_SSH_PORT},fork,reuseaddr TCP:127.0.0.1:22\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            let network_path = mnt.join("usr/local/sbin/shinu-net");
            if let Some(parent) = network_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&network_path, network_script)?;
            std::fs::set_permissions(&network_path, std::fs::Permissions::from_mode(0o755))?;
            std::fs::write(
                systemd.join("shinu-net.service"),
                "[Unit]\nAfter=local-fs.target\n\n[Service]\nExecStart=/usr/local/sbin/shinu-net\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n",
            )?;

            let multi = systemd.join("multi-user.target.wants");
            std::fs::create_dir_all(&multi)?;
            for service in ["ssh.service", "sshd.service"] {
                let _ = std::fs::remove_file(multi.join(service));
            }
            for service in ["shinu-sshd", "shinu-vsock", "shinu-net"] {
                let link = multi.join(format!("{service}.service"));
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(format!("/etc/systemd/system/{service}.service"), link)?;
            }

            let getty = systemd.join("getty.target.wants");
            std::fs::create_dir_all(&getty)?;
            for n in 1..=6 {
                let _ = std::fs::remove_file(getty.join(format!("getty@tty{n}.service")));
            }
            let serial = getty.join("serial-getty@ttyS0.service");
            let _ = std::fs::remove_file(&serial);
            std::os::unix::fs::symlink(
                "/usr/lib/systemd/system/serial-getty@.service",
                serial,
            )?;
        }
    }

    let hosts = mnt.join("etc/hosts");
    if !hosts.exists() {
        std::fs::write(&hosts, "127.0.0.1 localhost\n::1 localhost\n")?;
    }
    std::fs::write(mnt.join("etc/hostname"), "shinu\n")?;
    Ok(())
}

/// Bakes caller-supplied files into the base image.
///
/// The base build is the only moment shared guest files are baked into every
/// space. Runtime networking remains available for workloads that need it, but
/// preinstalling the payload keeps each clone identical and cheap to create.
///
/// Baking it into the base rather than pushing it per space also means every
/// space starts identical and pays nothing at clone time, since the payload is
/// shared CoW extents like the rest of the image.
///
/// `SHINU_PAYLOAD` is a comma-separated list of `<src>` or `<src>=<dst>`. A
/// bare `<src>` lands in `/usr/local/bin/<basename>`. `SHINU_PAYLOAD_SERVICE`
/// names a runit service to enable, whose `run` script must have arrived
/// through the payload as `/etc/sv/<name>/run`.
///
/// Nothing here knows what the payload *is* — that keeps this crate a generic
/// VM engine rather than one workload's launcher.
pub(super) fn install_payload(mnt: &Path, image: Image) -> Result<()> {
    let Some(spec) = std::env::var_os("SHINU_PAYLOAD") else {
        return Ok(());
    };
    let spec = spec.to_string_lossy().into_owned();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (src, dst) = match entry.split_once('=') {
            Some((src, dst)) => (Path::new(src.trim()), dst.trim().to_owned()),
            None => {
                let src = Path::new(entry);
                let name = src
                    .file_name()
                    .ok_or_else(|| Error::Invalid(format!("payload has no filename: {entry}")))?;
                (src, format!("/usr/local/bin/{}", name.to_string_lossy()))
            }
        };
        if !src.is_file() {
            return Err(Error::Invalid(format!(
                "payload is not a file: {}",
                src.display()
            )));
        }
        // Destinations are absolute guest paths; strip the leading slash so
        // they join under the mount instead of escaping to the host root.
        let target = mnt.join(dst.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, &target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
    }

    let Some(service) = std::env::var_os("SHINU_PAYLOAD_SERVICE") else {
        return Ok(());
    };
    let service = service.to_string_lossy();
    let service = service.trim();
    if service.is_empty() {
        return Ok(());
    }
    let run = mnt.join(format!("etc/sv/{service}/run"));
    if !run.exists() {
        return Err(Error::Invalid(format!(
            "SHINU_PAYLOAD_SERVICE={service} but the payload did not provide /etc/sv/{service}/run"
        )));
    }
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755))?;
    match image {
        Image::Void => {
            let link = mnt.join(format!("etc/runit/runsvdir/default/{service}"));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("/etc/sv/{service}"), link)?;
        }
        Image::Ubuntu | Image::Arch | Image::Rocky => {
            let systemd = mnt.join("etc/systemd/system");
            std::fs::create_dir_all(&systemd)?;
            std::fs::write(
                systemd.join(format!("shinu-payload-{service}.service")),
                format!(
                    "[Unit]\nAfter=network.target\n\n[Service]\nExecStart=/etc/sv/{service}/run\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            let wants = systemd.join("multi-user.target.wants");
            std::fs::create_dir_all(&wants)?;
            let link = wants.join(format!("shinu-payload-{service}.service"));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(
                format!("/etc/systemd/system/shinu-payload-{service}.service"),
                link,
            )?;
        }
    }
    Ok(())
}


#[cfg(test)]
mod resolver_tests {
    use super::{filter_guest_nameservers, guest_resolv_needs_repair};

    #[test]
    fn filters_private_guest_nameservers_and_keeps_public_ones() {
        let resolv = "# Generated by dhcpcd\nnameserver 192.168.5.123\nnameserver 8.8.8.8\nnameserver 172.16.0.1\nnameserver 127.0.0.53\n";
        assert_eq!(
            filter_guest_nameservers(resolv, "1.1.1.1"),
            "# Generated by dhcpcd\nnameserver 8.8.8.8\n"
        );
    }

    #[test]
    fn resolver_filter_falls_back_when_every_nameserver_is_private() {
        let resolv = "nameserver 10.0.0.2\nnameserver 169.254.169.254\n";
        assert_eq!(
            filter_guest_nameservers(resolv, "1.1.1.1"),
            "nameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn detects_only_unusable_guest_resolvers_for_repair() {
        assert!(!guest_resolv_needs_repair("# comment\nnameserver 8.8.8.8"));
        assert!(guest_resolv_needs_repair("nameserver 192.168.5.123\nnameserver 8.8.8.8"));
        assert!(guest_resolv_needs_repair(""));
    }
}
