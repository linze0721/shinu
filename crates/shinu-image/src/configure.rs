use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use shinu_core::{
    Error, Image, Result, VSOCK_SSH_PORT, VSOCK_VNC_PORT, is_blocked_guest_destination, parse_ipv4,
};

const GUEST_DNS_FALLBACK: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);

fn guest_dns_override() -> Result<Option<Ipv4Addr>> {
    match std::env::var("SHINU_GUEST_DNS") {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) if guest_can_reach_resolver(value.trim()) => value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| Error::NoReachableGuestDnsResolver),
        _ => Err(Error::NoReachableGuestDnsResolver),
    }
}

fn probe_guest_dns(server: SocketAddrV4) -> std::io::Result<bool> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let timeout = Some(Duration::from_secs(2));
    socket.set_write_timeout(timeout)?;
    socket.set_read_timeout(timeout)?;
    socket.connect(server)?;

    // One recursive A query for example.com; never use the host's resolver.
    let mut query = *b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01";
    query[..2].copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..2]);
    socket.send(&query)?;
    let mut reply = [0; 512];
    let len = socket.recv(&mut reply)?;
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    Ok(len >= query.len() + 12
        && reply[..2] == query[..2]
        // Response to a standard query, not truncated, NOERROR, one question.
        && flags & 0xfa0f == 0x8000
        && reply[4..6] == [0, 1]
        && reply[6..8] != [0, 0]
        && reply[12..query.len()] == query[12..])
}

fn guest_resolv_contents(
    resolv: &str,
    override_dns: Option<Ipv4Addr>,
    probe: impl FnOnce(SocketAddrV4) -> std::io::Result<bool>,
) -> Result<String> {
    if let Some(address) = override_dns {
        return Ok(format!("nameserver {address}\n"));
    }
    if let Some(contents) = filter_guest_nameservers(resolv) {
        return Ok(contents);
    }
    if !matches!(probe(GUEST_DNS_FALLBACK), Ok(true)) {
        return Err(Error::NoReachableGuestDnsResolver);
    }
    Ok(format!("nameserver {}\n", GUEST_DNS_FALLBACK.ip()))
}

/// The guest only has IPv4 routes and its egress policy blocks local addresses.
/// This is an address filter, not a reachability probe.
fn guest_can_reach_resolver(address: &str) -> bool {
    parse_ipv4(address).is_some() && !is_blocked_guest_destination(address)
}

/// Retains options and comments only if at least one guest-usable nameserver remains.
fn filter_guest_nameservers(resolv: &str) -> Option<String> {
    let mut has_nameserver = false;
    let mut filtered = String::new();
    for line in resolv.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("nameserver") {
            if !fields.next().is_some_and(guest_can_reach_resolver) {
                continue;
            }
            has_nameserver = true;
        }
        filtered.push_str(line);
        filtered.push('\n');
    }
    has_nameserver.then_some(filtered)
}

/// Returns whether a baked resolver file contains an unusable or missing
/// nameserver. Formatting alone does not trigger a repair, so a public file
/// remains untouched on every daemon restart.
fn guest_resolv_needs_repair(resolv: &str) -> bool {
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
        if !guest_can_reach_resolver(address) {
            return true;
        }
    }
    !has_nameserver
}

/// Seeds the build chroot and returns the selected contents to restore after package installation.
pub fn seed_resolv(mnt: &Path) -> Result<String> {
    let override_dns = guest_dns_override()?;
    let host_resolv = if override_dns.is_none() {
        std::fs::read("/etc/resolv.conf").unwrap_or_default()
    } else {
        Vec::new()
    };
    // chroot_run unshares mount and PID namespaces, not networking. The probe
    // here therefore uses the same routes as the build's package manager.
    let contents = guest_resolv_contents(
        &String::from_utf8_lossy(&host_resolv),
        override_dns,
        probe_guest_dns,
    )?;
    write_guest_resolv(mnt, &contents)?;
    Ok(contents)
}

pub(super) fn repair_guest_resolv(mnt: &Path) -> Result<bool> {
    let path = mnt.join("etc/resolv.conf");
    let is_symlink = std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_symlink());
    let resolv = if is_symlink {
        String::new()
    } else {
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        }
    };
    let override_dns = guest_dns_override()?;
    if override_dns.is_none() && !guest_resolv_needs_repair(&resolv) {
        return Ok(false);
    }
    let contents = guest_resolv_contents(&resolv, override_dns, probe_guest_dns)?;
    if contents == resolv {
        return Ok(false);
    }
    write_guest_resolv(mnt, &contents)?;
    Ok(true)
}

pub(super) fn write_guest_resolv(mnt: &Path, contents: &str) -> Result<()> {
    let path = mnt.join("etc/resolv.conf");
    if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_symlink()) {
        // Distro archives often ship a dangling systemd-resolved link; writing
        // through it would fail before the package manager has created /run.
        std::fs::remove_file(&path)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

/// Runs a shell command inside the mounted image. Only ever called by the
/// root daemon while building the base. The PID namespace is intentional:
/// package hooks can daemonize helpers, and killing the namespace at shell exit
/// lets the parent unmount the image without leaving a hidden loop mount.
pub(super) fn chroot_run(mnt: &Path, command: &str) -> Result<()> {
    let script = r#"mount -t proc proc "$1/proc" && (mount --rbind /dev "$1/dev" || :) && (mount --rbind /sys "$1/sys" || :) && exec chroot "$1" /bin/sh -c "$2""#;
    let status = std::process::Command::new("unshare")
        .args([
            "--mount",
            "--pid",
            "--fork",
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
/// console, sshd, and the vsock bridge. OpenSSH cannot provide an `AF_VSOCK`
/// listener itself, so socat forwards the guest vsock port to it.
pub(super) fn configure_image(mnt: &Path, image: Image) -> Result<()> {
    // Passwordless root for the serial console. Key auth is what `exec` uses;
    // this only matters when a human attaches to ttyS0 to debug a boot.
    let shadow = mnt.join("etc/shadow");
    if let Ok(contents) = std::fs::read_to_string(&shadow) {
        let patched = contents
            .lines()
            .map(|line| {
                line.strip_prefix("root:").map_or_else(
                    || line.to_owned(),
                    |rest| match rest.split_once(':') {
                        Some((_, tail)) => format!("root::{tail}"),
                        None => line.to_owned(),
                    },
                )
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
    // Keep callers independent of the capture utility baked into each distro.
    let screenshot_script = match image {
        Image::Rocky => {
            "#!/bin/sh\nif [ \"$#\" -ne 1 ]; then\n    echo \"usage: shinu-screenshot OUTPUT\" >&2\n    exit 2\nfi\nDISPLAY=${DISPLAY:-:0}\nexport DISPLAY\nexec import -window root \"$1\"\n"
        }
        Image::Void | Image::Ubuntu | Image::Arch => {
            "#!/bin/sh\nif [ \"$#\" -ne 1 ]; then\n    echo \"usage: shinu-screenshot OUTPUT\" >&2\n    exit 2\nfi\nDISPLAY=${DISPLAY:-:0}\nexport DISPLAY\nexec scrot -o \"$1\"\n"
        }
    };
    let screenshot_path = mnt.join("usr/local/bin/shinu-screenshot");
    if let Some(parent) = screenshot_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&screenshot_path, screenshot_script)?;
    std::fs::set_permissions(&screenshot_path, std::fs::Permissions::from_mode(0o755))?;

    let desktop_script = "#!/bin/sh\nexec 2>&1\nXvfb :0 -screen 0 1280x800x24 &\nsleep 1\nDISPLAY=:0 openbox &\nexec x11vnc -display :0 -rfbport 5900 -nopw -forever -shared -localhost\n";
    let desktop_command = "exec 2>&1; Xvfb :0 -screen 0 1280x800x24 & sleep 1; DISPLAY=:0 openbox & exec x11vnc -display :0 -rfbport 5900 -nopw -forever -shared -localhost";
    let vsock_vnc_script = format!(
        "#!/bin/sh\nexec 2>&1\nexec socat VSOCK-LISTEN:{VSOCK_VNC_PORT},fork,reuseaddr TCP:127.0.0.1:5900\n"
    );
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
            let desktop = mnt.join("etc/sv/shinu-desktop");
            std::fs::create_dir_all(&desktop)?;
            std::fs::write(desktop.join("run"), desktop_script)?;
            std::fs::set_permissions(desktop.join("run"), std::fs::Permissions::from_mode(0o755))?;
            let vnc = mnt.join("etc/sv/shinu-vsock-vnc");
            std::fs::create_dir_all(&vnc)?;
            std::fs::write(vnc.join("run"), &vsock_vnc_script)?;
            std::fs::set_permissions(vnc.join("run"), std::fs::Permissions::from_mode(0o755))?;
            for service in ["shinu-desktop", "shinu-vsock-vnc"] {
                let _ = std::fs::remove_file(default.join(service));
            }
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
            std::fs::write(
                systemd.join("shinu-desktop.service"),
                format!(
                    "[Unit]\nAfter=local-fs.target\n\n[Service]\nExecStart=/bin/sh -c '{desktop_command}'\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            std::fs::write(
                systemd.join("shinu-vsock-vnc.service"),
                format!(
                    "[Unit]\nAfter=shinu-desktop.service\n\n[Service]\nExecStart=/usr/bin/socat VSOCK-LISTEN:{VSOCK_VNC_PORT},fork,reuseaddr TCP:127.0.0.1:5900\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
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
            for service in ["shinu-desktop", "shinu-vsock-vnc"] {
                let _ = std::fs::remove_file(multi.join(format!("{service}.service")));
            }

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
            std::os::unix::fs::symlink("/usr/lib/systemd/system/serial-getty@.service", serial)?;
        }
    }

    let hosts = mnt.join("etc/hosts");
    if !hosts.exists() {
        std::fs::write(&hosts, "127.0.0.1 localhost\n::1 localhost\n")?;
    }
    std::fs::write(mnt.join("etc/hostname"), "shinu\n")?;
    Ok(())
}

fn payload_target(mnt: &Path, destination: &str) -> Result<PathBuf> {
    let relative = destination.trim_start_matches('/');
    if Path::new(relative)
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Invalid(format!(
            "payload destination escapes guest image: {destination}"
        )));
    }
    let target = mnt.join(relative);
    let root = mnt.canonicalize()?;
    let mut ancestor = target.as_path();
    let metadata = loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => break metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ancestor = ancestor.parent().ok_or_else(|| {
                    Error::Invalid(format!(
                        "payload destination has no guest root: {destination}"
                    ))
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    };
    if ancestor == target.as_path() && metadata.file_type().is_symlink() {
        return Err(Error::Invalid(format!(
            "payload destination is a symlink: {destination}"
        )));
    }
    if !ancestor.canonicalize()?.starts_with(&root) {
        return Err(Error::Invalid(format!(
            "payload destination escapes guest image: {destination}"
        )));
    }
    Ok(target)
}

/// Bakes caller-supplied files into the base image.
///
/// The base build is the only moment shared guest files are baked into every
/// space. Runtime networking remains available for workloads that need it, but
/// preinstalling the payload keeps each clone identical and cheap to create.
///
/// Baking it into the base rather than pushing it per space also means every
/// space starts identical and pays nothing at clone time, since the payload is
/// shared `CoW` extents like the rest of the image.
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
        // Reject parent components and symlinked ancestors before joining so a payload
        // cannot escape the guest image or overwrite a host file through a symlink.
        let target = payload_target(mnt, &dst)?;
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
    if service == "."
        || service == ".."
        || service.contains('/')
        || service.chars().any(char::is_control)
    {
        return Err(Error::Invalid(format!(
            "invalid SHINU_PAYLOAD_SERVICE={service}: service name must be one safe path component"
        )));
    }
    let run = payload_target(mnt, &format!("/etc/sv/{service}/run"))?;
    if !std::fs::symlink_metadata(&run)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
    {
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
mod payload_tests {
    use super::payload_target;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    #[test]
    fn rejects_parent_components_and_escaping_ancestors() {
        let mnt = std::env::temp_dir().join(format!("shinu-payload-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(mnt.join("etc")).expect("create test mount");
        symlink("/tmp", mnt.join("etc/redirect")).expect("create redirect symlink");

        assert!(payload_target(Path::new("/mnt"), "../outside").is_err());
        assert!(payload_target(&mnt, "/etc/redirect/file").is_err());

        fs::remove_dir_all(mnt).expect("remove test mount");
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::{Ipv4Addr, SocketAddrV4, guest_resolv_contents, guest_resolv_needs_repair};
    use shinu_core::Error;

    #[test]
    fn filters_private_stub_and_ipv6_resolvers_without_probing() {
        let resolv = "# Generated by dhcpcd\nnameserver 192.168.5.123\nnameserver 8.8.8.8\nnameserver 172.16.0.1\nnameserver 127.0.0.53\nnameserver 2001:db8::1\n";
        assert_eq!(
            guest_resolv_contents(resolv, None, |_| panic!("public nameserver remains")).unwrap(),
            "# Generated by dhcpcd\nnameserver 8.8.8.8\n"
        );
    }

    #[test]
    fn fails_fast_when_the_fallback_does_not_answer() {
        let resolv = "nameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver 169.254.169.254\n";
        let error =
            guest_resolv_contents(resolv, None, |_| Err(std::io::ErrorKind::TimedOut.into()))
                .unwrap_err();
        assert!(matches!(error, Error::NoReachableGuestDnsResolver));
        assert_eq!(
            error.to_string(),
            "no reachable guest DNS resolver; set SHINU_GUEST_DNS=<reachable public resolver>"
        );
    }

    #[test]
    fn accepts_fallback_only_after_a_dns_reply() {
        let resolv = "nameserver 2001:db8::1\n";
        let resolver = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        let contents = guest_resolv_contents(resolv, None, |endpoint| {
            assert_eq!(endpoint, resolver);
            Ok(true)
        })
        .unwrap();
        assert_eq!(contents, "nameserver 1.1.1.1\n");
        assert!(matches!(
            guest_resolv_contents(resolv, None, |_| Ok(false)),
            Err(Error::NoReachableGuestDnsResolver)
        ));
    }

    #[test]
    fn explicit_override_wins_even_if_the_host_has_a_public_resolver() {
        assert_eq!(
            guest_resolv_contents(
                "nameserver 8.8.8.8\n",
                Some(Ipv4Addr::new(223, 5, 5, 5)),
                |_| { panic!("explicit override bypasses the fallback probe") }
            )
            .unwrap(),
            "nameserver 223.5.5.5\n"
        );
    }

    #[test]
    fn detects_ipv6_only_guest_resolver_for_repair() {
        assert!(guest_resolv_needs_repair("nameserver 2001:db8::1\n"));
    }

    #[test]
    fn detects_only_unusable_guest_resolvers_for_repair() {
        assert!(!guest_resolv_needs_repair("# comment\nnameserver 8.8.8.8"));
        assert!(guest_resolv_needs_repair(
            "nameserver 192.168.5.123\nnameserver 8.8.8.8"
        ));
        assert!(guest_resolv_needs_repair(""));
    }
}
