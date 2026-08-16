pub use crate::net::egress_rules;

use crate::config::VmConfig;
use crate::net::NetConfig;
use shinu_core::{Error, Image, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// `<root>/jail/firecracker/<id>/root` is the host-visible chroot root.
/// This is pure path arithmetic so callers can validate it without KVM.
pub fn jail_root(root: &Path, id: Uuid) -> PathBuf {
    root.join("jail")
        .join("firecracker")
        .join(id.to_string())
        .join("root")
}

/// Firecracker's API socket as seen from the host, inside its chroot.
pub fn jail_socket(root: &Path, id: Uuid) -> PathBuf {
    jail_root(root, id).join("fc.sock")
}

fn jail_path(dir: &Path, name: &str) -> PathBuf {
    let Some(id) = dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| Uuid::parse_str(name).ok())
    else {
        return dir.join(name);
    };
    let Some(vm_root) = dir.parent() else {
        return dir.join(name);
    };
    let Some(root) = vm_root.parent() else {
        return dir.join(name);
    };
    jail_root(root, id).join(name)
}

pub fn config_path(dir: &Path) -> PathBuf {
    jail_path(dir, "fc.json")
}

pub fn vsock_path(dir: &Path) -> PathBuf {
    jail_path(dir, "vsock.sock")
}

/// `<root>/jail/firecracker/<id>/root/fc.sock` is kept in the chroot so
/// Firecracker cannot reach a host socket outside its namespace.
pub fn api_path(dir: &Path) -> PathBuf {
    jail_path(dir, "fc.sock")
}

/// The jailer writes the Firecracker pid inside the chroot. Keeping this
/// path next to the process it describes lets lifecycle checks survive a
/// daemon restart without exposing a host-side pid file to the guest.
pub fn pid_path(dir: &Path) -> PathBuf {
    jail_path(dir, "firecracker.pid")
}

const JAIL_KERNEL: &str = "vmlinux";
const JAIL_ROOTFS: &str = "rootfs.ext4";
const JAIL_VSOCK: &str = "vsock.sock";

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join("id_ed25519")
}

pub fn last_used_path(dir: &Path) -> PathBuf {
    dir.join("last_used")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn command_failure(program: &str, args: &[&str], output: &std::process::Output) -> Error {
    let command = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    Error::Invalid(format!(
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
    Ok(std::process::Command::new(program).args(args).output()?)
}

fn require_success(program: &str, args: &[&str]) -> Result<()> {
    let output = run_command(program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failure(program, args, &output))
    }
}

fn allow_file_exists(program: &str, args: &[&str]) -> Result<()> {
    let output = run_command(program, args)?;
    if output.status.success()
        || String::from_utf8_lossy(&output.stderr).contains("File exists")
    {
        Ok(())
    } else {
        Err(command_failure(program, args, &output))
    }
}

fn ensure_address_free(id: Uuid, tap: &str, address: &str) -> Result<()> {
    let args = ["-o", "addr", "show"];
    let output = run_command("ip", &args)?;
    if !output.status.success() {
        return Err(command_failure("ip", &args, &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let mut fields = line.split_whitespace();
        let _index = fields.next();
        let Some(interface) = fields.next() else {
            continue;
        };
        let Some(family) = fields.next() else {
            continue;
        };
        let Some(candidate) = fields.next() else {
            continue;
        };
        if family == "inet" && candidate == address && interface != tap {
            return Err(Error::Invalid(format!(
                "network address conflict for uuid {id}: {address} is already on {interface}; set SHINU_NET_BASE"
            )));
        }
    }
    Ok(())
}

fn ensure_iptables_rule(check: &[&str], add: &[&str]) -> Result<()> {
    let checked = run_command("iptables", check)?;
    if checked.status.success() {
        return Ok(());
    }
    require_success("iptables", add)
}

fn ensure_forward_rule(rule: &[String], position: usize) -> Result<()> {
    let mut check = vec!["-C".to_owned(), "FORWARD".to_owned()];
    check.extend(rule.iter().cloned());
    let check = check.iter().map(String::as_str).collect::<Vec<_>>();
    let mut add = vec![
        "-I".to_owned(),
        "FORWARD".to_owned(),
        position.to_string(),
    ];
    add.extend(rule.iter().cloned());
    let add = add.iter().map(String::as_str).collect::<Vec<_>>();
    ensure_iptables_rule(&check, &add)
}

/// Creates one tap, address, and forwarding/NAT rule set for this VM.
/// Every add is preceded by an existence check so retries do not grow the
/// host firewall, while the address check preserves /30 isolation.
pub fn tap_up(id: Uuid, cfg: &NetConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    let tap = crate::net::tap_name(id);
    let (third, fourth_base) = crate::net::net_slot(id);
    let network = format!(
        "{}.{}.{}.{}",
        cfg.base[0], cfg.base[1], third, fourth_base
    );
    let host = format!(
        "{}.{}.{}.{}",
        cfg.base[0], cfg.base[1], third, fourth_base + 1
    );
    let host_cidr = format!("{host}/30");
    let network_cidr = format!("{network}/30");

    ensure_address_free(id, &tap, &host_cidr)?;
    allow_file_exists("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])?;
    ensure_address_free(id, &tap, &host_cidr)?;
    allow_file_exists("ip", &["addr", "add", &host_cidr, "dev", &tap])?;
    ensure_address_free(id, &tap, &host_cidr)?;
    require_success("ip", &["link", "set", &tap, "up"])?;

    let nat_check = [
        "-t",
        "nat",
        "-C",
        "POSTROUTING",
        "-s",
        &network_cidr,
        "-o",
        &cfg.uplink,
        "-j",
        "MASQUERADE",
    ];
    let nat_add = [
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        &network_cidr,
        "-o",
        &cfg.uplink,
        "-j",
        "MASQUERADE",
    ];
    ensure_iptables_rule(&nat_check, &nat_add)?;

    let forward_out_check = [
        "-C",
        "FORWARD",
        "-i",
        &tap,
        "-o",
        &cfg.uplink,
        "-j",
        "ACCEPT",
    ];
    let forward_out_add = [
        "-I",
        "FORWARD",
        "1",
        "-i",
        &tap,
        "-o",
        &cfg.uplink,
        "-j",
        "ACCEPT",
    ];
    ensure_iptables_rule(&forward_out_check, &forward_out_add)?;

    let forward_in_check = [
        "-C",
        "FORWARD",
        "-i",
        &cfg.uplink,
        "-o",
        &tap,
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ];
    let forward_in_add = [
        "-I",
        "FORWARD",
        "1",
        "-i",
        &cfg.uplink,
        "-o",
        &tap,
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ];
    ensure_iptables_rule(&forward_in_check, &forward_in_add)?;
    // Insert after the broad forwarding rules so these entries end up
    // ahead of the unconditional tap-to-uplink ACCEPT.
    for (position, rule) in egress_rules(&tap, &host, &cfg.allow).iter().enumerate() {
        ensure_forward_rule(rule, position + 1)?;
    }
    // The guest uses a static /30 address and a public resolver baked into
    // the image; it has no DHCP or host DNS dependency. Drop all other
    // traffic destined for this host in INPUT. Public egress still takes
    // FORWARD because its destination is not a host-local address.
    let input_check = ["-C", "INPUT", "-i", &tap, "-j", "DROP"];
    let input_add = ["-I", "INPUT", "1", "-i", &tap, "-j", "DROP"];
    ensure_iptables_rule(&input_check, &input_add)
}

/// Removes this VM's rules and tap. Cleanup is deliberately best effort:
/// a stopped VM with a missing tap is already in the desired state.
pub fn tap_down(id: Uuid, cfg: &NetConfig) {
    if !cfg.enabled {
        return;
    }
    let tap = crate::net::tap_name(id);
    let (third, fourth_base) = crate::net::net_slot(id);
    let network = format!(
        "{}.{}.{}.{}",
        cfg.base[0], cfg.base[1], third, fourth_base
    );
    let network_cidr = format!("{network}/30");
    let gateway = format!(
        "{}.{}.{}.{}",
        cfg.base[0], cfg.base[1], third, fourth_base + 1
    );
    let _ = std::process::Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &network_cidr,
            "-o",
            &cfg.uplink,
            "-j",
            "MASQUERADE",
        ])
        .output();
    let _ = std::process::Command::new("iptables")
        .args([
            "-D",
            "FORWARD",
            "-i",
            &tap,
            "-o",
            &cfg.uplink,
            "-j",
            "ACCEPT",
        ])
        .output();
    let _ = std::process::Command::new("iptables")
        .args([
            "-D",
            "FORWARD",
            "-i",
            &cfg.uplink,
            "-o",
            &tap,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .output();
    for rule in egress_rules(&tap, &gateway, &cfg.allow) {
        let mut args = vec!["-D".to_owned(), "FORWARD".to_owned()];
        args.extend(rule);
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let _ = std::process::Command::new("iptables")
            .args(args)
            .output();
    }
    let _ = std::process::Command::new("iptables")
        .args(["-D", "INPUT", "-i", &tap, "-j", "DROP"])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["link", "del", &tap])
        .output();
}

/// One key pair per space, not one per host. `exec` runs in the caller's
/// unprivileged process, so the private key must be readable by that user;
/// a shared key would therefore be readable by everyone and let any user
/// SSH into any other user's VM, which is exactly the isolation the
/// owner-scoped lookups exist to provide.
pub fn prepare(dir: &Path, uid: u32, gid: u32) -> Result<String> {
    std::fs::create_dir_all(dir)?;
    let key = key_path(dir);
    if !key.exists() {
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&key)
            .status()?;
        if !status.success() {
            return Err(Error::Invalid("ssh-keygen failed for space key".to_owned()));
        }
    }
    let public = std::fs::read_to_string(key.with_extension("pub"))?;
    shinu_core::chown_tree(dir, uid, gid)?;
    Ok(public)
}

/// Writes the space's public key into its own image. Done once at clone
/// time rather than in the base, so no two spaces trust the same key.
pub fn authorize(image: &Path, public_key: &str, mnt: &Path) -> Result<()> {
    shinu_image::mount_image(image, mnt)?;
    let result = (|| -> Result<()> {
        let ssh = mnt.join("root/.ssh");
        std::fs::create_dir_all(&ssh)?;
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700))?;
        let authorized = ssh.join("authorized_keys");
        std::fs::write(&authorized, public_key)?;
        std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    })();
    shinu_image::umount(mnt)?;
    let _ = std::fs::remove_dir(mnt);
    result
}

fn read_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_path(dir))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// The pid of the Firecracker instance launched with `config`.
///
/// `setsid --fork` deliberately loses the grandchild's pid. The jailer
/// records Firecracker's pid inside the jail, while the process scan below
/// remains a fallback for the short window before that file is written.
fn find_vm_pid(config: &Path, id: Uuid) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if is_vm_process(pid, config, id) {
            return Some(pid);
        }
    }
    None
}

/// Whether `pid` is a live Firecracker running exactly this VM.
///
/// The single definition is shared by discovery and every later lifecycle
/// check. The jailer forwards Firecracker's UUID argument after chrooting,
/// so matching that identity avoids confusing relative `fc.json` paths.
fn is_vm_process(pid: u32, config: &Path, id: Uuid) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    let name = status.lines().find_map(|line| line.strip_prefix("Name:"));
    if name.map(str::trim) != Some("firecracker") {
        return false;
    }
    let state = status.lines().find_map(|line| line.strip_prefix("State:"));
    if state.is_none_or(|state| state.trim_start().starts_with('Z')) {
        return false;
    }
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let config_needle = config.as_os_str().as_encoded_bytes();
    let id_text = id.to_string();
    let id_with_equals = format!("--id={id_text}");
    let mut id_matches = false;
    let mut config_matches = false;
    let mut previous_was_id_flag = false;
    for arg in cmdline.split(|byte| *byte == 0) {
        if arg == id_with_equals.as_bytes()
            || (previous_was_id_flag && arg == id_text.as_bytes())
        {
            id_matches = true;
        }
        if arg == config_needle {
            config_matches = true;
        }
        previous_was_id_flag = arg == b"--id";
    }
    id_matches || config_matches
}

/// The pid of this space's VM, or `None` if it is not running.
pub fn running_pid(dir: &Path) -> Option<u32> {
    let pid = read_pid(dir)?;
    let id = dir_id(dir).ok()?;
    let config = config_path(dir);
    is_vm_process(pid, &config, id).then_some(pid)
}

pub fn is_running(dir: &Path) -> bool {
    running_pid(dir).is_some()
}

pub fn touch(dir: &Path) -> Result<()> {
    std::fs::write(last_used_path(dir), now_secs().to_string())?;
    Ok(())
}

/// One request against a VM's control API. `curl` is already this crate's
/// HTTP client (see `fetch_tarball`), and it speaks unix sockets, so no
/// hand-rolled HTTP and no new dependency.
fn api(dir: &Path, method: &str, path: &str, body: Option<&str>) -> Option<String> {
    let mut command = std::process::Command::new("curl");
    command
        .arg("-s")
        .arg("--max-time")
        .arg("5")
        .arg("--unix-socket")
        .arg(api_path(dir))
        .arg("-X")
        .arg(method)
        .arg(format!("http://localhost{path}"));
    if let Some(body) = body {
        command
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(body);
    }
    let out = command.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Pulls one unsigned field out of the balloon statistics object.
///
/// A hand-rolled scan rather than a `serde_json::Value`: the reply is a
/// flat object of numbers, and this avoids allocating a parse tree in the
/// daemon's poll loop every 30 seconds.
fn stat_field(stats: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = &stats[stats.find(&needle)? + needle.len()..];
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Hands the guest's unused memory back to the host.
///
/// Firecracker never reclaims on its own: a guest that once touched 500
/// MiB keeps that resident on the host forever, even after freeing it
/// (measured: RSS 91 MiB → 593 MiB, unchanged after the guest freed it;
/// inflating the balloon brought it to 100 MiB). This version has no
/// free-page reporting, so the reclaim has to be asked for explicitly.
///
/// The target comes from the guest's own `available_memory` rather than a
/// guess, less `keep_mib` so the page cache and a working margin survive.
/// Returns the MiB actually asked for.
pub fn reclaim(dir: &Path, keep_mib: u64) -> Option<u64> {
    let stats = api(dir, "GET", "/balloon/statistics", None)?;
    let available = stat_field(&stats, "available_memory")? / (1024 * 1024);
    let current = stat_field(&stats, "actual_mib")?;
    let target = current + available.saturating_sub(keep_mib);
    // Re-inflating to the size it already has just burns a request.
    if target <= current {
        return None;
    }
    api(
        dir,
        "PATCH",
        "/balloon",
        Some(&format!("{{\"amount_mib\": {target}}}")),
    )?;
    Some(target)
}

/// Gives the memory back before the guest is asked to do work.
///
/// Cheap and unconditional: deflating an already-empty balloon is a no-op
/// request, and skipping it would leave a reclaimed VM running under a
/// memory ceiling it never agreed to.
pub fn release(dir: &Path) {
    let _ = api(dir, "PATCH", "/balloon", Some("{\"amount_mib\": 0}"));
}

fn signal(pid: u32, sig: &str) -> bool {
    std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// True once the guest's sshd is ready to serve on `port`.
///
/// Firecracker's host vsock is not a transparent pipe: a client sends
/// `CONNECT <port>\n` and gets `OK <assigned>` back only if something in
/// the guest accepts.
///
/// A successful handshake alone is not enough, though. The bridge inside
/// the guest starts accepting before sshd is serving, so a VM could pass
/// that check and still refuse the very next connection — which is how a
/// first exec failed with 255 while two VMs were booting at once. Waiting
/// for the SSH identification string means readiness is decided by the
/// thing exec actually depends on.
fn probe(uds: &Path, port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(uds) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
        || stream
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .is_err()
    {
        return false;
    }
    // One byte at a time: a buffered reader would swallow the banner that
    // follows the handshake line, and both lines are read here.
    let line = |stream: &mut std::os::unix::net::UnixStream| -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        while out.len() < 256 {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return None,
                Ok(_) if byte[0] == b'\n' => return Some(out),
                Ok(_) => out.push(byte[0]),
            }
        }
        Some(out)
    };
    let Some(reply) = line(&mut stream) else {
        return false;
    };
    if !reply.starts_with(b"OK ") {
        return false;
    }
    line(&mut stream).is_some_and(|banner| banner.starts_with(b"SSH-"))
}
fn link_resource(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        std::fs::remove_file(dst)?;
    }
    // A 2 GiB image must stay on the same filesystem as its source: a
    // hardlink is O(1) and preserves CoW accounting, while copying would
    // consume the whole image and silently destroy that invariant.
    std::fs::hard_link(src, dst).map_err(|error| {
        Error::Invalid(format!(
            "hard-link {} -> {} failed (cross-device links are not supported): {error}",
            src.display(),
            dst.display()
        ))
    })?;
    Ok(())
}

fn clean_jail(dir: &Path) -> Result<()> {
    let Some(id) = dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| Uuid::parse_str(name).ok())
    else {
        return Ok(());
    };
    let Some(vm_root) = dir.parent() else {
        return Ok(());
    };
    let Some(root) = vm_root.parent() else {
        return Ok(());
    };
    let jail = jail_root(root, id);
    match std::fs::remove_dir_all(jail) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn wait_ready(dir: &Path, vsock: &Path) -> bool {
    for _ in 0..600 {
        if vsock.exists() && probe(vsock, shinu_core::VSOCK_SSH_PORT) {
            return true;
        }
        if !is_running(dir) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Per-space CPU and memory, each falling back to the daemon default when
/// the space stores nothing. `None` and a zero are different requests, so
/// this replaces the older pair of zero-sentinel integers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sizing {
    pub vcpus: Option<u32>,
    pub mem_mib: Option<u32>,
}

/// Boots the VM unless it is already up. Returns whether a boot happened.
pub fn start(
    root: &Path,
    id: Uuid,
    image_kind: Image,
    sizing: Sizing,
    cfg: &VmConfig,
    net_cfg: &NetConfig,
) -> Result<(PathBuf, bool)> {
    let vcpus = sizing.vcpus.unwrap_or(cfg.vcpus);
    let mem_mib = sizing.mem_mib.unwrap_or(cfg.mem_mib);
    let dir = shinu_core::vm_dir(root, id);
    let vsock = vsock_path(&dir);
    if is_running(&dir) {
        // The idle sweeper may have reclaimed this VM's memory; give it
        // back before the caller runs anything in it.
        release(&dir);
        touch(&dir)?;
        return Ok((vsock, false));
    }

    let image = shinu_core::space_image(root, id);
    if !image.exists() {
        return Err(Error::NotFound(format!("space image: {}", image.display())));
    }
    let kernel = shinu_core::kernel_path(root);
    if !kernel.exists() {
        return Err(Error::NotFound(format!("kernel image: {}", kernel.display())));
    }

    // A stale socket or jail from a dead VM must not make the next jailer
    // invocation reuse an old chroot or fail to bind its UDS.
    let _ = std::fs::remove_file(&vsock);
    let _ = std::fs::remove_file(api_path(&dir));
    std::fs::create_dir_all(&dir)?;
    clean_jail(&dir)?;
    let jail = jail_root(root, id);
    std::fs::create_dir_all(&jail)?;

    let net = crate::net::net_spec(id, net_cfg);
    if let Err(error) = tap_up(id, net_cfg) {
        tap_down(id, net_cfg);
        let _ = clean_jail(&dir);
        return Err(error);
    }
    let result = (|| -> Result<(PathBuf, bool)> {
        let jail_kernel = jail.join(JAIL_KERNEL);
        let jail_rootfs = jail.join(JAIL_ROOTFS);
        link_resource(&kernel, &jail_kernel)?;
        link_resource(&image, &jail_rootfs)?;
        // Hardlinks share inode ownership and mode with the source image.
        // Give only the dedicated jail group write access; the host's
        // 0700 spaces directory still keeps the image off user paths.
        std::os::unix::fs::chown(&jail_rootfs, None, Some(cfg.jail_gid))?;
        std::fs::set_permissions(&jail_rootfs, std::fs::Permissions::from_mode(0o660))?;
        std::fs::set_permissions(&jail_kernel, std::fs::Permissions::from_mode(0o444))?;
        std::fs::write(
            config_path(&dir),
            crate::config::vm_config_json(
                Path::new(JAIL_KERNEL),
                Path::new(JAIL_ROOTFS),
                image_kind,
                Path::new(JAIL_VSOCK),
                vcpus,
                mem_mib,
                net.as_ref(),
            ),
        )?;

        // Keep the VM outside the daemon's session so daemon restart does
        // not signal or reap a running guest. `setsid --fork` still gives
        // the jailer a detached process while its child becomes the
        // Firecracker process we identify below.
        let log = std::fs::File::create(dir.join("console.log"))?;
        let memory_limit = format!("memory.max={mem_mib}M");
        let status = std::process::Command::new("setsid")
            .arg("--fork")
            .arg(shinu_core::jailer_bin(root))
            .arg("--id")
            .arg(id.to_string())
            .arg("--exec-file")
            .arg(shinu_core::firecracker_bin(root))
            .arg("--uid")
            .arg(cfg.jail_uid.to_string())
            .arg("--gid")
            .arg(cfg.jail_gid.to_string())
            .arg("--chroot-base-dir")
            .arg(root.join("jail"))
            .arg("--cgroup-version")
            .arg("2")
            .arg("--cgroup")
            .arg(memory_limit)
            .arg("--cgroup")
            .arg("pids.max=512")
            .arg("--")
            .arg("--api-sock")
            .arg("fc.sock")
            .arg("--config-file")
            .arg("fc.json")
            .stdin(std::process::Stdio::null())
            .stderr(log.try_clone()?)
            .stdout(log)
            .status()?;
        if !status.success() {
            return Err(Error::Invalid("could not launch jailer".to_owned()));
        }

        // The jailer writes this pid inside the chroot. Scan as a fallback
        // during the short interval before that file becomes visible.
        let config = config_path(&dir);
        let mut pid = None;
        for _ in 0..100 {
            if let Some(found) = read_pid(&dir)
                && is_vm_process(found, &config, id)
            {
                pid = Some(found);
                break;
            }
            if let Some(found) = find_vm_pid(&config, id) {
                pid = Some(found);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let Some(pid) = pid else {
            let console = std::fs::read_to_string(dir.join("console.log")).unwrap_or_default();
            return Err(Error::Invalid(format!(
                "firecracker exited immediately: {}",
                console
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(" | ")
            )));
        };
        // Keep a deterministic pid file even if this is the scan fallback;
        // normal jailer launches have already created the same path.
        std::fs::write(pid_path(&dir), pid.to_string())?;

        if !wait_ready(&dir, &vsock) {
            let console = std::fs::read_to_string(dir.join("console.log")).unwrap_or_default();
            let _ = stop(&dir, net_cfg);
            return Err(Error::Invalid(format!(
                "vm did not come up: {}",
                console
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(" | ")
            )));
        }
        // The jailer runs Firecracker as its configured non-root uid, but
        // the host-side vsock stays owned by the daemon: 0600 as root is
        // what keeps a space owner from reaching another guest's socket.
        std::fs::set_permissions(&vsock, std::fs::Permissions::from_mode(0o600))?;
        // The control API remains daemon-only: it can resize the balloon
        // and reconfigure devices, so an owner must never receive it.
        std::fs::set_permissions(api_path(&dir), std::fs::Permissions::from_mode(0o600))?;
        touch(&dir)?;
        Ok((vsock, true))
    })();
    if result.is_err() {
        let _ = stop(&dir, net_cfg);
        tap_down(id, net_cfg);
    }
    result
}

fn dir_id(dir: &Path) -> Result<Uuid> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Invalid(format!("VM directory has no UUID: {}", dir.display())))?;
    Uuid::parse_str(name).map_err(|error| {
        Error::Invalid(format!("VM directory is not a UUID ({}): {error}", dir.display()))
    })
}
/// Whether an `e2fsck` exit status means the image is usable.
///
/// Unlike most commands, `e2fsck` uses status 1 to report that it fixed
/// filesystem errors. Status 0 means no errors; both are successful
/// outcomes here. Status 2 (fixed, but a reboot is required) and status 4
/// or 8 (unfixed errors or an operational failure) are not safe to treat
/// as a completed reclaim.
fn e2fsck_ok(code: i32) -> bool {
    matches!(code, 0 | 1)
}

/// Reclaims blocks freed by the guest after its VM has stopped.
pub fn reclaim_image(image: &Path) -> Result<u64> {
    if !image.exists() {
        return Ok(0);
    }

    let before = shinu_core::btrfs::exclusive(image)?;
    let image_arg = image.to_str().ok_or_else(|| {
        Error::Invalid(format!("image path is not valid UTF-8: {}", image.display()))
    })?;
    let args = ["-E", "discard", "-fp", image_arg];
    let output = std::process::Command::new("e2fsck").args(args).output()?;
    if !output.status.code().is_some_and(e2fsck_ok) {
        return Err(command_failure("e2fsck", &args, &output));
    }
    let after = shinu_core::btrfs::exclusive(image)?;
    Ok(before.saturating_sub(after))
}

const RECLAIM_GROWTH_BYTES: u64 = 8 * 1024 * 1024;

fn reclaim_due(current: u64, baseline: Option<u64>) -> bool {
    baseline.is_none_or(|baseline| {
        current.saturating_sub(baseline) >= RECLAIM_GROWTH_BYTES
    })
}
const RECLAIM_DELAY: Duration = Duration::from_secs(60);

fn stopped_at_path(dir: &Path) -> PathBuf {
    dir.join("stopped_at")
}

fn stopped_long_enough(dir: &Path) -> bool {
    let Ok(stopped_at) = std::fs::metadata(stopped_at_path(dir))
        .and_then(|metadata| metadata.modified())
    else {
        // VMs stopped before this marker existed have already had an
        // unbounded amount of time for their dirty pages to settle.
        return true;
    };
    SystemTime::now()
        .duration_since(stopped_at)
        .is_ok_and(|elapsed| elapsed >= RECLAIM_DELAY)
}

fn mark_stopped(dir: &Path) {
    if let Err(error) = std::fs::write(stopped_at_path(dir), now_secs().to_string()) {
        eprintln!("failed to record stop time for {}: {error}", dir.display());
    }
}

fn reclaim_stopped_image(root: &Path, dir: &Path, id: Uuid) {
    // The stop request can return before the kernel writes dirty pages
    // left by Firecracker's dead process. The idle sweep runs later, so
    // the writeback has settled before e2fsck inspects the image.
    if is_running(dir) {
        return;
    }
    if !stopped_long_enough(dir) {
        return;
    }
    let image = shinu_core::space_image(root, id);
    if !image.exists() {
        return;
    }
    let marker = dir.join("reclaimed");
    let baseline = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    let current = match shinu_core::btrfs::exclusive(&image) {
        Ok(size) => size,
        Err(error) => {
            eprintln!("failed to inspect {} for reclaim: {error}", image.display());
            return;
        }
    };
    if !reclaim_due(current, baseline) {
        // An operator may have compacted the image outside shinu. Lower
        // the baseline so later guest writes are not hidden by the old
        // larger value.
        if baseline.is_some_and(|baseline| current < baseline) {
            let _ = std::fs::write(&marker, current.to_string());
        }
        return;
    }
    // e2fsck can take seconds to tens of seconds on a large image. The
    // sweep pays that cost in the background for bounded host usage,
    // which is the premise that makes SaaS disk billing viable. Space
    // images are btrfs reflink clones: discard releases only unshared
    // extents, while shared checkpoint blocks remain protected by COW.
    match reclaim_image(&image) {
        Ok(bytes) => {
            if bytes > 0 {
                match shinu_core::btrfs::exclusive(&image) {
                    Ok(after) => {
                        if let Err(error) = std::fs::write(&marker, after.to_string()) {
                            eprintln!("failed to record reclaim for {}: {error}", image.display());
                        }
                    }
                    Err(error) => eprintln!(
                        "failed to record reclaim baseline for {}: {error}",
                        image.display()
                    ),
                }
                eprintln!(
                    "reclaimed {:.1} MiB from {}",
                    bytes as f64 / (1024.0 * 1024.0),
                    image.display()
                );
            } else {
                // Do not advance the baseline: the kernel may not have
                // written Firecracker's dirty pages yet, so the next
                // sweep must retry after they become visible.
                eprintln!("no blocks reclaimed from {}", image.display());
            }
        }
        Err(error) => eprintln!("failed to reclaim {}: {error}", image.display()),
    }
}
/// Graceful guest shutdown first, signals only as a fallback.
///
/// The API socket could send CtrlAltDel, but SIGTERM kills the VMM
/// outright either way: the guest never runs its shutdown path, so
/// everything still in its page cache is lost. Writes from the previous
/// command would silently vanish (measured: a file written and read back
/// fine within one session came back empty after a stop). So flush the
/// guest first, and keep SIGTERM/SIGKILL for one that is wedged or gone.
pub fn stop(dir: &Path, cfg: &NetConfig) -> Result<bool> {
    let id = dir_id(dir)?;
    let Some(pid) = running_pid(dir) else {
        let _ = std::fs::remove_file(vsock_path(dir));
        let _ = std::fs::remove_file(api_path(dir));
        let _ = std::fs::remove_file(pid_path(dir));
        tap_down(id, cfg);
        clean_jail(dir)?;
        mark_stopped(dir);
        return Ok(false);
    };

    let vsock = vsock_path(dir);
    if vsock.exists() {
        // Durability needs exactly one thing: the guest's dirty pages on
        // the image before the VMM dies. `sync` plus a read-only remount
        // does that and returns normally, leaving the connection intact.
        let _ = exec_in_vm(
            &vsock,
            &key_path(dir),
            shinu_core::VSOCK_SSH_PORT,
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "sync; mount -o remount,ro / 2>/dev/null; sync".to_owned(),
            ],
        );
    }

    signal(pid, "TERM");
    let mut gone = false;
    for _ in 0..100 {
        if running_pid(dir).is_none() {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !gone {
        signal(pid, "KILL");
        for _ in 0..20 {
            if running_pid(dir).is_none() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if !gone {
        tap_down(id, cfg);
        return Err(Error::Invalid(format!(
            "firecracker pid {pid} did not stop"
        )));
    }
    let _ = std::fs::remove_file(vsock_path(dir));
    let _ = std::fs::remove_file(api_path(dir));
    let _ = std::fs::remove_file(pid_path(dir));
    tap_down(id, cfg);
    clean_jail(dir)?;
    mark_stopped(dir);
    Ok(true)
}

/// Idle housekeeping, in two stages.
///
/// A VM that has been unused for a *tenth* of the idle window first has
/// its unused memory handed back to the host; one that passes the full
/// window is shut down. Reclaiming first means a VM the user comes back
/// to is still warm — the balloon deflates in `start` — while the host
/// stops paying for memory nobody is using. Without this stage a VM's
/// host footprint only ever grows, because Firecracker has no free-page
/// reporting to return pages on its own.
///
/// A stopped image is compacted here instead of inside `stop`: the VM's
/// dirty pages can still be written back asynchronously after Firecracker
/// exits, so running e2fsck immediately can miss blocks that are about to
/// land in the image. The `reclaimed` marker avoids rescanning unchanged
/// images on every sweep while keeping the work off the request path.
///
/// A missing `last_used` counts as "just used" rather than "ancient": a
/// VM that booted a moment ago must not be reaped before its first
/// command.
pub fn sweep_idle(root: &Path, idle_secs: u64, cfg: &NetConfig) -> Result<Vec<PathBuf>> {
    let mut stopped = Vec::new();
    let vm_root = root.join("vm");
    let entries = match std::fs::read_dir(&vm_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(stopped),
        Err(error) => return Err(error.into()),
    };
    let now = now_secs();
    // Enough headroom for the guest's page cache and a working margin;
    // reclaiming every last free page would make the next command swap
    // its own working set back in.
    const KEEP_MIB: u64 = 128;
    for entry in entries.flatten() {
        let dir = entry.path();
        if !is_running(&dir) {
            if let Ok(id) = dir_id(&dir) {
                reclaim_stopped_image(root, &dir, id);
            }
            continue;
        }
        let last = std::fs::read_to_string(last_used_path(&dir))
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(now);
        let idle_for = now.saturating_sub(last);
        if idle_for >= idle_secs {
            stop(&dir, cfg)?;
            stopped.push(dir);
        } else if idle_for >= (idle_secs / 10).max(30) {
            reclaim(&dir, KEEP_MIB);
        }
    }
    Ok(stopped)
}
#[cfg(test)]
mod jail_tests {
    use super::{jail_root, jail_socket, VmConfig};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use uuid::Uuid;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct JailEnv {
        uid: Option<OsString>,
        gid: Option<OsString>,
    }

    impl JailEnv {
        fn capture() -> Self {
            Self {
                uid: std::env::var_os("SHINU_JAIL_UID"),
                gid: std::env::var_os("SHINU_JAIL_GID"),
            }
        }
    }

    impl Drop for JailEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.uid {
                    Some(value) => std::env::set_var("SHINU_JAIL_UID", value),
                    None => std::env::remove_var("SHINU_JAIL_UID"),
                }
                match &self.gid {
                    Some(value) => std::env::set_var("SHINU_JAIL_GID", value),
                    None => std::env::remove_var("SHINU_JAIL_GID"),
                }
            }
        }
    }

    #[test]
    fn jail_root_has_the_expected_chroot_layout() {
        let id = Uuid::from_u128(1);
        assert_eq!(
            jail_root(Path::new("/var/lib/shinu"), id),
            PathBuf::from(format!(
                "/var/lib/shinu/jail/firecracker/{id}/root"
            ))
        );
    }

    #[test]
    fn jail_socket_is_inside_the_jail_root() {
        let id = Uuid::from_u128(2);
        let root = jail_root(Path::new("/srv/shinu"), id);
        let socket = jail_socket(Path::new("/srv/shinu"), id);
        assert!(socket.starts_with(&root));
        assert_eq!(socket.strip_prefix(root).expect("socket relative"), Path::new("fc.sock"));
    }

    #[test]
    fn different_uuids_get_disjoint_jails() {
        let first = jail_root(Path::new("/srv/shinu"), Uuid::from_u128(3));
        let second = jail_root(Path::new("/srv/shinu"), Uuid::from_u128(4));
        assert_ne!(first, second);
        assert!(!first.starts_with(&second));
        assert!(!second.starts_with(&first));
    }

    #[test]
    fn jail_ids_default_to_the_dedicated_non_root_user() {
        let _lock = ENV_LOCK.lock().expect("jail env lock");
        let _env = JailEnv::capture();
        unsafe {
            std::env::remove_var("SHINU_JAIL_UID");
            std::env::remove_var("SHINU_JAIL_GID");
        }
        let config = VmConfig::from_env();
        assert_eq!(config.jail_uid, 30_000);
        assert_eq!(config.jail_gid, 30_000);
    }

    #[test]
    fn jail_ids_can_be_overridden_per_deployment() {
        let _lock = ENV_LOCK.lock().expect("jail env lock");
        let _env = JailEnv::capture();
        unsafe {
            std::env::set_var("SHINU_JAIL_UID", "40123");
            std::env::set_var("SHINU_JAIL_GID", "40124");
        }
        let config = VmConfig::from_env();
        assert_eq!(config.jail_uid, 40_123);
        assert_eq!(config.jail_gid, 40_124);
    }
}
#[cfg(test)]
mod reclaim_tests {
    use super::{e2fsck_ok, reclaim_due, reclaim_image, sweep_idle};
    use crate::NetConfig;
        use shinu_core::{space_image, vm_dir};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use uuid::Uuid;

    #[test]
    fn reclaim_missing_image_is_a_noop() {
        let path = std::env::temp_dir().join(format!(
            "shinu-reclaim-missing-{}-{}.ext4",
            std::process::id(),
            Uuid::from_u128(0xfeed)
        ));
        let _ = std::fs::remove_file(&path);
        assert_eq!(reclaim_image(&path).expect("missing image is harmless"), 0);
    }

    #[test]
    fn e2fsck_repair_statuses_are_successful() {
        assert!(e2fsck_ok(0));
        assert!(e2fsck_ok(1));
        assert!(!e2fsck_ok(4));
        assert!(!e2fsck_ok(8));
    }
    #[test]
    fn reclaim_marker_requires_material_growth() {
        let threshold = 8 * 1024 * 1024;
        assert!(reclaim_due(0, None));
        assert!(!reclaim_due(threshold - 1, Some(0)));
        assert!(reclaim_due(threshold, Some(0)));
        assert!(!reclaim_due(0, Some(1)));
    }


    #[test]
    fn sweep_ignores_reclaim_failure_for_stopped_space() {
        let mut component = OsString::from(format!(
            "shinu-sweep-reclaim-{}",
            std::process::id()
        ));
        component.push(OsString::from_vec(vec![0xff]));
        let root = std::env::temp_dir().join(component);
        let id = Uuid::from_u128(0x1234);
        // An invalid path makes btrfs::exclusive fail before touching a
        // real filesystem, so this exercises sweep's best-effort boundary.
        let image = space_image(&root, id);
        std::fs::create_dir_all(image.parent().expect("image parent")).expect("image dir");
        std::fs::write(&image, b"not an ext4 image").expect("image fixture");
        std::fs::create_dir_all(vm_dir(&root, id)).expect("VM directory");

        let config = NetConfig {
            enabled: false,
            base: [172, 31],
            uplink: String::new(),
            allow: Vec::new(),
        };
        let stopped = sweep_idle(&root, 0, &config).expect("sweep ignores reclaim errors");
        assert!(stopped.is_empty());
        std::fs::remove_dir_all(root).expect("test fixture cleanup");
    }
}

/// The one library function an unprivileged process may call. Everything else
/// here (`btrfs::delete`, `btrfs::exclusive`, base building, starting VMs)
/// needs privileges the CLI does not have and must stay inside the daemon.
///
/// Runs `cmd` inside the space's VM over SSH carried on the host's vsock
/// socket, and returns the guest command's exit code. Nothing is rewritten:
/// SSH passes the remote status through, and its own failures surface as 255.
pub fn exec_in_vm(vsock_uds: &Path, key: &Path, port: u16, cmd: &[String]) -> Result<i32> {
    if cmd.is_empty() {
        return Err(Error::Invalid("exec needs a command".to_owned()));
    }
    let helper = shinu_core::vsock_helper()?;
    // Host key checking is pure noise here: the key is generated once in the
    // base image and therefore shared by every clone of it, and the transport
    // is a host-kernel vsock socket that never touches a network, so there is
    // no party in the middle to authenticate against.
    let status = std::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "IdentitiesOnly=yes",
        ])
        .arg("-o")
        .arg(format!(
            "ProxyCommand={} {} {port}",
            helper.display(),
            vsock_uds.display()
        ))
        .arg("-i")
        .arg(key)
        // The hostname is a placeholder: ProxyCommand decides the real peer.
        .arg("root@shinu")
        .arg("--")
        .arg(shinu_core::shell_quote(cmd))
        .status()?;
    Ok(status.code().unwrap_or(255))
}
