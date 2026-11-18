pub use crate::net::{egress_rules, peer_rules};

use crate::config::VmConfig;
use crate::net::NetConfig;
use crate::snapshot_memory::data_extents;
use shinu_core::{Error, Image, ReadySpec, Result};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
const JAIL_SNAP_MEM: &str = "snap.mem";
const JAIL_SNAP_STATE: &str = "snap.state";

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
    let mut command = String::with_capacity(args.iter().fold(program.len(), |length, arg| {
        length.saturating_add(arg.len()).saturating_add(1)
    }));
    command.push_str(program);
    for arg in args {
        command.push(' ');
        command.push_str(arg);
    }
    Error::Internal(format!(
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn console_tail(dir: &Path) -> String {
    const MAX: usize = 4 * 1024;
    let bytes = std::fs::read(dir.join("console.log")).unwrap_or_default();
    let start = bytes.len().saturating_sub(MAX);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
    Ok(std::process::Command::new(program).args(args).output()?)
}

// Guest sync cost scales with dirty disk pages; bound a wedged guest without
// applying the five-second control-plane deadline to a durability operation.
const GUEST_FLUSH_TIMEOUT: Duration = Duration::from_mins(1);
const PROCESS_GROUP_POLL_INTERVAL: Duration = Duration::from_millis(25);

fn ssh_command(
    helper: &Path,
    vsock_uds: &Path,
    key: &Path,
    port: u16,
    cmd: &[String],
) -> std::process::Command {
    let mut command = std::process::Command::new("ssh");
    command
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
        .arg(shinu_core::shell_quote(cmd));
    command
}

fn kill_process_group(pgid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--"])
        .arg(format!("-{pgid}"))
        .status();
}

fn run_process_group(
    mut command: std::process::Command,
    timeout: Duration,
    input: Option<(String, std::fs::File)>,
) -> Option<std::process::ExitStatus> {
    // The SSH client, proxy and optional stdin producer share one killable
    // group. Keep the deadline until both client and producer have finished.
    command.process_group(0);
    if input.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    let Ok(mut child) = command.spawn() else {
        return None;
    };
    let pgid = child.id();
    let deadline = Instant::now() + timeout;
    let mut producer = if let Some((prefix, payload)) = input {
        let Some(stdin) = child.stdin.take() else {
            kill_process_group(pgid);
            let _ = child.wait();
            return None;
        };
        let output: std::os::fd::OwnedFd = stdin.into();
        let mut source = std::process::Command::new("sh");
        source.args(["-c", "printf '%s\\n' \"$SHINU_SNAPSHOT_SETUP_NONCE\"; unset SHINU_SNAPSHOT_SETUP_NONCE; exec cat"])
            .env("SHINU_SNAPSHOT_SETUP_NONCE", prefix)
            .stdin(payload).stdout(std::process::Stdio::from(output)).process_group(pgid.cast_signed());
        let spawned = source.spawn();
        // Command retains configured descriptors for reuse; closing its copy
        // here is essential so producer exit really sends EOF to SSH.
        drop(source);
        match spawned {
            Ok(source) => Some(source),
            Err(_) => {
                kill_process_group(pgid);
                let _ = child.wait();
                return None;
            }
        }
    } else {
        None
    };
    let mut status = None;
    let mut input_finished = producer.is_none();
    let result = loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(done)) => {
                    status = Some(done);
                    if !done.success() {
                        kill_process_group(pgid);
                        break status;
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    kill_process_group(pgid);
                    break None;
                }
            }
        }
        if !input_finished && let Some(source) = producer.as_mut() {
            match source.try_wait() {
                Ok(Some(done)) if done.success() => input_finished = true,
                Ok(Some(_)) | Err(_) => {
                    kill_process_group(pgid);
                    break None;
                }
                Ok(None) => {}
            }
        }
        if status.is_some() && input_finished {
            break status;
        }
        let now = Instant::now();
        if now >= deadline {
            kill_process_group(pgid);
            break None;
        }
        std::thread::sleep(PROCESS_GROUP_POLL_INTERVAL.min(deadline.duration_since(now)));
    };
    let _ = child.wait();
    if let Some(mut source) = producer {
        let _ = source.wait();
    }
    result
}

fn run_guest_flush(vsock_uds: &Path, key: &Path) -> Option<std::process::ExitStatus> {
    let helper = shinu_core::vsock_helper().ok()?;
    let command = [
        "sh".to_owned(),
        "-c".to_owned(),
        "sync; mount -o remount,ro / 2>/dev/null; sync".to_owned(),
    ];
    let ssh = ssh_command(
        &helper,
        vsock_uds,
        key,
        shinu_core::VSOCK_SSH_PORT,
        &command,
    );
    run_process_group(ssh, GUEST_FLUSH_TIMEOUT, None)
}

/// Whether an asset's no-follow metadata satisfies the root-executed trust
/// boundary. Keep this scalar seam testable without impersonating uid 0.
fn trusted_asset_attributes(regular: bool, uid: u32, mode: u32, expected_uid: u32) -> bool {
    regular && uid == expected_uid && mode & 0o111 != 0 && mode & 0o022 == 0
}

fn validate_vm_asset(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::Invalid(format!(
            "cannot validate {label} asset {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !trusted_asset_attributes(
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode(),
            0,
        )
    {
        return Err(Error::Invalid(format!(
            "unsafe {label} asset: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_vm_assets(jailer: &Path, firecracker: &Path) -> Result<()> {
    validate_vm_asset(jailer, "jailer")?;
    validate_vm_asset(firecracker, "firecracker")
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
    if output.status.success() || String::from_utf8_lossy(&output.stderr).contains("File exists") {
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
            return Err(Error::Internal(format!(
                "network address conflict for uuid {id}: {address} is already on {interface}; set SHINU_NET_BASE"
            )));
        }
    }
    Ok(())
}

/// The daemon owns this chain so callback ACCEPTs and tap fences have one
/// stable ordering independent of which VM happens to start first.
const SHINU_INPUT_CHAIN: &str = "SHINU-INPUT";
// iptables serialises each command, not the check-plus-append sequence. Keep
// concurrent VM starts from placing a tap DROP between shared ACCEPT updates.
static INPUT_CHAIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
// FORWARD rules use absolute insertion positions. Hold one process-wide lock
// across each complete batch so concurrent VM lifecycle operations cannot
// interleave a broad allow ahead of another tap's isolation fence.
static FORWARD_CHAIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_forward_chain() -> std::sync::MutexGuard<'static, ()> {
    FORWARD_CHAIN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs an iptables check, then the add if the rule is absent.
///
/// Every invocation waits for /run/xtables.lock rather than failing fast:
/// iptables serialises all callers on that file, and concurrent VM boots
/// would otherwise lose the race and report "Resource temporarily
/// unavailable" instead of configuring their network.
fn ensure_iptables_rule(check: &[&str], add: &[&str]) -> Result<()> {
    fn with_wait<'a>(args: &[&'a str]) -> Vec<&'a str> {
        let mut full = vec!["-w", "5"];
        full.extend_from_slice(args);
        full
    }
    let checked = run_command("iptables", &with_wait(check))?;
    if checked.status.success() {
        return Ok(());
    }
    require_success("iptables", &with_wait(add))
}

fn input_chain_create_args() -> [&'static str; 2] {
    ["-N", SHINU_INPUT_CHAIN]
}

fn input_chain_jump_check_args() -> [&'static str; 4] {
    ["-C", "INPUT", "-j", SHINU_INPUT_CHAIN]
}

fn input_chain_jump_add_args() -> [&'static str; 5] {
    ["-I", "INPUT", "1", "-j", SHINU_INPUT_CHAIN]
}

/// Creates the shared chain and places its sole INPUT jump at position one.
fn ensure_input_chain() -> Result<()> {
    let create = input_chain_create_args();
    let mut create_wait = vec!["-w", "5"];
    create_wait.extend_from_slice(&create);
    let output = run_command("iptables", &create_wait)?;
    if !output.status.success()
        && !String::from_utf8_lossy(&output.stderr).contains("already exists")
    {
        return Err(command_failure("iptables", &create_wait, &output));
    }
    let check = input_chain_jump_check_args();
    let add = input_chain_jump_add_args();
    ensure_iptables_rule(&check, &add)
}

fn input_rule_args(rule: &[String]) -> (Vec<String>, Vec<String>) {
    let mut check = vec!["-C".to_owned(), SHINU_INPUT_CHAIN.to_owned()];
    check.extend(rule.iter().cloned());
    let mut add = vec!["-A".to_owned(), SHINU_INPUT_CHAIN.to_owned()];
    add.extend(rule.iter().cloned());
    (check, add)
}

fn ensure_input_rule(rule: &[String]) -> Result<()> {
    let (check, add) = input_rule_args(rule);
    let check = check.iter().map(String::as_str).collect::<Vec<_>>();
    let add = add.iter().map(String::as_str).collect::<Vec<_>>();
    ensure_iptables_rule(&check, &add)
}

fn delete_iptables_rule(chain: &str, rule: &[String]) {
    let mut args = vec![
        "-w".to_owned(),
        "5".to_owned(),
        "-D".to_owned(),
        chain.to_owned(),
    ];
    args.extend(rule.iter().cloned());
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let _ = run_command("iptables", &args);
}

fn ensure_forward_rule(rule: &[String], position: usize) -> Result<()> {
    let mut check = vec!["-C".to_owned(), "FORWARD".to_owned()];
    check.extend(rule.iter().cloned());
    let check = check.iter().map(String::as_str).collect::<Vec<_>>();
    let mut add = vec!["-I".to_owned(), "FORWARD".to_owned(), position.to_string()];
    add.extend(rule.iter().cloned());
    let add = add.iter().map(String::as_str).collect::<Vec<_>>();
    ensure_iptables_rule(&check, &add)
}

fn claim_tap_file(path: &Path, tap: &str) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(0o400000) // Linux O_NOFOLLOW.
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(Error::Invalid(format!("unsafe TAP lock for {tap}")));
    }
    file.try_lock().map_err(|error| {
        Error::TapBusy(format!(
            "TAP {tap} is being configured by another shinud: {error}"
        ))
    })?;
    Ok(file)
}

/// Serialize create-to-VMM-attachment across daemon processes. Lock files stay
/// linked after release so every contender always locks the same inode.
fn claim_tap(id: Uuid) -> Result<std::fs::File> {
    let directory = Path::new("/run/shinu-tap-locks");
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(Error::Invalid("unsafe TAP lock directory".into()));
    }
    let tap = crate::net::tap_name(id);
    let file = claim_tap_file(&directory.join(format!("{tap}.lock")), &tap)?;
    if file.metadata()?.uid() != 0 {
        return Err(Error::Invalid(format!("unsafe TAP lock owner for {tap}")));
    }
    Ok(file)
}

fn tap_holder(tap: &str, proc_root: &Path) -> Result<Option<std::ffi::OsString>> {
    let mut contents = String::new();
    for process in std::fs::read_dir(proc_root)? {
        let process = process?;
        let pid = process.file_name();
        if !pid.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let descriptors = match std::fs::read_dir(process.path().join("fdinfo")) {
            Ok(descriptors) => descriptors,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(Error::Internal(format!(
                    "cannot prove TAP {tap} unused: inspecting process {}: {error}",
                    pid.to_string_lossy()
                )));
            }
        };
        for descriptor in descriptors {
            let descriptor = descriptor?;
            let mut file = match std::fs::File::open(descriptor.path()) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(Error::Internal(format!(
                        "cannot prove TAP {tap} unused: {error}"
                    )));
                }
            };
            contents.clear();
            match file.read_to_string(&mut contents) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(Error::Internal(format!(
                        "cannot prove TAP {tap} unused: {error}"
                    )));
                }
            }
            if contents.lines().any(|line| {
                line.strip_prefix("iff:")
                    .is_some_and(|name| name.trim() == tap)
            }) {
                return Ok(Some(pid));
            }
        }
    }
    Ok(None)
}

/// The caller holds its TAP claim until the VMM owns the fd (or has stopped).
/// Sysfs/proc roots and the ip command are the host adapter, shared with tests.
fn prepare_tap(
    tap: &str,
    cfg: &VmConfig,
    sys_net: &Path,
    proc_root: &Path,
    mut ip: impl FnMut(&[&str]) -> Result<std::process::Output>,
) -> Result<()> {
    let uid = cfg.jail_uid.to_string();
    let gid = cfg.jail_gid.to_string();
    let create = [
        "tuntap", "add", "dev", tap, "mode", "tap", "user", &uid, "group", &gid,
    ];
    let output = ip(&create)?;
    if output.status.success() {
        return Ok(());
    }
    // iproute2 uses IFF_TUN_EXCL. Existing TAPs can report EBUSY or EEXIST;
    // neither permits changing ownership or deleting an attached interface.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("File exists") && !stderr.contains("Device or resource busy") {
        return Err(command_failure("ip", &create, &output));
    }
    let interface = sys_net.join(tap);
    let attribute = |field| -> Result<i64> {
        std::fs::read_to_string(interface.join(field))?
            .trim()
            .parse::<i64>()
            .map_err(|_| Error::Invalid(format!("invalid TAP {tap} {field}")))
    };
    let owner = attribute("owner")?;
    let group = attribute("group")?;
    if let Some(pid) = tap_holder(tap, proc_root)? {
        return Err(Error::TapBusy(format!(
            "TAP {tap} is in use by process {}; refusing to reconfigure it",
            pid.to_string_lossy()
        )));
    }
    if owner == i64::from(cfg.jail_uid) && group == i64::from(cfg.jail_gid) {
        return Ok(());
    }
    let delete = ["link", "delete", "dev", tap];
    let output = ip(&delete)?;
    if !output.status.success() {
        return Err(command_failure("ip", &delete, &output));
    }
    let output = ip(&create)?;
    if !output.status.success() {
        return Err(command_failure("ip", &create, &output));
    }
    Ok(())
}

/// Creates a TAP for the jailed identity, then configures its network.
/// A rejected pre-existing TAP is never cleaned up by this transaction.
fn tap_up(id: Uuid, cfg: &NetConfig, vm_cfg: &VmConfig) -> Result<()> {
    tap_up_with_peers(id, cfg, &[], vm_cfg)
}

enum TapSetup {
    Create,
    Existing,
}

fn tap_up_with_peers(id: Uuid, cfg: &NetConfig, peers: &[String], vm_cfg: &VmConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    let tap = crate::net::tap_name(id);
    prepare_tap(
        &tap,
        vm_cfg,
        Path::new("/sys/class/net"),
        Path::new("/proc"),
        |args| {
            Ok(std::process::Command::new("ip")
                .env("LC_ALL", "C")
                .args(args)
                .output()?)
        },
    )?;
    let result = configure_tap(id, cfg, peers, TapSetup::Create);
    if result.is_err() {
        tap_down_with_peers(id, cfg, peers);
    }
    result
}

fn configure_tap(id: Uuid, cfg: &NetConfig, peers: &[String], setup: TapSetup) -> Result<()> {
    reassert_tap_policy(id, cfg, peers, setup)?;
    expose_tap(id, cfg)
}

/// Brings a TAP up; callers first prove its address and firewall policy.
fn expose_tap(id: Uuid, cfg: &NetConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    require_success("ip", &["link", "set", &crate::net::tap_name(id), "up"])
}

/// Asserts a TAP's address and firewall policy without changing link state,
/// so a quarantined restore can do this while the guest is still thawing.
fn reassert_tap_policy(id: Uuid, cfg: &NetConfig, peers: &[String], setup: TapSetup) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    let tap = crate::net::tap_name(id);
    let (third, fourth_base) = crate::net::net_slot(id);
    let network = format!("{}.{}.{}.{}", cfg.base[0], cfg.base[1], third, fourth_base);
    let host = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 1
    );
    let host_cidr = format!("{host}/30");
    let network_cidr = format!("{network}/30");

    ensure_address_free(id, &tap, &host_cidr)?;
    match setup {
        TapSetup::Create => allow_file_exists("ip", &["addr", "add", &host_cidr, "dev", &tap])?,
        TapSetup::Existing => require_success("ip", &["addr", "replace", &host_cidr, "dev", &tap])?,
    }
    ensure_address_free(id, &tap, &host_cidr)?;

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

    {
        let _forward_chain_guard = lock_forward_chain();
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
        for (position, rule) in crate::net::egress_rules_with_peers(&tap, &host, &cfg.allow, peers)
            .iter()
            .enumerate()
        {
            ensure_forward_rule(rule, position + 1)?;
        }
    }
    let _input_chain_guard = INPUT_CHAIN_LOCK
        .lock()
        .map_err(|_| Error::Internal("input firewall lock poisoned".to_owned()))?;
    // The guest uses a static /30 address and a public resolver baked into
    // the image; it has no DHCP or host DNS dependency. Public egress still
    // takes FORWARD because its destination is not a host-local address.
    ensure_input_chain()?;
    for allow in &cfg.host_allow {
        ensure_input_rule(&crate::net::host_allow_rule(allow))?;
    }
    // SHINU-INPUT is shared: callback ACCEPTs are appended before the first
    // tap DROP, and every later tap appends only its DROP. Therefore accepts
    // stay ahead of every per-tap DROP even when taps start concurrently.
    ensure_input_rule(&crate::net::input_drop_rule(&tap))?;
    Ok(())
}
/// Adds the current named-network peer exceptions to an existing tap.
///
/// This uses the same fixed positions as `tap_up`: the gateway occupies the
/// first slot, peer /32s follow, and the inter-tap fence and operator/private
/// rules remain after them. `ensure_forward_rule` makes repeated refreshes
/// idempotent instead of growing FORWARD on every start.
pub fn refresh_peer_rules(id: Uuid, cfg: &NetConfig, peers: &[String]) -> Result<()> {
    if !cfg.enabled || peers.is_empty() {
        return Ok(());
    }
    let tap = crate::net::tap_name(id);
    let _forward_chain_guard = lock_forward_chain();
    let prefix = 1;
    for (position, peer) in peers.iter().enumerate() {
        let rule = crate::net::peer_rule(&tap, peer);
        ensure_forward_rule(&rule, prefix + position + 1)?;
    }
    Ok(())
}

/// Removes only named-network peer exceptions from an existing tap.
///
/// Stopping one member must not tear down the gateway, egress, or blanket
/// isolation rules that still protect the remaining VM.
pub fn remove_peer_rules(id: Uuid, cfg: &NetConfig, peers: &[String]) {
    if !cfg.enabled || peers.is_empty() {
        return;
    }
    let tap = crate::net::tap_name(id);
    let _forward_chain_guard = lock_forward_chain();
    for peer in peers {
        let rule = crate::net::peer_rule(&tap, peer);
        let mut args = vec![
            "-w".to_owned(),
            "5".to_owned(),
            "-D".to_owned(),
            "FORWARD".to_owned(),
        ];
        args.extend(rule);
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let _ = std::process::Command::new("iptables").args(args).output();
    }
}

/// Removes this VM's rules and tap. Cleanup is deliberately best effort:
/// a stopped VM with a missing tap is already in the desired state.
pub fn tap_down(id: Uuid, cfg: &NetConfig) {
    tap_down_with_peers(id, cfg, &[]);
}

pub fn tap_down_with_peers(id: Uuid, cfg: &NetConfig, peers: &[String]) {
    if !cfg.enabled {
        return;
    }
    let tap = crate::net::tap_name(id);
    let (third, fourth_base) = crate::net::net_slot(id);
    let network = format!("{}.{}.{}.{}", cfg.base[0], cfg.base[1], third, fourth_base);
    let network_cidr = format!("{network}/30");
    let gateway = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 1
    );
    let _ = std::process::Command::new("iptables")
        .args([
            "-w",
            "5",
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
    {
        let _forward_chain_guard = lock_forward_chain();
        let _ = std::process::Command::new("iptables")
            .args([
                "-w",
                "5",
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
                "-w",
                "5",
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
        for rule in crate::net::egress_rules_with_peers(&tap, &gateway, &cfg.allow, peers) {
            let mut args = vec![
                "-w".to_owned(),
                "5".to_owned(),
                "-D".to_owned(),
                "FORWARD".to_owned(),
            ];
            args.extend(rule);
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let _ = std::process::Command::new("iptables").args(args).output();
        }
    }
    let input_drop = crate::net::input_drop_rule(&tap);
    delete_iptables_rule(SHINU_INPUT_CHAIN, &input_drop);
    // Older binaries inserted the fence directly into INPUT. Keep deleting
    // that legacy rule so upgraded hosts converge after each VM stops.
    delete_iptables_rule("INPUT", &input_drop);
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
            return Err(Error::Internal(
                "ssh-keygen failed for space key".to_owned(),
            ));
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

/// The pid of the Firecracker instance launched for `id`.
///
/// `setsid --fork` deliberately loses the grandchild's pid. The jailer
/// records Firecracker's pid inside the jail, while the process scan below
/// remains a fallback for the short window before that file is written. Cold
/// boots can be identified by their config path; restores rely on the UUID
/// that the jailer forwards to Firecracker because they have no config file.
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
/// check. The jailer forwards Firecracker's UUID argument after chrooting, so
/// matching that identity keeps discovery valid for restores without a
/// config path, while the config match preserves cold-boot discovery.
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
    let id = id.to_string();
    let config = config.as_os_str().as_encoded_bytes();
    matches_vm_args(&cmdline, |arg| arg == id.as_bytes(), |arg| arg == config)
}

fn matches_vm_args(
    cmdline: &[u8],
    matches_id: impl Fn(&[u8]) -> bool,
    matches_config: impl Fn(&[u8]) -> bool,
) -> bool {
    let mut previous_was_id_flag = false;
    for arg in cmdline.split(|byte| *byte == 0) {
        if arg.strip_prefix(b"--id=").is_some_and(&matches_id)
            || (previous_was_id_flag && matches_id(arg))
            || matches_config(arg)
        {
            return true;
        }
        previous_was_id_flag = arg == b"--id";
    }
    false
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

/// Find a live Firecracker or jailer for this root without relying on PID files.
/// `Ok(None)` means no match was found; an error means absence could not be
/// verified. Run with the host's process view and hold the daemon's root lock
/// through the check and maintenance operation to exclude new launches.
pub fn offline_vm_process(root: &Path, space_ids: Vec<Uuid>) -> std::io::Result<Option<u32>> {
    scan_offline_vm_processes(root, Path::new("/proc"), space_ids)
}

fn scan_offline_vm_processes(
    root: &Path,
    proc_root: &Path,
    space_ids: Vec<Uuid>,
) -> std::io::Result<Option<u32>> {
    use std::collections::HashSet;

    let mut ids: HashSet<_> = space_ids.into_iter().collect();
    // A detached VMM can outlive the daemon's bookkeeping. Include UUIDs
    // still present in either half of the jail layout.
    for name in ["vm", "jail/firecracker"] {
        for entry in std::fs::read_dir(root.join(name))? {
            let name = entry?.file_name();
            if let Ok(id) = Uuid::try_parse_ascii(name.as_encoded_bytes()) {
                ids.insert(id);
            }
        }
    }
    if ids.is_empty() {
        return Ok(None);
    }
    let configs: HashSet<_> = ids
        .iter()
        .map(|&id| {
            config_path(&shinu_core::vm_dir(root, id))
                .into_os_string()
                .into_encoded_bytes()
        })
        .collect();

    for entry in std::fs::read_dir(proc_root)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let process = entry.path();
        if !live_vm_process(&process)? {
            continue;
        }
        let Some(cmdline) = read_process_file(&process, "cmdline")? else {
            continue;
        };
        if cmdline.is_empty() {
            // A process exiting after the first status read can have no args
            // by the time we read cmdline. Only ignore it if it is now gone.
            if !live_vm_process(&process)? {
                continue;
            }
            return Err(std::io::Error::other(format!(
                "{} has no process arguments",
                process.display()
            )));
        }
        if matches_vm_args(
            &cmdline,
            |arg| Uuid::try_parse_ascii(arg).is_ok_and(|id| ids.contains(&id)),
            |arg| configs.contains(arg),
        ) {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

fn read_process_file(process: &Path, name: &str) -> std::io::Result<Option<Vec<u8>>> {
    let path = process.join(name);
    match std::fs::read(&path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error)
            if (error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH))
                && !process.try_exists()? =>
        {
            Ok(None)
        }
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            format!("inspect {}: {error}", path.display()),
        )),
    }
}

fn live_vm_process(process: &Path) -> std::io::Result<bool> {
    let Some(status) = read_process_file(process, "status")? else {
        return Ok(false);
    };
    // Linux comm strings need not be UTF-8.
    let field = |prefix: &[u8]| {
        status
            .split(|byte| *byte == b'\n')
            .find_map(|line| line.strip_prefix(prefix))
            .filter(|field| !field.is_empty())
            .ok_or_else(|| {
                std::io::Error::other(format!("invalid process status at {}", process.display()))
            })
    };
    let name = field(b"Name:\t")?;
    if name != b"firecracker" && name != b"jailer" {
        return Ok(false);
    }
    let state = field(b"State:\t")?[0];
    Ok(!matches!(state, b'Z' | b'X'))
}

#[cfg(test)]
mod offline_process_tests {
    use super::*;

    #[test]
    fn offline_scan_distinguishes_absence_from_unreadable_identity() {
        let root = std::env::temp_dir().join(format!("shinu-offline-{}", Uuid::new_v4()));
        shinu_core::init_layout(&root).unwrap();
        let id = Uuid::new_v4();
        // Recognize a jail UUID even if the corresponding vm/ entry is gone.
        std::fs::create_dir_all(jail_root(&root, id)).unwrap();
        let proc_root = root.join("proc");
        let scan = || scan_offline_vm_processes(&root, &proc_root, Vec::new());
        assert!(scan().is_err());
        let process = proc_root.join("123");
        std::fs::create_dir_all(&process).unwrap();
        std::fs::write(process.join("status"), b"Name:\tfirecracker\nState:\tZ\n").unwrap();
        assert_eq!(scan().unwrap(), None);

        std::fs::write(process.join("status"), b"Name:\tfirecracker\nState:\tS\n").unwrap();
        assert!(scan().is_err());
        let cmdline = process.join("cmdline");
        std::fs::write(&cmdline, b"").unwrap();
        assert!(scan().is_err());
        std::fs::write(&cmdline, format!("firecracker\0--id={}\0", Uuid::new_v4())).unwrap();
        assert_eq!(scan().unwrap(), None);
        std::fs::write(cmdline, format!("firecracker\0--id={id}\0")).unwrap();
        assert_eq!(scan().unwrap(), Some(123));
        std::fs::remove_dir_all(root).unwrap();
    }
}

pub fn touch(dir: &Path) -> Result<()> {
    std::fs::write(last_used_path(dir), now_secs().to_string())?;
    Ok(())
}

/// Control-plane calls need a short deadline; a slow response indicates a
/// wedged VMM.
const API_TIMEOUT_SECS: u32 = 5;

/// Snapshot writes scale with guest memory and storage speed, so they use a
/// separate generous deadline rather than the control-plane timeout.
const SNAPSHOT_TIMEOUT_SECS: u32 = 900;

/// Sends one request to Firecracker's Unix-socket control API.
/// `None` means transport failure or Firecracker rejection. The curl
/// `--fail` flag makes HTTP 4xx/5xx responses failures instead of bodies.
fn api(dir: &Path, method: &str, path: &str, body: Option<&str>) -> Option<String> {
    api_with_timeout(dir, method, path, body, API_TIMEOUT_SECS)
}

/// Uses a caller-supplied deadline for requests whose duration scales with
/// guest size.
fn api_with_timeout(
    dir: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout_secs: u32,
) -> Option<String> {
    let mut command = std::process::Command::new("curl");
    command
        .arg("-s")
        .arg("--fail")
        .arg("--max-time")
        .arg(timeout_secs.to_string())
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
    #[cfg(test)]
    ledger_journal::record(format!("api {method} {path}"));
    let out = command.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Reads an unsigned numeric field from Firecracker's flat statistics object.
fn stat_field(stats: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = &stats[stats.find(&needle)? + needle.len()..];
    let digits = rest.trim_start();
    let end = digits
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].parse().ok()
}

/// Hands guest-unused memory back to the host through Firecracker's balloon.
/// Free-page reporting returns pages the guest kernel marks free, but explicit
/// inflation remains necessary for page cache. `keep_mib` leaves a working
/// margin available to the guest.
/// Returns the MiB actually requested.
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

/// The memory representation requested from Firecracker when creating a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotKind {
    Full,
    Diff,
}

impl SnapshotKind {
    fn firecracker_name(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Diff => "Diff",
        }
    }
}

/// Captured files and application-freeze / VM-pause durations, in milliseconds.
#[derive(Debug, Default)]
pub struct SnapshotCapture {
    pub memory: Option<(PathBuf, PathBuf)>,
    pub pause_ms: u64,
    pub freeze_ms: u64,
    pub thaw_ms: u64,
    pub guest_snapshot_nonce: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotStep {
    Freeze,
    Pause,
    Create,
    Cut,
    Resume,
    Thaw,
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// The transaction owns cleanup, not the caller. Even an ambiguous pause
// transport failure must attempt resume before thawing the guest.
fn snapshot_transaction(
    memory: bool,
    mut step: impl FnMut(SnapshotStep) -> Result<()>,
) -> Result<SnapshotCapture> {
    let mut capture = SnapshotCapture::default();
    let freeze_start = Instant::now();
    let frozen = step(SnapshotStep::Freeze);
    capture.freeze_ms = elapsed_ms(freeze_start);
    let mut result = frozen;
    if result.is_ok() {
        let pause_start = Instant::now();
        result = (|| {
            step(SnapshotStep::Pause)?;
            if memory {
                step(SnapshotStep::Create)?;
            }
            step(SnapshotStep::Cut)
        })();
        let resumed = step(SnapshotStep::Resume);
        capture.pause_ms = elapsed_ms(pause_start);
        result = combine_snapshot_results(result, resumed);
    }
    let thaw_start = Instant::now();
    let thawed = step(SnapshotStep::Thaw);
    capture.thaw_ms = elapsed_ms(thaw_start);
    combine_snapshot_results(result, thawed)?;
    Ok(capture)
}

fn combine_snapshot_results(primary: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (primary, cleanup) {
        (Err(primary), Err(cleanup)) => Err(Error::Internal(format!(
            "{primary}; snapshot cleanup also failed: {cleanup}"
        ))),
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreStep {
    Quarantine,
    Load,
    Thaw,
    Ready,
    Configure,
    Expose,
    ApplicationReady,
}

/// Fully serial: overlapping `Ready` with later steps measured no gain on
/// 4-vCPU nested guests (the extra socat/sshd forks slowed `Configure` and
/// `ApplicationReady`), and the network hook in `ApplicationReady` uses SSH.
fn restore_transaction(mut step: impl FnMut(RestoreStep) -> Result<()>) -> Result<()> {
    step(RestoreStep::Quarantine)?;
    let loaded = step(RestoreStep::Load);
    // A failed/lost load reply can still leave live frozen vCPUs behind.
    let thawed = step(RestoreStep::Thaw);
    combine_snapshot_results(loaded, thawed)?;
    step(RestoreStep::Ready)?;
    step(RestoreStep::Configure)?;
    step(RestoreStep::Expose)?;
    step(RestoreStep::ApplicationReady)
}

// The listener is captured in guest RAM, so restore can thaw without starting
// sshd/PAM under a frozen root or competing with application timer catch-up.
fn snapshot_line<'a, const N: usize>(
    reader: &mut impl std::io::Read,
    buffer: &'a mut [u8; N],
) -> std::io::Result<&'a [u8]> {
    for length in 0..buffer.len() {
        reader.read_exact(&mut buffer[length..=length])?;
        if buffer[length] == b'\n' {
            return Ok(&buffer[..length]);
        }
    }
    Err(std::io::Error::other("oversized snapshot worker reply"))
}

// Nonblocking transport enforces one host monotonic deadline, including the
// Unix/vsock handshake and every byte of a slow or malicious guest response.
struct ReadyTransport {
    stream: std::os::unix::net::UnixStream,
    deadline: Instant,
    buffer: [u8; 256],
}

impl ReadyTransport {
    fn connect(path: &Path, deadline: Instant) -> Result<Self> {
        unsafe extern "C" {
            fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
            fn connect(fd: i32, address: *const u8, length: u32) -> i32;
        }
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.len() >= 108 || bytes.contains(&0) {
            return Err(Error::Invalid("readiness socket path is too long".into()));
        }
        let mut address = [0_u8; 110];
        address[..2].copy_from_slice(&1_u16.to_ne_bytes());
        address[2..2 + bytes.len()].copy_from_slice(bytes);
        // SAFETY: Linux AF_UNIX, SOCK_STREAM | NONBLOCK | CLOEXEC, no pointers.
        let fd = unsafe { socket(1, 1 | 0x800 | 0x80000, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: socket returned a fresh uniquely owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Internal("readiness transport timeout".into()));
            }
            // SAFETY: address is a live Linux sockaddr_un, length fits its array.
            if unsafe {
                connect(
                    fd.as_raw_fd(),
                    address.as_ptr(),
                    u32::try_from(3 + bytes.len()).unwrap(),
                )
            } == 0
            {
                return Ok(Self {
                    stream: fd.into(),
                    deadline,
                    buffer: [0; 256],
                });
            }
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) && error.raw_os_error() != Some(115)
            {
                return Err(error.into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.check_deadline()?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(Error::Internal("readiness transport disconnected".into())),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn check_deadline(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(Error::Internal("readiness transport timeout".into()));
        }
        Ok(())
    }

    fn line(&mut self) -> Result<&str> {
        use std::io::Read;
        let mut length = 0;
        while length < self.buffer.len() {
            self.check_deadline()?;
            let mut byte = [0];
            match self.stream.read(&mut byte) {
                Ok(0) => return Err(Error::Internal("readiness transport disconnected".into())),
                Ok(_) if byte[0] == b'\n' => {
                    return std::str::from_utf8(&self.buffer[..length])
                        .map_err(|_| Error::Internal("invalid readiness response".into()));
                }
                Ok(_) => {
                    self.buffer[length] = byte[0];
                    length += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::Internal("oversized readiness response".into()))
    }

    fn guest(dir: &Path, deadline: Instant) -> Result<Self> {
        let mut transport = Self::connect(&vsock_path(dir), deadline)?;
        transport.write(b"CONNECT 2224\n")?;
        if !transport.line()?.starts_with("OK ") || transport.line()? != "SHINU-SNAPSHOT-1" {
            return Err(Error::Internal(
                "unsupported readiness guest protocol".into(),
            ));
        }
        Ok(transport)
    }
}

fn ready_capability(dir: &Path, deadline: Instant) -> Result<()> {
    let nonce = std::fs::read_to_string(dir.join("snapshot-worker-nonce"))?;
    let mut transport =
        ReadyTransport::guest(dir, deadline.min(Instant::now() + Duration::from_secs(2)))?;
    transport.write(format!("capabilities {nonce}\n").as_bytes())?;
    if transport.line()? != "READY-1" {
        return Err(Error::Internal("guest lacks READY-1 capability".into()));
    }
    Ok(())
}

enum SetupError {
    /// No helper, or a helper predating `setup`: nothing was applied.
    Unsupported,
    Failed(Error),
}

/// One restored-generation identity frame: wall clock and, when networked,
/// the eth0 MAC/address/gateway. The guest helper validates every field.
fn guest_setup_frame(
    nonce: &str,
    now: SystemTime,
    net: Option<&crate::net::NetSpec>,
) -> Result<String> {
    let clock = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Internal("host clock precedes the epoch".into()))?
        .as_nanos();
    Ok(net.map_or_else(
        || format!("setup {nonce} {clock}\n"),
        |spec| {
            format!(
                "setup {nonce} {clock} {} {} {}\n",
                spec.mac, spec.guest_cidr, spec.gateway
            )
        },
    ))
}

// Platform setup is a separate helper action, never a readiness request: it
// runs no policy argv and its `SETUP-OK` cannot satisfy `READY <restore_id>`.
fn guest_setup(
    dir: &Path,
    net: Option<&crate::net::NetSpec>,
    deadline: Instant,
) -> std::result::Result<(), SetupError> {
    let Ok(nonce) = std::fs::read_to_string(dir.join("snapshot-worker-nonce")) else {
        return Err(SetupError::Unsupported);
    };
    let frame = guest_setup_frame(&nonce, SystemTime::now(), net).map_err(SetupError::Failed)?;
    let Ok(mut transport) = ReadyTransport::guest(dir, deadline) else {
        return Err(SetupError::Unsupported);
    };
    transport
        .write(frame.as_bytes())
        .map_err(SetupError::Failed)?;
    match transport.line().map_err(SetupError::Failed)? {
        "SETUP-OK" => Ok(()),
        "FAILED setup" => Err(SetupError::Failed(Error::Internal(
            "restored guest setup failed".into(),
        ))),
        // Older helpers reject the unknown action without applying anything.
        _ => Err(SetupError::Unsupported),
    }
}

fn ssh_guest_setup(dir: &Path, vsock: &Path, net: Option<&crate::net::NetSpec>) -> Result<()> {
    let mut reconfigure = format!("set -eu; date -u -s @{}; ", now_secs());
    if let Some(spec) = net {
        reconfigure.push_str(&format!("ip link set dev eth0 down; ip addr flush dev eth0; ip link set dev eth0 address {}; ip link set dev eth0 up; ip addr add {} dev eth0; ip route replace default via {} dev eth0; ip neigh flush dev eth0", spec.mac, spec.guest_cidr, spec.gateway));
    }
    let command = ["sh".to_owned(), "-c".to_owned(), reconfigure];
    let helper = shinu_core::vsock_helper()?;
    let ssh = ssh_command(
        &helper,
        vsock,
        &key_path(dir),
        shinu_core::VSOCK_SSH_PORT,
        &command,
    );
    match run_process_group(ssh, Duration::from_secs(30), None) {
        Some(status) if status.success() => Ok(()),
        _ => Err(Error::Internal(
            "restored guest setup failed or timed out".into(),
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootIdentity {
    pid: u32,
    starttime: u64,
    host_boot_id: Uuid,
}

fn boot_identity(dir: &Path) -> Result<BootIdentity> {
    let pid = running_pid(dir)
        .ok_or_else(|| Error::Internal("readiness VM identity unavailable".into()))?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let starttime = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::Internal("readiness VM starttime unavailable".into()))?;
    let host_boot_id =
        Uuid::parse_str(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim())
            .map_err(|_| Error::Internal("readiness host boot identity unavailable".into()))?;
    if running_pid(dir) != Some(pid) {
        return Err(Error::Internal("readiness VM generation changed".into()));
    }
    Ok(BootIdentity {
        pid,
        starttime,
        host_boot_id,
    })
}

#[derive(Clone)]
struct ReadyReceipt {
    boot: BootIdentity,
    policy: ReadySpec,
}

static READY_RECEIPTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, ReadyReceipt>>,
> = std::sync::LazyLock::new(std::sync::Mutex::default);

fn forget_readiness(dir: &Path) {
    READY_RECEIPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(dir);
}

fn admit_application(
    dir: &Path,
    spec: &ReadySpec,
    boot: &BootIdentity,
    network_ready: &mut impl FnMut(Instant) -> Result<()>,
) -> Result<()> {
    {
        let mut receipts = READY_RECEIPTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if receipts
            .get(dir)
            .is_some_and(|receipt| receipt.boot == *boot && receipt.policy == *spec)
        {
            return Ok(());
        }
        receipts.remove(dir);
    }
    application_ready(dir, spec, boot, network_ready)?;
    if boot_identity(dir)? != *boot {
        return Err(Error::Internal(
            "readiness VM generation changed before admission".into(),
        ));
    }
    READY_RECEIPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            dir.to_owned(),
            ReadyReceipt {
                boot: *boot,
                policy: spec.clone(),
            },
        );
    Ok(())
}

fn cleanup_boot(dir: &Path, cfg: &NetConfig, expected: &BootIdentity) -> Result<()> {
    forget_readiness(dir);
    if running_pid(dir).is_none()
        || boot_identity(dir)
            .as_ref()
            .is_ok_and(|actual| actual == expected)
    {
        stop(dir, cfg)?;
        return Ok(());
    }
    Err(Error::Internal(
        "refusing cleanup of a different or unverified VM generation".into(),
    ))
}

fn application_ready(
    dir: &Path,
    spec: &ReadySpec,
    boot: &BootIdentity,
    network_ready: &mut impl FnMut(Instant) -> Result<()>,
) -> Result<()> {
    let restore_id = Uuid::new_v4();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(spec.timeout_seconds);
    let vm_id = dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| Uuid::parse_str(name).ok())
        .map_or_else(|| "unknown".into(), |id| id.to_string());
    eprintln!(
        "event=guest_readiness vm_id={vm_id} restore_id={restore_id} stage=requested elapsed_ms=0"
    );
    // Sanitized per-substep timing, same level as `restore_step`; only names,
    // durations and outcomes, never guest output or the policy argv.
    let substep = |step: &str, started: Instant, ok: bool| {
        eprintln!(
            "event=restore_substep vm_id={vm_id} restore_id={restore_id} step={step} elapsed_ms={} ok={ok}",
            started.elapsed().as_millis()
        );
    };
    let result = (|| {
        spec.validate()?;
        let begun = Instant::now();
        let networked = network_ready(deadline);
        substep("NetworkReady", begun, networked.is_ok());
        networked?;
        if Instant::now() >= deadline {
            return Err(Error::Internal("readiness admission timeout".into()));
        }
        let begun = Instant::now();
        let capable = ready_capability(dir, deadline);
        substep("HelperCapability", begun, capable.is_ok());
        if capable.is_err() {
            let begun = Instant::now();
            let installed = install_snapshot_worker(dir, Some(deadline))
                .and_then(|()| ready_capability(dir, deadline));
            substep("HelperInstall", begun, installed.is_ok());
            installed?;
        }
        let nonce = std::fs::read_to_string(dir.join("snapshot-worker-nonce"))?;
        if nonce.len() != 36 || Uuid::parse_str(&nonce).is_err() {
            return Err(Error::Internal(
                "invalid readiness authentication identity".into(),
            ));
        }
        let begun = Instant::now();
        let transport = ReadyTransport::guest(dir, deadline);
        substep("HelperConnect", begun, transport.is_ok());
        let mut transport = transport?;
        let frame = format!(
            "ready {nonce} {restore_id} {}\n",
            serde_json::to_string(spec)?
        );
        if frame.len() > 65536 {
            return Err(Error::Invalid("oversized readiness request".into()));
        }
        let begun = Instant::now();
        let sent = transport.write(frame.as_bytes());
        substep("ReadyRequestSent", begun, sent.is_ok());
        sent?;
        // From the request leaving the host to the guest's reply line: the
        // guest command's own run time plus vsock delivery.
        let begun = Instant::now();
        let replied = transport
            .line()
            .map(|line| line == format!("READY {restore_id}"));
        substep("ReadyReply", begun, matches!(replied, Ok(true)));
        if !replied? {
            return Err(Error::Internal(
                "guest readiness failed or restore identity mismatched".into(),
            ));
        }
        if boot_identity(dir)? != *boot {
            return Err(Error::Internal(
                "readiness VM generation changed before READY".into(),
            ));
        }
        Ok(())
    })();
    let stage = if result.is_ok() { "ready" } else { "failed" };
    let code = if result.is_ok() {
        "accepted"
    } else {
        "transaction_failed"
    };
    eprintln!(
        "event=guest_readiness vm_id={vm_id} restore_id={restore_id} stage={stage} elapsed_ms={} code={code}",
        started.elapsed().as_millis()
    );
    result
}

enum SnapshotCommand<'a> {
    Status,
    Rotate(&'a str),
    Freeze,
    Thaw,
    Hold,
}

struct SnapshotConnection {
    stream: std::os::unix::net::UnixStream,
    nonce: String,
}

impl SnapshotConnection {
    // None identifies a legacy/unavailable worker, not a successful thaw.
    fn connect(dir: &Path) -> Option<Result<Self>> {
        let nonce = std::fs::read_to_string(dir.join("snapshot-worker-nonce")).ok()?;
        if Uuid::parse_str(&nonce).is_err() || nonce.len() != 36 {
            return Some(Err(Error::Internal("invalid snapshot worker nonce".into())));
        }
        let mut stream = std::os::unix::net::UnixStream::connect(vsock_path(dir)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .ok()?;
        stream.write_all(b"CONNECT 2224\n").ok()?;
        let mut buffer = [0u8; 64];
        if !snapshot_line(&mut stream, &mut buffer)
            .ok()?
            .starts_with(b"OK ")
        {
            return None;
        }
        if snapshot_line(&mut stream, &mut buffer).ok()? != b"SHINU-SNAPSHOT-1" {
            return Some(Err(Error::Internal("unknown guest snapshot worker".into())));
        }
        Some(Ok(Self { stream, nonce }))
    }

    fn request(&mut self, dir: &Path, command: SnapshotCommand<'_>) -> Result<()> {
        let (action, argument) = match command {
            SnapshotCommand::Status => ("status", None),
            SnapshotCommand::Rotate(next) => {
                // Persist before sending: losing the acknowledgement must not
                // strand cleanup or the next capture with the obsolete nonce.
                store_snapshot_nonce(dir, next)?;
                ("status", Some(next))
            }
            SnapshotCommand::Freeze => ("freeze", None),
            SnapshotCommand::Thaw => ("thaw", None),
            SnapshotCommand::Hold => ("status", Some("hold")),
        };
        self.stream
            .set_read_timeout(Some(Duration::from_secs(250)))?;
        self.stream.write_all(action.as_bytes())?;
        self.stream.write_all(b" ")?;
        self.stream.write_all(self.nonce.as_bytes())?;
        if let Some(argument) = argument {
            self.stream.write_all(b" ")?;
            self.stream.write_all(argument.as_bytes())?;
        }
        self.stream.write_all(b"\n")?;
        let mut buffer = [0u8; 256];
        let reply = snapshot_line(&mut self.stream, &mut buffer)?;
        if reply != b"OK" {
            return Err(Error::Internal(format!(
                "guest snapshot {action} failed: {}",
                String::from_utf8_lossy(reply)
            )));
        }
        Ok(())
    }
}

fn guest_snapshot_action(dir: &Path, command: SnapshotCommand<'_>) -> Option<Result<()>> {
    Some(
        SnapshotConnection::connect(dir)?
            .and_then(|mut connection| connection.request(dir, command)),
    )
}

fn snapshot_preconnect_enabled() -> Result<bool> {
    let invalid = || Error::Invalid("SHINU_SNAPSHOT_PRECONNECT must be 0/false or 1/true".into());
    match std::env::var("SHINU_SNAPSHOT_PRECONNECT") {
        Ok(value) if value.trim() == "0" || value.trim().eq_ignore_ascii_case("false") => Ok(false),
        Ok(value) if value.trim() == "1" || value.trim().eq_ignore_ascii_case("true") => Ok(true),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(invalid()),
    }
}

fn prepare_snapshot_worker(dir: &Path) -> Result<()> {
    // Capture time is where a helper predating `setup` is replaced, so that
    // generations restored later can skip the SSH setup session.
    if matches!(
        guest_snapshot_action(dir, SnapshotCommand::Status),
        Some(Ok(()))
    ) && setup_capability(dir, Instant::now() + Duration::from_secs(2))
    {
        return Ok(());
    }
    install_snapshot_worker(dir, None)
}

fn setup_capability(dir: &Path, deadline: Instant) -> bool {
    let Ok(nonce) = std::fs::read_to_string(dir.join("snapshot-worker-nonce")) else {
        return false;
    };
    ReadyTransport::guest(dir, deadline)
        .and_then(|mut transport| {
            transport.write(format!("capabilities {nonce} setup\n").as_bytes())?;
            Ok(transport.line()? == "SETUP-1")
        })
        .unwrap_or(false)
}

fn install_snapshot_worker(dir: &Path, deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(Error::Internal("readiness helper upgrade timeout".into()));
    }
    let agent = shinu_core::vsock_helper()?.with_file_name("shinu-snapshot-agent");
    validate_vm_asset(&agent, "guest snapshot helper")?;
    let nonce = Uuid::new_v4().to_string();
    let mut script = String::from(
        "set -eu; [ \"$(findmnt -n -o FSTYPE --target /run)\" = tmpfs ]; mkdir -p -m 700 /run/shinu-snapshot; ",
    );
    // Replace only after thaw, under the same guest flock as capture/thaw.
    // Old helpers own port 2224: TERM the exact executable owner and prove it
    // has exited before changing its nonce or launching the replacement.
    script.push_str("phase=$(cat /run/shinu-snapshot/phase 2>/dev/null || printf thawed); case $phase in thawed|ready) ;; *) exit 1;; esac; for proc in /proc/[0-9]*; do exe=$(readlink \"$proc/exe\" 2>/dev/null || :); case $exe in /run/shinu-snapshot/agent|'/run/shinu-snapshot/agent (deleted)') pid=${proc##*/}; kill -TERM \"$pid\"; while [ \"$(readlink \"$proc/exe\" 2>/dev/null || :)\" = \"$exe\" ]; do sleep 0.02; done;; esac; done; ");
    script.push_str("IFS= read -r nonce; [ \"${#nonce}\" = 36 ]; printf %s \"$nonce\" > /run/shinu-snapshot/nonce; unset nonce; printf thawed > /run/shinu-snapshot/phase; ");
    for (name, body) in [
        ("freeze", include_str!("freeze.sh")),
        ("thaw", include_str!("thaw.sh")),
    ] {
        script.push_str(&format!(
            "printf %s {} > /run/shinu-snapshot/{name}.sh; chmod 700 /run/shinu-snapshot/{name}.sh; ",
            shinu_core::shell_quote_word(body)
        ));
    }
    script.push_str("cat > /run/shinu-snapshot/agent.next; chmod 700 /run/shinu-snapshot/agent.next; mv /run/shinu-snapshot/agent.next /run/shinu-snapshot/agent; nohup /run/shinu-snapshot/agent </dev/null >/dev/null 2>&1 &");
    guest_snapshot_script(
        dir,
        &script,
        Some((nonce.clone(), std::fs::File::open(agent)?)),
        deadline,
    )?;
    store_snapshot_nonce(dir, &nonce)?;
    for _ in 0..20 {
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                return Err(Error::Internal("readiness helper upgrade timeout".into()));
            }
            if ready_capability(dir, deadline).is_ok() {
                return Ok(());
            }
        } else if let Some(result) = guest_snapshot_action(dir, SnapshotCommand::Status) {
            return result;
        }
        std::thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
    }
    Err(Error::Internal(
        "guest snapshot worker did not start".into(),
    ))
}

fn store_snapshot_nonce(dir: &Path, nonce: &str) -> Result<()> {
    if Uuid::parse_str(nonce).is_err() || nonce.len() != 36 {
        return Err(Error::Invalid("invalid snapshot worker nonce".into()));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(dir.join("snapshot-worker-nonce"))?;
    file.write_all(nonce.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn guest_snapshot_script(
    dir: &Path,
    script: &str,
    payload: Option<(String, std::fs::File)>,
    deadline: Option<Instant>,
) -> Result<()> {
    let helper = shinu_core::vsock_helper()?;
    // The guest deadline terminates the remote script too; killing only SSH
    // would allow a late fsfreeze to race the host's thaw attempt.
    // Setup must not leak the flock into its detached resident process. Thaw
    // retains it across nested hook groups, even if a timeout kills the shell.
    let flock_mode = if payload.is_some() { "-o" } else { "-F" };
    let timeout = deadline.map_or(Duration::from_secs(250), |deadline| {
        deadline.saturating_duration_since(Instant::now())
    });
    if timeout.is_zero() {
        return Err(Error::Internal("guest setup deadline exceeded".into()));
    }
    let seconds = |cap| {
        let millis = timeout.min(Duration::from_secs(cap)).as_millis().max(1);
        format!("{}.{:03}", millis / 1000, millis % 1000)
    };
    let command = [
        "timeout".to_owned(),
        "-k".to_owned(),
        "5".to_owned(),
        seconds(240),
        "flock".to_owned(),
        flock_mode.to_owned(),
        "-w".to_owned(),
        seconds(115),
        "/run/shinu-snapshot.lock".to_owned(),
        "timeout".to_owned(),
        "--foreground".to_owned(),
        "-k".to_owned(),
        "5".to_owned(),
        seconds(110),
        "sh".to_owned(),
        "-c".to_owned(),
        script.to_owned(),
    ];
    let ssh = ssh_command(
        &helper,
        &vsock_path(dir),
        &key_path(dir),
        shinu_core::VSOCK_SSH_PORT,
        &command,
    );
    match run_process_group(ssh, timeout, payload) {
        Some(status) if status.success() => Ok(()),
        status => Err(Error::Internal(format!(
            "guest snapshot freeze/thaw failed or timed out: {status:?}"
        ))),
    }
}

/// Thaws a restored generation before exposing it to callers. The captured
/// ledger makes this idempotent, including after partially completed cleanup.
pub fn thaw_snapshot(dir: &Path) -> Result<()> {
    let thaw = || match guest_snapshot_action(dir, SnapshotCommand::Thaw) {
        Some(Ok(())) => Ok(()),
        Some(Err(_)) | None => {
            // Banner readiness is advisory for cleanup: even when it fails,
            // execute the bounded SSH thaw rather than skipping the attempt.
            let _ = wait_ready(dir, &vsock_path(dir));
            guest_snapshot_script(dir, include_str!("thaw.sh"), None, None)
        }
    };
    let first = thaw();
    match first {
        Ok(()) => Ok(()),
        Err(first) => {
            thaw().map_err(|retry| Error::Internal(format!("{first}; thaw retry failed: {retry}")))
        }
    }
}

/// Application-consistent capture: freeze, pause, drain/capture, cut disk,
/// resume, thaw. The disk cut runs while paused and only after snapshot/create.
/// Disk-only hot commits use the same transaction without creating RAM state.
pub fn snapshot(
    dir: &Path,
    kind: Option<SnapshotKind>,
    disk_cut: impl FnOnce() -> Result<()>,
) -> Result<SnapshotCapture> {
    let preconnect = snapshot_preconnect_enabled()?;
    let mut thaw_connection = None;
    let version = api(dir, "GET", "/version", None)
        .ok_or_else(|| Error::Internal("cannot identify running Firecracker build".into()))?;
    let version: serde_json::Value = serde_json::from_str(&version)?;
    if version["firecracker_version"].as_str()
        != Some(shinu_core::FC_VERSION.trim_start_matches('v'))
    {
        return Err(Error::Invalid(format!(
            "running Firecracker is {}, expected {}; cold restart this Space before capturing",
            version["firecracker_version"],
            shinu_core::FC_VERSION
        )));
    }
    release(dir);
    let mut disk_cut = Some(disk_cut);
    let mut capture = snapshot_transaction(kind.is_some(), |step| match step {
        SnapshotStep::Freeze => {
            prepare_snapshot_worker(dir)?;
            let nonce = Uuid::new_v4().to_string();
            guest_snapshot_action(dir, SnapshotCommand::Rotate(&nonce))
                .ok_or_else(|| Error::Internal("guest snapshot worker disappeared".into()))??;
            guest_snapshot_action(dir, SnapshotCommand::Freeze)
                .ok_or_else(|| Error::Internal("guest snapshot worker disappeared".into()))??;
            if preconnect {
                let mut connection = SnapshotConnection::connect(dir)
                    .ok_or_else(|| Error::Internal("guest snapshot worker disappeared".into()))??;
                connection.request(dir, SnapshotCommand::Hold)?;
                thaw_connection = Some(connection);
            }
            Ok(())
        }
        SnapshotStep::Thaw => {
            if let Some(mut connection) = thaw_connection.take() {
                let result = connection.request(dir, SnapshotCommand::Thaw);
                // Release a broken held connection before attempting a new one.
                drop(connection);
                if result.is_ok() {
                    return result;
                }
            }
            thaw_snapshot(dir)
        }
        SnapshotStep::Cut => {
            if kind.is_none() {
                // Sync IO has no outstanding requests once paused. Disk-only
                // captures do not call snapshot/create, so flush this inode
                // explicitly and fail the same transaction on storage errors.
                std::fs::File::open(jail_path(dir, JAIL_ROOTFS))?.sync_all()?;
            }
            disk_cut
                .take()
                .ok_or_else(|| Error::Internal("snapshot disk cut already consumed".into()))?(
            )
        }
        SnapshotStep::Pause | SnapshotStep::Resume => {
            let state = if step == SnapshotStep::Pause {
                "Paused"
            } else {
                "Resumed"
            };
            for _ in 0..3 {
                if api(
                    dir,
                    "PATCH",
                    "/vm",
                    Some(&format!("{{\"state\":\"{state}\"}}")),
                )
                .is_some()
                {
                    return Ok(());
                }
                if step == SnapshotStep::Pause {
                    break;
                }
                // A lost resume response is not evidence that vCPUs are paused.
                if let Some(info) = api(dir, "GET", "/", None)
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                    && info["state"] == "Running"
                {
                    return Ok(());
                }
            }
            Err(Error::Internal(format!(
                "failed snapshot VM transition: {state}"
            )))
        }
        SnapshotStep::Create => {
            let kind = kind.ok_or_else(|| Error::Internal("snapshot kind missing".into()))?;
            let body = serde_json::json!({
                "snapshot_type": kind.firecracker_name(),
                "snapshot_path": JAIL_SNAP_STATE,
                "mem_file_path": JAIL_SNAP_MEM,
            })
            .to_string();
            api_with_timeout(
                dir,
                "PUT",
                "/snapshot/create",
                Some(&body),
                SNAPSHOT_TIMEOUT_SECS,
            )
            .ok_or_else(|| Error::Internal("failed to create VM snapshot".to_owned()))?;
            Ok(())
        }
    })?;
    capture.memory = kind.map(|_| {
        (
            jail_path(dir, JAIL_SNAP_MEM),
            jail_path(dir, JAIL_SNAP_STATE),
        )
    });
    capture.guest_snapshot_nonce =
        Some(std::fs::read_to_string(dir.join("snapshot-worker-nonce"))?);
    Ok(capture)
}

/// Builds a loadable memory image from a full base and a Firecracker diff.
/// Reflinking keeps untouched pages shared with the base; only allocated diff
/// extents are copied over it. Holes must not be copied as zeroes, while
/// zero-filled dirty extents must not be skipped.
pub fn merge_snapshot_memory(base: &Path, diff: &Path, merged: &Path) -> Result<()> {
    if merged.exists() {
        std::fs::remove_file(merged)?;
    }
    shinu_core::btrfs::reflink(base, merged)?;
    let source = std::fs::File::open(diff)?;
    let size = source.metadata()?.len();
    // A dirty diff page filled with zeroes is still an allocated data extent.
    let target = std::fs::OpenOptions::new().write(true).open(merged)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let buffer_len = u64::try_from(buffer.len()).map_err(|error| {
        Error::Internal(format!(
            "snapshot merge buffer length does not fit u64: {error}"
        ))
    })?;
    for extent in data_extents(&source, size) {
        let extent = extent?;
        let offset = extent.start;
        let length = extent.end - offset;
        let mut copied = 0u64;
        while copied < length {
            let chunk =
                usize::try_from(std::cmp::min(buffer_len, length - copied)).map_err(|error| {
                    Error::Internal(format!(
                        "snapshot merge chunk length does not fit usize: {error}"
                    ))
                })?;
            let at = offset + copied;
            std::os::unix::fs::FileExt::read_exact_at(&source, &mut buffer[..chunk], at)?;
            std::os::unix::fs::FileExt::write_all_at(&target, &buffer[..chunk], at)?;
            copied += chunk as u64;
        }
    }
    target.sync_all()?;
    Ok(())
}

fn signal(pid: u32, sig: &str) -> bool {
    std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Total budget of one SSH readiness wait (the former 600 × 50 ms polls).
const READY_WAIT: Duration = Duration::from_secs(30);
/// Longest wait for the banner on a connection the guest already accepted.
const PROBE_BANNER_WAIT: Duration = Duration::from_secs(10);

/// True once the guest's sshd is ready to serve on `port`.
///
/// A successful vsock CONNECT only proves that the bridge accepts a socket.
/// Requiring the SSH identification line makes readiness match the service
/// that execution actually uses.
fn probe(uds: &Path, port: u16, deadline: Instant) -> bool {
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
    // Read one byte at a time so the handshake read cannot consume the SSH banner.
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
    // The guest accepted: sshd is being forked for this very connection, so
    // wait for its banner instead of dropping it and forking another.
    let banner_wait = deadline
        .saturating_duration_since(Instant::now())
        .min(PROBE_BANNER_WAIT);
    if banner_wait.is_zero() || stream.set_read_timeout(Some(banner_wait)).is_err() {
        return false;
    }
    line(&mut stream).is_some_and(|banner| banner.starts_with(b"SSH-"))
}
fn link_resource(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        std::fs::remove_file(dst)?;
    }
    // Hardlinks preserve zero-copy CoW accounting; copying the image would
    // consume its full size and violate the jail layout invariant.
    std::fs::hard_link(src, dst).map_err(|error| {
        Error::Internal(format!(
            "hard-link {} -> {} failed (cross-device links are not supported): {error}",
            src.display(),
            dst.display()
        ))
    })?;
    Ok(())
}

/// Full memory forks retain the checkpoint inode; unlinking any one name is safe.
pub fn link_checkpoint_memory(source: &Path, destination: &Path) -> Result<()> {
    if std::fs::metadata(source)?.mode() & 0o777 != 0o440 {
        std::fs::set_permissions(source, std::fs::Permissions::from_mode(0o440))?;
    }
    std::fs::hard_link(source, destination)?;
    Ok(())
}

/// Read immutable memory in a persistent, dedicated page-cache charging cgroup.
pub fn warm_checkpoint_memory(memory: &Path) -> Result<()> {
    let group = Path::new("/sys/fs/cgroup/shinu-ckpt-cache");
    std::fs::create_dir_all(group)?;
    let executable = format!("/proc/{}/exe", std::process::id());
    let output = std::process::Command::new("sh")
        .args([
            "-eu",
            "-c",
            "printf '%s\n' \"$$\" > \"$1/cgroup.procs\"; exec \"$2\" --warm-memory-file \"$3\"",
            "shinu-ckpt-warm",
        ])
        .arg(group)
        .arg(executable)
        .arg(memory)
        .output()?;
    if !output.status.success() {
        return Err(Error::Internal(format!(
            "checkpoint cache warming failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Remote-read stride. Each read fault maps the cached pages of its aligned
/// window (Linux `fault_around_bytes`, 64 KiB by default); pages a coarser
/// stride leaves unmapped simply fault on first guest touch as before.
const PREFAULT_STRIDE: u64 = 64 * 1024;
/// Linux `UIO_MAXIOV`: remote iovecs accepted by one `process_vm_readv`.
const PREFAULT_BATCH: usize = 1024;

/// One private mapping of the snapshot file and its file offset.
#[derive(Debug, PartialEq, Eq)]
struct MemoryRange {
    start: u64,
    end: u64,
    offset: u64,
}

/// Guest RAM of a loaded VM: Firecracker's private mappings of the jailed
/// snapshot file, which is unlinked from the jail right after load.
fn snapshot_memory_ranges(maps: &str) -> Vec<MemoryRange> {
    let target = format!("/{JAIL_SNAP_MEM}");
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let private = fields.next()?.ends_with('p');
            let offset = fields.next()?;
            let path = fields.nth(2)?;
            let tail: Vec<&str> = fields.collect();
            (private && path == target && matches!(tail.as_slice(), [] | ["(deleted)"]))
                .then_some(())?;
            Some(MemoryRange {
                start: u64::from_str_radix(start, 16).ok()?,
                end: u64::from_str_radix(end, 16).ok()?,
                offset: u64::from_str_radix(offset, 16).ok()?,
            })
        })
        .filter(|range| range.start < range.end)
        .collect()
}

/// Page-cache residency of `file`, one byte per page (bit 0 = resident).
/// Mapping the file without touching it reads nothing from disk.
fn resident_pages(file: &std::fs::File, page: u64) -> Result<Vec<u8>> {
    unsafe extern "C" {
        fn mmap(
            address: usize,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> usize;
        fn munmap(address: usize, length: usize) -> i32;
        fn mincore(address: usize, length: usize, vector: *mut u8) -> i32;
    }
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| Error::Internal("snapshot memory too large".into()))?;
    if length == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: a fresh PROT_READ, MAP_SHARED mapping of a live descriptor.
    let address = unsafe { mmap(0, length, 1, 1, file.as_raw_fd(), 0) };
    if address == usize::MAX {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut vector = vec![0_u8; length.div_ceil(usize::try_from(page).unwrap_or(4096))];
    // SAFETY: `vector` holds one byte per page of the live mapping above.
    let result = unsafe { mincore(address, length, vector.as_mut_ptr()) };
    let error = (result != 0).then(std::io::Error::last_os_error);
    // SAFETY: unmaps exactly the mapping created above.
    unsafe { munmap(address, length) };
    error.map_or(Ok(vector), |error| Err(error.into()))
}

/// One remote address per stride window that already has a cached page: the
/// read faults on that page and fault-around maps the window's other cached
/// pages. Windows not resident when sampled are skipped (best effort: a page
/// evicted after sampling is still read back), so cost stays bounded when the
/// checkpoint cache was evicted.
fn prefault_targets(ranges: &[MemoryRange], resident: &[u8], page: u64) -> Vec<u64> {
    let mut targets = Vec::new();
    for range in ranges {
        let mut window = range.start;
        while window < range.end {
            let limit = window.saturating_add(PREFAULT_STRIDE).min(range.end);
            let mut address = window;
            while address < limit {
                let index = (range.offset + (address - range.start)) / page;
                if usize::try_from(index)
                    .ok()
                    .and_then(|index| resident.get(index))
                    .is_some_and(|state| state & 1 != 0)
                {
                    targets.push(address);
                    break;
                }
                address += page;
            }
            window = limit;
        }
    }
    targets
}

/// Maps already-cached snapshot pages into `pid`'s private file mappings by
/// reading one byte at each target through `process_vm_readv`. Remote reads
/// fault without `FOLL_WRITE`, so they install read-only page-cache PTEs and
/// never copy-on-write or allocate anonymous memory; guest writes still do.
fn populate_read(pid: u32, targets: &[u64]) -> Result<()> {
    #[repr(C)]
    struct IoVec {
        base: usize,
        len: usize,
    }
    unsafe extern "C" {
        fn process_vm_readv(
            pid: i32,
            local: *const IoVec,
            local_count: u64,
            remote: *const IoVec,
            remote_count: u64,
            flags: u64,
        ) -> isize;
    }
    let pid = i32::try_from(pid).map_err(|_| Error::Internal("invalid VMM pid".into()))?;
    let mut sink = [0_u8; PREFAULT_BATCH];
    let mut remote = Vec::with_capacity(PREFAULT_BATCH);
    for batch in targets.chunks(PREFAULT_BATCH) {
        remote.clear();
        for &address in batch {
            remote.push(IoVec {
                base: usize::try_from(address)
                    .map_err(|_| Error::Internal("invalid VMM address".into()))?,
                len: 1,
            });
        }
        let local = IoVec {
            base: sink.as_mut_ptr() as usize,
            len: remote.len(),
        };
        // SAFETY: one live local buffer of `local.len` bytes and a live
        // array of remote descriptors; the kernel only writes `sink`.
        let read = unsafe {
            process_vm_readv(
                pid,
                &raw const local,
                1,
                remote.as_ptr(),
                remote.len() as u64,
                0,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if read.cast_unsigned() != remote.len() {
            return Err(Error::Internal(format!(
                "prefault stopped after {read} of {} pages",
                remote.len()
            )));
        }
    }
    Ok(())
}

fn page_size() -> u64 {
    unsafe extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    // SAFETY: _SC_PAGESIZE (30) takes no pointers.
    u64::try_from(unsafe { sysconf(30) }).unwrap_or(4096)
}

/// Best-effort fill-time prefault of a loaded, paused VM. Failure is only
/// logged: the VM stays correct and merely faults pages on first touch.
fn prefault_loaded(dir: &Path, id: Uuid, memory: &Path) {
    let started = Instant::now();
    let result = (|| -> Result<(u64, u64)> {
        let pid =
            running_pid(dir).ok_or_else(|| Error::Internal("loaded VMM is not running".into()))?;
        let ranges = snapshot_memory_ranges(&std::fs::read_to_string(format!("/proc/{pid}/maps"))?);
        // An all-hole image can legitimately have no file-backed mappings.
        if ranges.is_empty() {
            return Ok((0, 0));
        }
        let page = page_size();
        let file = std::fs::File::open(memory)?;
        let mut resident = resident_pages(&file, page)?;
        mask_hole_residency(&file, page, &mut resident)?;
        let targets = prefault_targets(&ranges, &resident, page);
        populate_read(pid, &targets)?;
        let mapped: u64 = ranges.iter().map(|range| range.end - range.start).sum();
        Ok((mapped, targets.len() as u64 * PREFAULT_STRIDE))
    })();
    let elapsed_ms = started.elapsed().as_millis();
    match result {
        Ok((mapped, cached)) => eprintln!(
            "event=prefault vm_id={id} mapped_mib={} cached_windows_mib={} elapsed_ms={elapsed_ms} ok=true",
            mapped >> 20,
            cached >> 20
        ),
        Err(error) => {
            eprintln!("event=prefault vm_id={id} elapsed_ms={elapsed_ms} ok=false error={error}");
        }
    }
}

fn mask_hole_residency(file: &std::fs::File, page: u64, resident: &mut [u8]) -> Result<()> {
    let mut previous_end = 0;
    for extent in data_extents(file, file.metadata()?.len()) {
        let extent = extent?;
        let start = usize::try_from(extent.start / page)
            .unwrap_or(resident.len())
            .min(resident.len());
        resident[previous_end..start.max(previous_end)].fill(0);
        previous_end = usize::try_from(extent.end.div_ceil(page))
            .unwrap_or(resident.len())
            .min(resident.len());
    }
    resident[previous_end..].fill(0);
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
    wait_ready_observed(dir, vsock, |_, _, _| {})
}

/// `wait_ready` reporting each SSH banner probe (1-based attempt, duration,
/// success); every probe makes the guest fork socat and sshd work. Only a
/// failed connection (no socket yet, CONNECT refused, EOF) is retried, every
/// 50 ms; an accepted one waits for its banner. All within `READY_WAIT`.
fn wait_ready_observed(
    dir: &Path,
    vsock: &Path,
    mut probed: impl FnMut(usize, Duration, bool),
) -> bool {
    let deadline = Instant::now() + READY_WAIT;
    let mut attempt = 0;
    while Instant::now() < deadline {
        if vsock.exists() {
            attempt += 1;
            let started = Instant::now();
            let ready = probe(vsock, shinu_core::VSOCK_SSH_PORT, deadline);
            probed(attempt, started.elapsed(), ready);
            if ready {
                return true;
            }
        }
        if !is_running(dir) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Per-Space boot choices. Absent CPU/memory inherit the daemon defaults;
/// readiness is always evaluated against the actual running VM generation.
#[derive(Clone, Copy)]
pub struct StartOptions<'a> {
    pub vcpus: Option<u32>,
    pub mem_mib: Option<u32>,
    pub restore: Option<&'a RestoreFiles<'a>>,
    pub readiness: Option<&'a ReadySpec>,
    pub load_only: bool,
    pub track_dirty: bool,
}

impl Default for StartOptions<'_> {
    fn default() -> Self {
        Self {
            vcpus: None,
            mem_mib: None,
            restore: None,
            readiness: None,
            load_only: false,
            track_dirty: true,
        }
    }
}

/// Lifecycle ledger I/O. Unit tests journal each step so the order of the
/// crash-consistency barriers is asserted, not just the final file contents.
#[cfg(test)]
mod ledger_journal {
    use std::cell::RefCell;

    thread_local! {
        static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(event: String) {
        EVENTS.with(|events| events.borrow_mut().push(event));
    }

    pub(super) fn take() -> Vec<String> {
        EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
    }
}

const PHASE_RECORD: &str = "loaded.json";

fn host_boot_id() -> Result<Uuid> {
    Uuid::parse_str(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim())
        .map_err(|_| Error::Internal("host boot identity unavailable".into()))
}

/// Records the space's lifecycle phase together with the current host boot.
///
/// Deliberately no fsync, on the handout path or anywhere else. The contract
/// is that memory whose vCPUs may have run is never restored again. A daemon
/// crash keeps the page cache, so the restarted daemon always sees this
/// rename. A host crash changes the boot id, so any record that survives it,
/// at whatever version reached the disk, names the old boot and is consumed;
/// a missing record is consumed too. Durability therefore only decides what a
/// crash leaves behind, and nothing a host crash leaves behind is ever reused.
fn write_phase(dir: &Path, phase: &str) -> Result<()> {
    let boot_id = host_boot_id()?;
    let temporary = dir.join("loaded.json.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    write!(file, "{{\"phase\":\"{phase}\",\"boot_id\":\"{boot_id}\"}}")?;
    drop(file);
    std::fs::rename(temporary, dir.join(PHASE_RECORD))?;
    #[cfg(test)]
    ledger_journal::record(format!("rename {phase}"));
    Ok(())
}

enum PhaseRecord {
    Missing,
    Invalid,
    Present {
        phase: &'static str,
        boot_id: Option<Uuid>,
    },
}

fn read_phase(dir: &Path) -> Result<PhaseRecord> {
    let bytes = match std::fs::read(dir.join(PHASE_RECORD)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PhaseRecord::Missing);
        }
        Err(error) => return Err(error.into()),
    };
    let Ok(serde_json::Value::Object(record)) = serde_json::from_slice(&bytes) else {
        return Ok(PhaseRecord::Invalid);
    };
    let phase = match record.get("phase").and_then(serde_json::Value::as_str) {
        Some("pending") => "pending",
        Some("loading") => "loading",
        Some("loaded") => "loaded",
        Some("resuming") => "resuming",
        _ => return Ok(PhaseRecord::Invalid),
    };
    let boot_id = record
        .get("boot_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    Ok(PhaseRecord::Present { phase, boot_id })
}

/// Records that a fork or checkout materialized never-run pending Full
/// memory/state for this stopped space.
pub fn mark_pending(dir: &Path) -> Result<()> {
    write_phase(dir, "pending")
}

/// Settles pending Full memory/state once no VMM runs for the space.
///
/// Only a `pending`, `loading` or `loaded` record written in the current host
/// boot proves the vCPUs never ran; the files are then kept, recorded as
/// `pending`. Anything else (`resuming`, another boot, a missing, invalid or
/// pre-upgrade record) consumes them and logs why.
pub fn settle_pending(dir: &Path) -> Result<()> {
    let reason = match read_phase(dir)? {
        PhaseRecord::Present {
            phase: "pending" | "loading" | "loaded",
            boot_id,
        } => (boot_id.is_none() || boot_id != host_boot_id().ok()).then_some("boot_mismatch"),
        PhaseRecord::Present { .. } => Some("resuming"),
        PhaseRecord::Invalid => Some("invalid"),
        PhaseRecord::Missing => Some("missing"),
    };
    let id = dir_id(dir)?;
    let root = dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Error::Internal("invalid VM directory".into()))?;
    let image = shinu_core::space_image(root, id);
    let files = [image.with_extension("mem"), image.with_extension("state")];
    let pending = files
        .iter()
        .any(|path| std::fs::symlink_metadata(path).is_ok());
    if pending && reason.is_none() {
        return write_phase(dir, "pending");
    }
    if let Some(reason) = reason.filter(|_| pending) {
        for path in &files {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        eprintln!("event=pending_consumed vm_id={id} reason={reason}");
    }
    match std::fs::remove_file(dir.join(PHASE_RECORD)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// A loaded VM has a live VMM but no executing vCPUs or readiness receipt.
pub fn lifecycle_state(dir: &Path) -> Result<&'static str> {
    if !is_running(dir) {
        return Ok("stopped");
    }
    match read_phase(dir)? {
        PhaseRecord::Missing => Ok("running"),
        PhaseRecord::Present {
            phase: phase @ ("loading" | "loaded" | "resuming"),
            ..
        } => Ok(phase),
        PhaseRecord::Present { .. } | PhaseRecord::Invalid => {
            Err(Error::Internal("invalid persisted VM phase".into()))
        }
    }
}

/// Before a start: a live VMM (running, or a loaded/loading pool generation)
/// is left to `start`'s own phase checks; a dead VMM with a record is stopped,
/// which settles it; a stopped space only settles its pending memory, without
/// touching TAP or jail state.
pub fn settle_before_start(dir: &Path, cfg: &NetConfig) -> Result<()> {
    if is_running(dir) {
        return Ok(());
    }
    match read_phase(dir)? {
        PhaseRecord::Missing
        | PhaseRecord::Present {
            phase: "pending", ..
        } => settle_pending(dir),
        _ => stop(dir, cfg).map(|_| ()),
    }
}

/// Recovers every space before the daemon accepts requests: interrupted pool
/// generations, live or not, are stopped; stopped spaces are settled.
pub fn recover_loaded(root: &Path, cfg: &NetConfig) -> Result<()> {
    for entry in std::fs::read_dir(root.join("vm"))? {
        let dir = entry?.path();
        if dir_id(&dir).is_err() {
            continue;
        }
        match (read_phase(&dir)?, is_running(&dir)) {
            (PhaseRecord::Missing, true) => {}
            (_, false) => settle_before_start(&dir, cfg)?,
            (_, true) => {
                stop(&dir, cfg)?;
            }
        }
    }
    Ok(())
}

/// Host-side snapshot files to load instead of a cold boot.
pub struct RestoreFiles<'a> {
    pub mem: &'a Path,
    pub state: &'a Path,
    pub guest_snapshot_nonce: Option<&'a str>,
    pub anon_holes: bool,
}

/// File-backed restore uses private mappings; never grant the jail write access.
/// A load-only (pool) load also freezes the guest clocks until the handout
/// resume, so the pool dwell neither advances guest monotonic time nor fires
/// every overdue guest timer at once.
fn snapshot_load_body(
    tap: Option<&str>,
    load_only: bool,
    track_dirty: bool,
    anon_holes: bool,
) -> String {
    let mut base = format!(
        "\"snapshot_path\":\"snap.state\",\"mem_backend\":{{\"backend_path\":\"snap.mem\",\"backend_type\":\"File\"}},\"track_dirty_pages\":{track_dirty},\"resume_vm\":{}{}",
        !load_only,
        if load_only {
            ",\"freeze_clock_until_resume\":true"
        } else {
            ""
        }
    );
    if anon_holes {
        base.push_str(",\"anon_holes\":true");
    }
    tap.map_or_else(
        || format!("{{{base}}}"),
        |tap| format!(
            "{{{base},\"network_overrides\":[{{\"iface_id\":\"eth0\",\"host_dev_name\":\"{tap}\"}}]}}"
        ),
    )
}

/// Classifies the typed thaw fields in Firecracker's clock log, which shares
/// the console with guest serial output. A missing thaw line is not success.
fn clock_thaw(console: &str) -> Option<(&'static str, u64)> {
    console.lines().find_map(|line| {
        let (_, summary) = line.split_once(" guest clock")?;
        let (_, fields) = summary.split_once(" clock_frozen=")?;
        let mut fields = fields.split(' ');
        let frozen = fields.next()?.parse().ok()?;
        let dwell_ms = fields.next()?.strip_prefix("dwell_ms=")?.parse().ok()?;
        let tsc_frozen = fields.next()?.strip_prefix("tsc_frozen=")?.parse().ok()?;
        let outcome = match (frozen, tsc_frozen) {
            (true, true) => "both",
            (true, false) => "kvmclock_only",
            (false, false) => "none",
            (false, true) => return None,
        };
        Some((outcome, dwell_ms))
    })
}

/// Console output appended since `offset`, capped so a chatty guest cannot
/// make the resume path read megabytes.
fn resumed_console(dir: &Path, offset: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX: u64 = 64 * 1024;
    let mut file = std::fs::File::open(dir.join("console.log")).ok()?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Boots the VM unless it is already up. Returns whether a boot happened.
/// `network_ready` reconciles peer connectivity after thaw/base setup and TAP
/// activation but before application admission, without holding state locks.
/// The hook receives the shared monotonic admission deadline and is skipped
/// when a verified same-generation receipt is reused.
pub fn start(
    root: &Path,
    id: Uuid,
    image_kind: Image,
    options: StartOptions<'_>,
    cfg: &VmConfig,
    net_cfg: &NetConfig,
    mut network_ready: impl FnMut(Instant) -> Result<()>,
) -> Result<(PathBuf, bool)> {
    let StartOptions {
        vcpus,
        mem_mib,
        restore,
        readiness,
        load_only,
        track_dirty,
    } = options;
    let vcpus = vcpus.unwrap_or(cfg.vcpus);
    let mem_mib = mem_mib.unwrap_or(cfg.mem_mib);
    let dir = shinu_core::vm_dir(root, id);
    let vsock = vsock_path(&dir);
    let phase = lifecycle_state(&dir)?;
    if phase == "loaded" && load_only {
        return Ok((vsock, false));
    }
    if phase != "running" && phase != "stopped" {
        return Err(Error::Invalid("space is loaded; use resume or stop".into()));
    }
    if load_only && (restore.is_none() || is_running(&dir)) {
        return Err(Error::Invalid(
            "load_only requires a stopped Full memory fork".into(),
        ));
    }
    if let Some(spec) = readiness {
        spec.validate()?;
    }
    if phase == "stopped" {
        settle_pending(&dir)?;
    }
    if is_running(&dir) {
        // The idle sweeper may have reclaimed this VM's memory; give it
        // back before the caller runs anything in it.
        release(&dir);
        if let Some(spec) = readiness {
            let boot = boot_identity(&dir).inspect_err(|_| forget_readiness(&dir))?;
            if let Err(error) = admit_application(&dir, spec, &boot, &mut network_ready) {
                if let Err(cleanup) = cleanup_boot(&dir, net_cfg, &boot) {
                    eprintln!("readiness boot cleanup for {id}: {cleanup}");
                }
                return Err(error);
            }
        }
        touch(&dir)?;
        return Ok((vsock, false));
    }
    forget_readiness(&dir);
    match std::fs::remove_file(dir.join("snapshot-generation")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let memory_limit_bytes = crate::config::jailer_memory_limit_bytes(mem_mib)?;

    let image = shinu_core::space_image(root, id);
    if !image.exists() {
        return Err(Error::NotFound(format!("space image: {}", image.display())));
    }
    let kernel = shinu_core::kernel_path(root);
    if !kernel.exists() {
        return Err(Error::NotFound(format!(
            "kernel image: {}",
            kernel.display()
        )));
    }

    // A stale socket or jail from a dead VM must not make the next jailer
    // invocation reuse an old chroot or fail to bind its UDS.
    let _ = std::fs::remove_file(&vsock);
    let _ = std::fs::remove_file(api_path(&dir));
    std::fs::create_dir_all(&dir)?;
    if restore.is_some() {
        // A direct restore loads with resume_vm=true, so its vCPUs may run as
        // soon as the load request is sent: record `resuming` first.
        write_phase(&dir, if load_only { "loading" } else { "resuming" })?;
    }
    std::fs::write(
        dir.join("track-dirty"),
        if track_dirty { "true" } else { "false" },
    )?;
    if let Some(nonce) = restore.and_then(|files| files.guest_snapshot_nonce) {
        store_snapshot_nonce(&dir, nonce)?;
    } else {
        match std::fs::remove_file(dir.join("snapshot-worker-nonce")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    clean_jail(&dir)?;
    let jail = jail_root(root, id);
    let mut jail_builder = std::fs::DirBuilder::new();
    jail_builder.recursive(true).mode(0o700).create(&jail)?;
    std::fs::set_permissions(&jail, std::fs::Permissions::from_mode(0o700))?;

    let net = crate::net::net_spec(id, net_cfg);
    // Keep the cross-process claim through launch/admission and all cleanup.
    // An existing TAP rejected before prepare_tap succeeds is never ours to delete.
    let _tap_claim = if net_cfg.enabled {
        Some(claim_tap(id)?)
    } else {
        None
    };
    if let Err(error) = tap_up(id, net_cfg, cfg) {
        let _ = clean_jail(&dir);
        return Err(error);
    }
    let mut attempted_boot = None;
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
        if let Some(files) = restore {
            let jail_mem = jail.join(JAIL_SNAP_MEM);
            let jail_state = jail.join(JAIL_SNAP_STATE);
            link_resource(files.mem, &jail_mem)?;
            link_resource(files.state, &jail_state)?;
            // Shared checkpoint inodes must never be writable by the jailed uid.
            // Root owns the inode; only its group is granted read access.
            for path in [&jail_mem, &jail_state] {
                let metadata = std::fs::metadata(path)?;
                if metadata.uid() != 0 || metadata.gid() != cfg.jail_gid {
                    std::os::unix::fs::chown(path, Some(0), Some(cfg.jail_gid))?;
                }
                if metadata.mode() & 0o777 != 0o440 {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o440))?;
                }
            }
        }

        if restore.is_none() {
            let config = config_path(&dir);
            let body = crate::config::vm_config_json(
                Path::new(JAIL_KERNEL),
                Path::new(JAIL_ROOTFS),
                image_kind,
                Path::new(JAIL_VSOCK),
                crate::config::MachineConfig {
                    vcpus,
                    mem_mib,
                    track_dirty,
                },
                net.as_ref(),
            );
            let mut config_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&config)?;
            config_file.write_all(body.as_bytes())?;
            config_file.sync_all()?;
            drop(config_file);
            // The jailer drops to the dedicated uid/gid before Firecracker
            // opens its config. Make that single file group-readable rather
            // than depending on the daemon process umask.
            std::os::unix::fs::chown(&config, None, Some(cfg.jail_gid))?;
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640))?;
        }

        // Keep the VM outside the daemon's session so daemon restart does
        // not signal or reap a running guest. `setsid --fork` still gives
        // the jailer a detached process while its child becomes the
        // Firecracker process we identify below.
        let log = std::fs::File::create(dir.join("console.log"))?;
        let memory_limit = format!("memory.max={memory_limit_bytes}");
        let jailer = shinu_core::jailer_bin(root);
        let firecracker = shinu_core::firecracker_bin(root);
        let mut command = std::process::Command::new("setsid");
        command
            .arg("--fork")
            .arg(&jailer)
            .arg("--id")
            .arg(id.to_string())
            .arg("--exec-file")
            .arg(&firecracker)
            .arg("--uid")
            .arg(cfg.jail_uid.to_string())
            .arg("--gid")
            .arg(cfg.jail_gid.to_string())
            .arg("--chroot-base-dir")
            .arg(root.join("jail"))
            .arg("--cgroup-version")
            .arg("2")
            .arg("--cgroup")
            .arg(&memory_limit)
            .arg("--cgroup")
            .arg("pids.max=512")
            .arg("--")
            .arg("--api-sock")
            .arg("fc.sock");
        if restore.is_none() {
            command.arg("--config-file").arg("fc.json");
        }
        // The assets cross from the daemon's root privilege into the jailer
        // boundary. Re-read no-follow metadata immediately before execution;
        // an unsafe replacement must fail closed rather than reach `setsid`.
        validate_vm_assets(&jailer, &firecracker)?;
        if std::env::var("SHINU_KSM_MERGE").as_deref() == Ok("1") {
            // SAFETY: the post-fork hook only performs prctl and captures no references.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_MEMORY_MERGE, 1_u64, 0_u64, 0_u64, 0_u64) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        #[cfg(test)]
        ledger_journal::record("launch".into());
        let status = command
            .stdin(std::process::Stdio::null())
            .stderr(log.try_clone()?)
            .stdout(log)
            .status()?;
        if !status.success() {
            return Err(Error::Internal(format!(
                "could not launch jailer: {}",
                console_tail(&dir).trim()
            )));
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
            return Err(Error::Internal(format!(
                "firecracker exited immediately: {}",
                console_tail(&dir)
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
        attempted_boot = Some(boot_identity(&dir)?);

        let ready = || {
            if wait_ready(&dir, &vsock) {
                return Ok(());
            }
            Err(Error::Internal(format!(
                "vm did not come up: {}",
                console_tail(&dir)
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(" | ")
            )))
        };
        if restore.is_some() {
            let mut api_ready = false;
            for _ in 0..100 {
                if api_path(&dir).exists() {
                    api_ready = true;
                    break;
                }
                if !is_running(&dir) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !api_ready {
                let _ = stop(&dir, net_cfg);
                let _ = std::fs::remove_file(jail.join(JAIL_SNAP_MEM));
                let _ = std::fs::remove_file(jail.join(JAIL_SNAP_STATE));
                return Err(Error::Internal(
                    "snapshot restore API socket did not appear".to_owned(),
                ));
            }
            if let Some(spec) = net.as_ref() {
                require_success("ip", &["link", "set", &spec.tap, "down"])?;
            }
            let body = snapshot_load_body(
                net.as_ref().map(|spec| spec.tap.as_str()),
                load_only,
                track_dirty,
                restore.is_some_and(|files| files.anon_holes),
            );
            if api_with_timeout(
                &dir,
                "PUT",
                "/snapshot/load",
                Some(&body),
                SNAPSHOT_TIMEOUT_SECS,
            )
            .is_none()
            {
                return Err(Error::Internal("failed to load VM snapshot".into()));
            }
            // The private mapping keeps the inode alive. New hot captures must
            // create fresh files, never truncate a linked checkpoint inode.
            std::fs::remove_file(jail.join(JAIL_SNAP_MEM))?;
            std::fs::remove_file(jail.join(JAIL_SNAP_STATE))?;
            if load_only {
                std::fs::set_permissions(api_path(&dir), std::fs::Permissions::from_mode(0o600))?;
                if vsock.exists() {
                    std::fs::set_permissions(&vsock, std::fs::Permissions::from_mode(0o600))?;
                }
                // Pool fill only: the handout path never waits for this.
                if let Some(files) = restore {
                    prefault_loaded(&dir, id, files.mem);
                }
                write_phase(&dir, "loaded")?;
                touch(&dir)?;
                return Ok((vsock, true));
            }
            finish_restore(root, id, readiness, net_cfg, &mut network_ready)?;
        } else {
            ready()?;
        }
        if restore.is_none() {
            match readiness {
                Some(spec) => admit_application(
                    &dir,
                    spec,
                    attempted_boot
                        .as_ref()
                        .ok_or_else(|| Error::Internal("readiness boot identity missing".into()))?,
                    &mut network_ready,
                )?,
                None => network_ready(Instant::now() + Duration::from_secs(30))?,
            }
        }
        if readiness.is_none()
            && let Err(error) = prepare_snapshot_worker(&dir)
        {
            // Nonconfigured spaces retain their platform-only contract.
            eprintln!("snapshot worker preparation for {id}: {error}");
        }

        // The jailer runs Firecracker as its configured non-root uid, but
        // the host-side vsock stays owned by the daemon: 0600 as root is
        // what keeps a space owner from reaching another guest's socket.
        std::fs::set_permissions(&vsock, std::fs::Permissions::from_mode(0o600))?;
        // The control API remains daemon-only: it can resize the balloon
        // and reconfigure devices, so an owner must never receive it.
        std::fs::set_permissions(api_path(&dir), std::fs::Permissions::from_mode(0o600))?;
        if restore.is_some() {
            settle_pending(&dir)?;
        }
        touch(&dir)?;
        Ok((vsock, true))
    })();
    if result.is_err() {
        let cleanup = attempted_boot.as_ref().map_or_else(
            || stop(&dir, net_cfg).map(|_| ()),
            |boot| cleanup_boot(&dir, net_cfg, boot),
        );
        if let Err(error) = cleanup {
            eprintln!("boot cleanup for {id}: {error}");
        }
    }
    result
}

fn finish_restore(
    root: &Path,
    id: Uuid,
    readiness: Option<&ReadySpec>,
    net_cfg: &NetConfig,
    network_ready: &mut impl FnMut(Instant) -> Result<()>,
) -> Result<()> {
    let dir = shinu_core::vm_dir(root, id);
    let net = crate::net::net_spec(id, net_cfg);
    let vsock = vsock_path(&dir);
    restore_transaction(|step| {
        let started = Instant::now();
        let result = restore_step(
            &dir,
            id,
            step,
            readiness,
            net_cfg,
            net.as_ref(),
            &vsock,
            network_ready,
        );
        // Sanitized per-step timing; no guest output, argv or secrets.
        eprintln!(
            "event=restore_step vm_id={id} step={step:?} elapsed_ms={} ok={}",
            started.elapsed().as_millis(),
            result.is_ok()
        );
        result
    })
}

#[allow(clippy::too_many_arguments)]
fn restore_step(
    dir: &Path,
    id: Uuid,
    step: RestoreStep,
    readiness: Option<&ReadySpec>,
    net_cfg: &NetConfig,
    net: Option<&crate::net::NetSpec>,
    vsock: &Path,
    network_ready: &mut impl FnMut(Instant) -> Result<()>,
) -> Result<()> {
    match step {
        RestoreStep::Quarantine | RestoreStep::Load => Ok(()),
        // The TAP stays down: its policy is reasserted while the guest thaws,
        // leaving only the link flip on the critical path after Configure.
        RestoreStep::Thaw => std::thread::scope(|scope| {
            let policy = scope.spawn(|| reassert_tap_policy(id, net_cfg, &[], TapSetup::Existing));
            let thawed = thaw_snapshot(dir);
            let policy = policy
                .join()
                .unwrap_or_else(|_| Err(Error::Internal("TAP policy worker panicked".into())));
            combine_snapshot_results(thawed, policy)
        }),
        RestoreStep::Ready => {
            let ready = wait_ready_observed(dir, vsock, |attempt, elapsed, ok| {
                eprintln!(
                    "event=restore_substep vm_id={id} step=ReadyProbe attempt={attempt} elapsed_ms={} ok={ok}",
                    elapsed.as_millis()
                );
            });
            if ready {
                Ok(())
            } else {
                Err(Error::Internal(
                    "restored guest SSH did not become ready".into(),
                ))
            }
        }
        RestoreStep::Configure => {
            match guest_setup(dir, net, Instant::now() + Duration::from_secs(30)) {
                Ok(()) => Ok(()),
                // Pre-setup helpers and helper-less guests keep the SSH path.
                Err(SetupError::Unsupported) => ssh_guest_setup(dir, vsock, net),
                Err(SetupError::Failed(error)) => Err(error),
            }
        }
        RestoreStep::Expose => expose_tap(id, net_cfg),
        RestoreStep::ApplicationReady => match readiness {
            Some(spec) => admit_application(dir, spec, &boot_identity(dir)?, network_ready),
            None => network_ready(Instant::now() + Duration::from_secs(30)),
        },
    }
}

/// Resume only a durably loaded generation, then perform the normal admission.
pub fn resume(
    root: &Path,
    id: Uuid,
    readiness: Option<&ReadySpec>,
    net_cfg: &NetConfig,
    mut network_ready: impl FnMut(Instant) -> Result<()>,
) -> Result<(PathBuf, bool)> {
    let dir = shinu_core::vm_dir(root, id);
    if lifecycle_state(&dir)? != "loaded" {
        return Err(Error::Invalid("resume requires a loaded space".into()));
    }
    if let Some(spec) = readiness {
        spec.validate()?;
    }
    let boot = boot_identity(&dir)?;
    forget_readiness(&dir);
    // Recorded before PATCH Resumed; see `write_phase` for why no fsync.
    let persisted = Instant::now();
    write_phase(&dir, "resuming")?;
    eprintln!(
        "event=restore_step vm_id={id} step=PersistResuming elapsed_us={} ok=true",
        persisted.elapsed().as_micros()
    );
    let result = (|| {
        let started = Instant::now();
        let console_offset = std::fs::metadata(dir.join("console.log")).map_or(0, |m| m.len());
        if api(&dir, "PATCH", "/vm", Some("{\"state\":\"Resumed\"}")).is_none() {
            return Err(Error::Internal("failed to resume loaded VM".into()));
        }
        // Firecracker logs the thaw before acknowledging the resume.
        let clock = resumed_console(&dir, console_offset)
            .as_deref()
            .and_then(clock_thaw)
            .map_or_else(
                || " clock_frozen=none".to_owned(),
                |(outcome, dwell_ms)| format!(" clock_frozen={outcome} dwell_ms={dwell_ms}"),
            );
        eprintln!(
            "event=restore_step vm_id={id} step=Resume elapsed_ms={} ok=true{clock}",
            started.elapsed().as_millis()
        );
        finish_restore(root, id, readiness, net_cfg, &mut network_ready)?;
        settle_pending(&dir)?;
        touch(&dir)?;
        Ok((vsock_path(&dir), true))
    })();
    if result.is_err()
        && let Err(error) = cleanup_boot(&dir, net_cfg, &boot)
    {
        eprintln!("resume cleanup for {id}: {error}");
    }
    result
}

fn dir_id(dir: &Path) -> Result<Uuid> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Internal(format!("VM directory has no UUID: {}", dir.display())))?;
    Uuid::parse_str(name).map_err(|error| {
        Error::Internal(format!(
            "VM directory is not a UUID ({}): {error}",
            dir.display()
        ))
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
        Error::Internal(format!(
            "image path is not valid UTF-8: {}",
            image.display()
        ))
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
    baseline.is_none_or(|baseline| current.saturating_sub(baseline) >= RECLAIM_GROWTH_BYTES)
}
const RECLAIM_DELAY: Duration = Duration::from_mins(1);

fn stopped_at_path(dir: &Path) -> PathBuf {
    dir.join("stopped_at")
}

fn stopped_long_enough(dir: &Path) -> bool {
    let Ok(stopped_at) =
        std::fs::metadata(stopped_at_path(dir)).and_then(|metadata| metadata.modified())
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
    // Run e2fsck off the request path. Reflinked checkpoint extents remain
    // protected by CoW, while discard releases only unshared blocks.
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
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "Reclaim bytes are converted to f64 solely for a human-readable MiB display metric."
                )]
                let reclaimed_mib = bytes as f64 / (1024.0 * 1024.0);
                eprintln!(
                    "reclaimed {:.1} MiB from {}",
                    reclaimed_mib,
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
/// Flushes guest writes before stopping the VMM; signals are only a fallback
/// for a wedged or already-unresponsive process.
pub fn stop(dir: &Path, cfg: &NetConfig) -> Result<bool> {
    stop_with_peers(dir, cfg, &[])
}

pub fn stop_with_peers(dir: &Path, cfg: &NetConfig, peers: &[String]) -> Result<bool> {
    forget_readiness(dir);
    let id = dir_id(dir)?;
    let vsock = vsock_path(dir);
    let api_socket = api_path(dir);
    let pid_file = pid_path(dir);
    let Some(pid) = running_pid(dir) else {
        let _ = std::fs::remove_file(&vsock);
        let _ = std::fs::remove_file(&api_socket);
        let _ = std::fs::remove_file(&pid_file);
        tap_down_with_peers(id, cfg, peers);
        clean_jail(dir)?;
        settle_pending(dir)?;
        mark_stopped(dir);
        return Ok(false);
    };

    if vsock.exists() && !matches!(lifecycle_state(dir), Ok("loading" | "loaded")) {
        // Durability needs exactly one thing: the guest's dirty pages on
        // the image before the VMM dies. `sync` plus a read-only remount
        // does that and returns normally, leaving the connection intact.
        let _ = run_guest_flush(&vsock, &key_path(dir));
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
        tap_down_with_peers(id, cfg, peers);
        return Err(Error::Internal(format!(
            "firecracker pid {pid} did not stop"
        )));
    }
    let _ = std::fs::remove_file(&vsock);
    let _ = std::fs::remove_file(&api_socket);
    let _ = std::fs::remove_file(&pid_file);
    tap_down_with_peers(id, cfg, peers);
    clean_jail(dir)?;
    settle_pending(dir)?;
    mark_stopped(dir);
    Ok(true)
}

/// Idle housekeeping reclaims memory before shutting down a VM at the full
/// idle deadline. Stopped images are compacted on a later sweep so kernel
/// writeback has settled; the reclaim marker avoids rescanning unchanged
/// images. A missing `last_used` is treated as just used so a fresh VM is not
/// reaped before its first command.
pub fn sweep_idle(
    root: &Path,
    vm_cfg: &VmConfig,
    cfg: &NetConfig,
    space_lock: impl Fn(Uuid) -> std::sync::Arc<std::sync::Mutex<()>>,
) -> Result<Vec<PathBuf>> {
    // Leave page-cache and working-set headroom for the next guest command.
    const KEEP_MIB: u64 = 128;
    let idle_secs = vm_cfg.idle_secs;
    let mut stopped = Vec::new();
    let vm_root = root.join("vm");
    let entries = match std::fs::read_dir(&vm_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(stopped),
        Err(error) => return Err(error.into()),
    };
    let now = now_secs();
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(id) = dir_id(&dir) else {
            continue;
        };
        // Share the request handlers' lifecycle lock. A stopped-image check
        // must remain true until e2fsck/discard has finished, not race a boot.
        let lock = space_lock(id);
        let _guard = match lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => continue,
        };
        if !is_running(&dir) {
            if vm_cfg.idle_reclaim {
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
            if let Err(error) = stop(&dir, cfg) {
                eprintln!("idle sweep failed to stop {}: {error}", dir.display());
                continue;
            }
            stopped.push(dir);
        } else if idle_for >= (idle_secs / 10).max(30) && !dir.join("loaded.json").exists() {
            reclaim(&dir, KEEP_MIB);
        }
    }
    Ok(stopped)
}
#[cfg(test)]
mod jail_tests {
    use super::{VmConfig, jail_root, jail_socket};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use uuid::Uuid;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct JailEnv {
        uid: Option<OsString>,
        gid: Option<OsString>,
        idle_reclaim: Option<OsString>,
    }

    impl JailEnv {
        fn capture() -> Self {
            Self {
                uid: std::env::var_os("SHINU_JAIL_UID"),
                gid: std::env::var_os("SHINU_JAIL_GID"),
                idle_reclaim: std::env::var_os("SHINU_IDLE_RECLAIM"),
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
                match &self.idle_reclaim {
                    Some(value) => std::env::set_var("SHINU_IDLE_RECLAIM", value),
                    None => std::env::remove_var("SHINU_IDLE_RECLAIM"),
                }
            }
        }
    }

    #[test]
    fn jail_root_has_the_expected_chroot_layout() {
        let id = Uuid::from_u128(1);
        assert_eq!(
            jail_root(Path::new("/var/lib/shinu"), id),
            PathBuf::from(format!("/var/lib/shinu/jail/firecracker/{id}/root"))
        );
    }

    #[test]
    fn jail_socket_is_inside_the_jail_root() {
        let id = Uuid::from_u128(2);
        let root = jail_root(Path::new("/srv/shinu"), id);
        let socket = jail_socket(Path::new("/srv/shinu"), id);
        assert!(socket.starts_with(&root));
        assert_eq!(
            socket.strip_prefix(root).expect("socket relative"),
            Path::new("fc.sock")
        );
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
            std::env::remove_var("SHINU_IDLE_RECLAIM");
        }
        let config = VmConfig::from_env().expect("valid VM config");
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
            std::env::remove_var("SHINU_IDLE_RECLAIM");
        }
        let config = VmConfig::from_env().expect("valid VM config");
        assert_eq!(config.jail_uid, 40_123);
        assert_eq!(config.jail_gid, 40_124);
    }

    #[test]
    fn idle_reclaim_configuration_defaults_on_and_accepts_boolean_override() {
        let _lock = ENV_LOCK.lock().expect("jail env lock");
        let _env = JailEnv::capture();
        unsafe { std::env::remove_var("SHINU_IDLE_RECLAIM") };
        assert!(VmConfig::from_env().expect("default config").idle_reclaim);
        for (value, expected) in [
            ("0", false),
            (" false ", false),
            ("1", true),
            ("TRUE", true),
        ] {
            unsafe { std::env::set_var("SHINU_IDLE_RECLAIM", value) };
            assert_eq!(
                VmConfig::from_env().expect("boolean config").idle_reclaim,
                expected
            );
        }
    }

    #[test]
    fn idle_reclaim_configuration_rejects_invalid_startup_values() {
        use std::os::unix::ffi::OsStringExt;

        let _lock = ENV_LOCK.lock().expect("jail env lock");
        let _env = JailEnv::capture();
        for value in ["", " ", "2", "-1", "disabled"] {
            unsafe { std::env::set_var("SHINU_IDLE_RECLAIM", value) };
            let error = VmConfig::from_env().expect_err("invalid reclaim config");
            assert!(error.to_string().contains("SHINU_IDLE_RECLAIM"));
        }
        unsafe {
            std::env::set_var("SHINU_IDLE_RECLAIM", OsString::from_vec(vec![0xff]));
        }
        assert!(VmConfig::from_env().is_err());
    }
}
#[cfg(test)]
mod asset_validation_tests {
    use super::{trusted_asset_attributes, validate_vm_asset};
    use std::os::unix::fs::symlink;
    use uuid::Uuid;

    #[test]
    fn execution_asset_attributes_require_root_owned_nonwritable_executable() {
        assert!(trusted_asset_attributes(true, 0, 0o755, 0));
        assert!(!trusted_asset_attributes(false, 0, 0o755, 0));
        assert!(!trusted_asset_attributes(true, 1000, 0o755, 0));
        assert!(!trusted_asset_attributes(true, 0, 0o775, 0));
        assert!(!trusted_asset_attributes(true, 0, 0o644, 0));
    }

    #[test]
    fn execution_rejects_a_symlinked_asset() {
        let parent = std::env::temp_dir().join(format!("shinu-vm-assets-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&parent).expect("create fixture parent");
        let target = parent.join("target");
        let link = parent.join("jailer");
        std::fs::write(&target, b"not a trusted binary").expect("write fixture target");
        symlink(&target, &link).expect("create asset symlink");

        let result = validate_vm_asset(&link, "jailer");

        assert!(matches!(result, Err(super::Error::Invalid(_))));
        std::fs::remove_dir_all(parent).expect("remove fixture");
    }
}
#[cfg(test)]
mod reclaim_tests {
    use super::{e2fsck_ok, reclaim_due, reclaim_image, sweep_idle};
    use crate::{NetConfig, VmConfig};
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
        let mut component = OsString::from(format!("shinu-sweep-reclaim-{}", std::process::id()));
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
            host_allow: Vec::new(),
        };
        let vm_config = VmConfig {
            vcpus: 1,
            mem_mib: 128,
            idle_secs: 0,
            idle_reclaim: true,
            jail_uid: 30000,
            jail_gid: 30000,
        };
        let lock = std::sync::Arc::new(std::sync::Mutex::new(()));
        let stopped = sweep_idle(&root, &vm_config, &config, |_| lock.clone())
            .expect("sweep ignores reclaim errors");

        assert!(stopped.is_empty());
        std::fs::remove_dir_all(root).expect("test fixture cleanup");
    }

    #[test]
    fn idle_reclaim_sweep_skips_an_inflight_lifecycle_operation() {
        let root = std::env::temp_dir().join(format!("shinu-sweep-lock-{}", Uuid::new_v4()));
        let id = Uuid::from_u128(0x5678);
        std::fs::create_dir_all(vm_dir(&root, id)).expect("VM fixture");
        let vm_config = VmConfig {
            vcpus: 1,
            mem_mib: 128,
            idle_secs: 0,
            idle_reclaim: false,
            jail_uid: 30000,
            jail_gid: 30000,
        };
        let config = NetConfig {
            enabled: false,
            base: [172, 31],
            uplink: String::new(),
            allow: Vec::new(),
            host_allow: Vec::new(),
        };
        let lock = std::sync::Arc::new(std::sync::Mutex::new(()));
        let guard = lock.lock().expect("lifecycle lock");
        let sweep_lock = lock.clone();
        let sweep_root = root.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = sweep_idle(&sweep_root, &vm_config, &config, |found| {
                assert_eq!(found, id);
                sweep_lock.clone()
            });
            send.send(result).expect("send sweep result");
        });
        let result = receive.recv_timeout(std::time::Duration::from_secs(1));
        drop(guard);
        worker.join().expect("sweep worker");
        assert!(
            result
                .expect("busy space must be skipped")
                .expect("sweep")
                .is_empty()
        );
        std::fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
#[cfg(test)]
mod input_chain_tests {
    use super::{
        SHINU_INPUT_CHAIN, input_chain_create_args, input_chain_jump_add_args,
        input_chain_jump_check_args, input_rule_args,
    };

    #[test]
    fn chain_creation_and_input_jump_are_idempotent_argv() {
        assert_eq!(input_chain_create_args(), ["-N", "SHINU-INPUT"]);
        assert_eq!(
            input_chain_jump_check_args(),
            ["-C", "INPUT", "-j", "SHINU-INPUT"]
        );
        assert_eq!(
            input_chain_jump_add_args(),
            ["-I", "INPUT", "1", "-j", "SHINU-INPUT"]
        );
        assert_eq!(SHINU_INPUT_CHAIN, "SHINU-INPUT");
    }

    #[test]
    fn chain_rule_check_and_add_append_to_shared_chain() {
        let rule = vec![
            "-i".to_owned(),
            "shinu0123456789".to_owned(),
            "-j".to_owned(),
            "DROP".to_owned(),
        ];
        let (check, add) = input_rule_args(&rule);
        assert_eq!(
            check,
            vec![
                "-C".to_owned(),
                "SHINU-INPUT".to_owned(),
                "-i".to_owned(),
                "shinu0123456789".to_owned(),
                "-j".to_owned(),
                "DROP".to_owned(),
            ]
        );
        assert_eq!(
            add,
            vec![
                "-A".to_owned(),
                "SHINU-INPUT".to_owned(),
                "-i".to_owned(),
                "shinu0123456789".to_owned(),
                "-j".to_owned(),
                "DROP".to_owned(),
            ]
        );
    }
}

#[cfg(test)]
mod process_group_tests {
    use super::{run_process_group, ssh_command};
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    #[test]
    fn process_group_runner_places_the_child_in_its_own_group() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test \"$(ps -o pgid= -p $$ | tr -d ' ')\" = \"$$\"");

        let status = run_process_group(command, Duration::from_secs(1), None);

        assert_eq!(status.and_then(|status| status.code()), Some(0));
    }

    #[test]
    fn process_group_runner_kills_descendants_at_the_deadline() {
        let marker = std::env::temp_dir().join(format!(
            "shinu-process-group-{}-{}.marker",
            std::process::id(),
            Uuid::new_v4()
        ));
        let marker_word = shinu_core::shell_quote_word(&marker.to_string_lossy());
        let script = format!("(sleep 0.3; printf leaked > {marker_word}) & wait");
        let mut command = Command::new("sh");
        command.arg("-c").arg(&script);

        let started = Instant::now();
        let status = run_process_group(command, Duration::from_millis(50), None);

        assert!(status.is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(500));
        assert!(!marker.exists());
        let _ = std::fs::remove_file(marker);
    }

    #[test]
    fn private_payload_prefix_is_not_exposed_in_process_arguments() {
        let root = std::env::temp_dir().join(format!("shinu-input-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let payload = root.join("source");
        std::fs::write(&payload, b"binary\0\xffpayload").unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "tr '\\0' ' ' < /proc/$$/cmdline > \"$1/argv\"; IFS= read -r secret; printf %s \"$secret\" > \"$1/prefix\"; cat > \"$1/binary\"", "snapshot-setup"]).arg(&root);
        let status = run_process_group(
            command,
            Duration::from_secs(1),
            Some((
                "private-token".into(),
                std::fs::File::open(&payload).unwrap(),
            )),
        );
        assert_eq!(status.and_then(|status| status.code()), Some(0));
        assert_eq!(
            std::fs::read(root.join("binary")).unwrap(),
            b"binary\0\xffpayload"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("prefix")).unwrap(),
            "private-token"
        );
        assert!(
            !std::fs::read_to_string(root.join("argv"))
                .unwrap()
                .contains("private-token")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn blocked_payload_writer_cannot_escape_the_process_deadline() {
        let path = std::env::temp_dir().join(format!("shinu-input-{}", Uuid::new_v4()));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(1024 * 1024).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 2"]);
        let started = Instant::now();
        assert!(
            run_process_group(
                command,
                Duration::from_millis(50),
                Some(("private-token".into(), std::fs::File::open(&path).unwrap()))
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn successful_child_cannot_leave_a_blocked_payload_producer_unbounded() {
        let path = std::env::temp_dir().join(format!("shinu-input-{}", Uuid::new_v4()));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "exec 3<&0; sleep 2 <&3 & exit 0"]);
        let started = Instant::now();
        assert!(
            run_process_group(
                command,
                Duration::from_millis(50),
                Some(("private-token".into(), std::fs::File::open(&path).unwrap()))
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn ssh_command_keeps_exec_transport_and_flush_argv_unchanged() {
        let flush = [
            "sh".to_owned(),
            "-c".to_owned(),
            "sync; mount -o remount,ro / 2>/dev/null; sync".to_owned(),
        ];
        let command = ssh_command(
            Path::new("/opt/shinu/shinu-vsock"),
            Path::new("/tmp/shinu-vsock.sock"),
            Path::new("/tmp/id_ed25519"),
            2222,
            &flush,
        );
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(command.get_program(), OsStr::new("ssh"));
        assert_eq!(
            args,
            vec![
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ProxyCommand=/opt/shinu/shinu-vsock /tmp/shinu-vsock.sock 2222",
                "-i",
                "/tmp/id_ed25519",
                "root@shinu",
                "--",
                "'sh' '-c' 'sync; mount -o remount,ro / 2>/dev/null; sync'",
            ]
        );
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
    let status = ssh_command(&helper, vsock_uds, key, port, cmd).status()?;
    Ok(status.code().unwrap_or(255))
}

#[cfg(test)]
mod snapshot_load_tests {
    use super::{clock_thaw, snapshot_load_body};

    // Firecracker rebuilds dirty-page tracking from the load request, so the
    // restore body must keep this flag on every branch.
    #[test]
    fn every_restore_requests_dirty_page_tracking() {
        assert!(
            snapshot_load_body(None, false, true, false).contains("\"track_dirty_pages\":true")
        );
        assert!(
            snapshot_load_body(Some("shinu0123456789"), false, true, false)
                .contains("\"track_dirty_pages\":true")
        );
    }

    #[test]
    fn a_tap_override_repoints_only_the_interface() {
        let body = snapshot_load_body(Some("shinudeadbeef0"), false, true, true);
        assert!(body.contains("\"iface_id\":\"eth0\""));
        assert!(body.contains("\"host_dev_name\":\"shinudeadbeef0\""));
        assert!(body.contains("\"resume_vm\":true"));
        assert!(body.contains("\"anon_holes\":true"));
    }

    #[test]
    fn no_tap_omits_the_override_entirely() {
        let body = snapshot_load_body(None, false, true, false);
        assert!(!body.contains("network_overrides"));
        assert!(body.contains("\"snapshot_path\":\"snap.state\""));
        assert!(body.contains("\"backend_type\":\"File\""));
        assert!(!body.contains("anon_holes"));
    }

    // Only a load-only (pool) load keeps the VM paused, so only it freezes the
    // clock; Firecracker rejects the flag together with resume_vm=true.
    #[test]
    fn only_load_only_freezes_the_clock() {
        for tap in [None, Some("shinudeadbeef0")] {
            let pooled: serde_json::Value =
                serde_json::from_str(&snapshot_load_body(tap, true, true, true)).unwrap();
            assert_eq!(pooled["resume_vm"], false);
            assert_eq!(pooled["freeze_clock_until_resume"], true);
            let direct: serde_json::Value =
                serde_json::from_str(&snapshot_load_body(tap, false, true, false)).unwrap();
            assert_eq!(direct["resume_vm"], true);
            assert!(direct.get("freeze_clock_until_resume").is_none());
        }
    }

    #[test]
    fn thaw_line_yields_only_typed_fields() {
        let console = "guest says guest clock: clock_frozen=maybe dwell_ms=1 tsc_frozen=false\n\
            2026-11-18T11:15:00.1 [anonymous-instance:fc_api] Thawed the frozen guest clock: clock_frozen=true dwell_ms=15004 tsc_frozen=true\n";
        assert_eq!(clock_thaw(console), Some(("both", 15004)));
        let legacy = "[x:fc_api] Thawed the frozen guest clock with errors: clock_frozen=true dwell_ms=1501 tsc_frozen=false reason=unsupported\n";
        assert_eq!(clock_thaw(legacy), Some(("kvmclock_only", 1501)));
        let failed = "[x:fc_api] Thawed the frozen guest clock with errors: clock_frozen=false dwell_ms=2 tsc_frozen=false reason=KVM_SET_CLOCK: Invalid argument (os error 22)\n";
        assert_eq!(clock_thaw(failed), Some(("none", 2)));
        assert_eq!(
            clock_thaw("guest clock: clock_frozen=false dwell_ms=1 tsc_frozen=true"),
            None
        );
        assert_eq!(clock_thaw("no thaw here\n"), None);
    }
}

#[cfg(test)]
mod hot_snapshot_tests {
    use super::{SnapshotStep, snapshot_transaction};

    #[test]
    fn disk_cut_follows_create_and_precedes_resume_and_thaw() {
        use SnapshotStep::{Create, Cut, Freeze, Pause, Resume, Thaw};
        let mut observed = Vec::new();
        snapshot_transaction(true, |step| {
            observed.push(step);
            Ok(())
        })
        .expect("capture");
        assert_eq!(observed, [Freeze, Pause, Create, Cut, Resume, Thaw]);
    }

    #[test]
    fn every_failure_attempts_thaw_and_never_publishes_success() {
        use SnapshotStep::{Create, Cut, Freeze, Pause, Resume, Thaw};
        for failed in [Freeze, Pause, Create, Cut, Resume, Thaw] {
            let mut observed = Vec::new();
            let result = snapshot_transaction(true, |step| {
                observed.push(step);
                if step == failed {
                    Err(shinu_core::Error::Internal(format!("injected {step:?}")))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "failure at {failed:?}");
            assert_eq!(observed.last(), Some(&Thaw));
            if failed != Freeze {
                assert!(observed.contains(&Resume), "failure at {failed:?}");
            }
            if matches!(failed, Freeze | Pause | Create) {
                assert!(!observed.contains(&Cut));
            }
        }
    }

    #[test]
    fn disk_only_hot_capture_still_freezes_pauses_and_thaws() {
        use SnapshotStep::{Cut, Freeze, Pause, Resume, Thaw};
        let mut observed = Vec::new();
        snapshot_transaction(false, |step| {
            observed.push(step);
            Ok(())
        })
        .expect("disk capture");
        assert_eq!(observed, [Freeze, Pause, Cut, Resume, Thaw]);
    }
}

#[cfg(test)]
mod restore_transaction_tests {
    use super::{RestoreStep, restore_transaction};

    #[test]
    fn restored_network_is_quarantined_until_thaw_and_configuration_succeed() {
        use RestoreStep::{ApplicationReady, Configure, Expose, Load, Quarantine, Ready, Thaw};
        let mut observed = Vec::new();
        restore_transaction(|step| {
            observed.push(step);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            observed,
            [
                Quarantine,
                Load,
                Thaw,
                Ready,
                Configure,
                Expose,
                ApplicationReady
            ]
        );
    }

    #[test]
    fn failed_restore_never_exposes_and_always_thaws_after_a_load_attempt() {
        use RestoreStep::{Configure, Expose, Load, Quarantine, Ready, Thaw};
        for failed in [Quarantine, Load, Thaw, Ready, Configure, Expose] {
            let mut observed = Vec::new();
            let result = restore_transaction(|step| {
                observed.push(step);
                if step == failed {
                    Err(shinu_core::Error::Internal(format!("injected {step:?}")))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "{failed:?}");
            if observed.contains(&Load) {
                assert!(observed.contains(&Thaw), "{failed:?}");
            }
            if failed != Expose {
                assert!(!observed.contains(&Expose), "{failed:?}");
            }
            if matches!(failed, Load | Thaw) {
                assert!(!observed.contains(&Configure));
            }
        }
    }

    #[test]
    fn application_failure_is_after_network_activation_but_never_success() {
        use RestoreStep::{ApplicationReady, Expose, Thaw};
        let mut observed = Vec::new();
        let result = restore_transaction(|step| {
            observed.push(step);
            if step == ApplicationReady {
                Err(shinu_core::Error::Internal("ready failed".into()))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert!(
            observed.iter().position(|step| *step == Thaw).unwrap()
                < observed.iter().position(|step| *step == Expose).unwrap()
        );
        assert_eq!(&observed[observed.len() - 2..], [Expose, ApplicationReady]);
    }
}

#[cfg(test)]
mod guest_setup_tests {
    use super::{SetupError, guest_setup, guest_setup_frame};
    use crate::net::NetSpec;
    use std::io::{BufRead, BufReader, Write};
    use std::time::{Duration, Instant, UNIX_EPOCH};

    const NONCE: &str = "00000000-0000-4000-8000-000000000001";

    fn spec() -> NetSpec {
        NetSpec {
            tap: "shinu0123456789".into(),
            mac: "06:00:ac:1d:00:02".into(),
            guest_cidr: "172.29.0.2/30".into(),
            gateway: "172.29.0.1".into(),
        }
    }

    #[test]
    fn setup_frame_is_a_platform_action_never_a_readiness_request() {
        let now = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        assert_eq!(
            guest_setup_frame(NONCE, now, None).unwrap(),
            format!("setup {NONCE} 1700000000000000005\n")
        );
        assert_eq!(
            guest_setup_frame(NONCE, now, Some(&spec())).unwrap(),
            format!(
                "setup {NONCE} 1700000000000000005 06:00:ac:1d:00:02 172.29.0.2/30 172.29.0.1\n"
            )
        );
    }

    /// Fake guest helper behind the Firecracker vsock UDS handshake.
    fn exchange(reply: &'static str) -> (std::result::Result<(), SetupError>, String) {
        let dir = std::env::temp_dir().join(format!("shinu-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("snapshot-worker-nonce"), NONCE).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(dir.join("vsock.sock")).unwrap();
        let guest = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "CONNECT 2224\n");
            (&stream).write_all(b"OK 1\nSHINU-SNAPSHOT-1\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            (&stream).write_all(reply.as_bytes()).unwrap();
            line
        });
        let result = guest_setup(&dir, Some(&spec()), Instant::now() + Duration::from_secs(5));
        let request = guest.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        (result, request)
    }

    #[test]
    fn only_setup_ok_succeeds_and_legacy_helpers_fall_back() {
        let (result, request) = exchange("SETUP-OK\n");
        assert!(result.is_ok());
        assert!(request.starts_with(&format!("setup {NONCE} ")), "{request}");
        // A READY line, even one for some restore, never satisfies setup.
        assert!(matches!(
            exchange("READY 00000000-0000-4000-8000-000000000002\n").0,
            Err(SetupError::Unsupported)
        ));
        assert!(matches!(
            exchange("FAILED readiness\n").0,
            Err(SetupError::Unsupported)
        ));
        assert!(matches!(
            exchange("FAILED setup\n").0,
            Err(SetupError::Failed(_))
        ));
    }

    #[test]
    fn missing_helper_identity_uses_the_ssh_fallback() {
        let dir = std::env::temp_dir().join(format!("shinu-setup-{}", uuid::Uuid::new_v4()));
        assert!(matches!(
            guest_setup(&dir, None, Instant::now() + Duration::from_millis(50)),
            Err(SetupError::Unsupported)
        ));
    }
}

#[cfg(test)]
mod prefault_tests {
    use super::{
        MemoryRange, PREFAULT_STRIDE, mask_hole_residency, populate_read, prefault_targets,
        resident_pages, snapshot_memory_ranges,
    };

    #[test]
    fn cached_holes_are_not_prefault_targets() {
        use std::os::unix::fs::FileExt;
        let path =
            std::env::temp_dir().join(format!("shinu-prefault-hole-{}", uuid::Uuid::new_v4()));
        let file = std::fs::File::create_new(&path).unwrap();
        file.set_len(3 * PREFAULT_STRIDE).unwrap();
        file.write_all_at(&[1], PREFAULT_STRIDE).unwrap();
        file.sync_all().unwrap();
        let page = super::page_size();
        let mut resident = vec![1; (3 * PREFAULT_STRIDE / page) as usize];
        mask_hole_residency(&file, page, &mut resident).unwrap();
        let range = MemoryRange {
            start: 0,
            end: 3 * PREFAULT_STRIDE,
            offset: 0,
        };
        assert_eq!(
            prefault_targets(&[range], &resident, page),
            [PREFAULT_STRIDE]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn only_private_snapshot_file_mappings_are_guest_memory() {
        let maps = "\
7f102da00000-7f116da00000 rw-p c0000000 00:1f 7497875                    /snap.mem (deleted)
7f116da00000-7f122da00000 rw-p 00000000 00:1f 7497875                    /snap.mem (deleted)
7f122da00000-7f122da01000 rw-s 00000000 00:1f 7497876                    /snap.mem
7f122da01000-7f122da02000 r--p 00000000 00:1f 7497877                    /snap.mem.old
7f122da02000-7f122da03000 rw-p 00000000 00:1f 7497878                    /x/snap.mem
7f122da03000-7f122da04000 rw-p 00000000 00:00 0
7f122da04000-7f122da05000 r--p 00001000 00:1f 7497879                    /snap.mem
";
        let range = |start, end, offset| MemoryRange { start, end, offset };
        assert_eq!(
            snapshot_memory_ranges(maps),
            [
                range(0x7f10_2da0_0000, 0x7f11_6da0_0000, 0xc000_0000),
                range(0x7f11_6da0_0000, 0x7f12_2da0_0000, 0),
                range(0x7f12_2da0_4000, 0x7f12_2da0_5000, 0x1000)
            ]
        );
    }

    #[test]
    fn targets_follow_file_offsets_and_skip_uncached_windows() {
        const PAGE: u64 = 4096;
        let pages = usize::try_from(PREFAULT_STRIDE / PAGE).unwrap();
        // File windows: 0 uncached, 1 cached at its third page, 2 cached.
        let mut resident = vec![0_u8; pages * 3];
        resident[pages + 2] = 1;
        resident[pages * 2] = 1;
        let base = 0x10_0000_0000;
        let ranges = [
            // Guest region mapping file windows 1..3 first, then window 0.
            MemoryRange {
                start: base,
                end: base + 2 * PREFAULT_STRIDE,
                offset: PREFAULT_STRIDE,
            },
            MemoryRange {
                start: base + 4 * PREFAULT_STRIDE,
                end: base + 5 * PREFAULT_STRIDE,
                offset: 0,
            },
        ];
        assert_eq!(
            prefault_targets(&ranges, &resident, PAGE),
            [base + 2 * PAGE, base + PREFAULT_STRIDE]
        );
        // A residency vector shorter than the mapping never indexes past it.
        assert!(prefault_targets(&ranges, &[], PAGE).is_empty());
    }

    fn smaps_field(address: usize, field: &str) -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, _)) = range.split_once('-')
                && start.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                inside = usize::from_str_radix(start, 16) == Ok(address);
            } else if inside && let Some(value) = line.strip_prefix(field) {
                return value
                    .trim_start_matches(':')
                    .trim()
                    .trim_end_matches(" kB")
                    .parse()
                    .unwrap();
            }
        }
        panic!("mapping {address:#x} has no {field}");
    }

    #[test]
    fn populate_maps_page_cache_read_only_without_private_memory() {
        use std::os::fd::AsRawFd;
        unsafe extern "C" {
            fn mmap(
                address: usize,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> usize;
            fn munmap(address: usize, length: usize) -> i32;
        }
        const LENGTH: usize = 8 << 20;
        // A disk filesystem like the checkpoint store: tmpfs pages are always
        // dirty, which smaps would report as Private_Dirty without any CoW.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(".shinu-prefault-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, vec![7_u8; LENGTH]).unwrap();
        std::fs::File::open(&path).unwrap().sync_all().unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: fresh PROT_READ|PROT_WRITE MAP_PRIVATE mapping of a live file.
        let address = unsafe { mmap(0, LENGTH, 1 | 2, 2, file.as_raw_fd(), 0) };
        assert_ne!(address, usize::MAX);
        assert_eq!(smaps_field(address, "Rss"), 0);
        let page = super::page_size();
        let resident = resident_pages(&file, page).unwrap();
        assert!(resident.iter().all(|state| state & 1 != 0));
        let range = MemoryRange {
            start: address as u64,
            end: (address + LENGTH) as u64,
            offset: 0,
        };
        let targets = prefault_targets(&[range], &resident, page);
        assert_eq!(targets.len() as u64, LENGTH as u64 / PREFAULT_STRIDE);
        populate_read(std::process::id(), &targets).unwrap();
        // Fault-around may stop at page-cache folio boundaries; most pages map.
        assert!(smaps_field(address, "Rss") >= (LENGTH as u64 >> 10) / 2);
        assert_eq!(smaps_field(address, "Anonymous"), 0);
        assert_eq!(smaps_field(address, "Private_Dirty"), 0);
        assert_eq!(
            smaps_field(address, "Rss"),
            smaps_field(address, "Private_Clean") + smaps_field(address, "Shared_Clean")
        );
        // SAFETY: unmaps exactly the mapping created above.
        assert_eq!(unsafe { munmap(address, LENGTH) }, 0);
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod tap_tests {
    use super::{VmConfig, claim_tap_file, prepare_tap};
    use std::os::unix::{fs::MetadataExt, process::ExitStatusExt};
    use std::path::PathBuf;

    const TAP: &str = "shinu0123456789";

    struct Host {
        root: PathBuf,
        config: VmConfig,
        commands: Vec<Vec<String>>,
        collision: &'static str,
    }

    impl Host {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("shinu-tap-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("sys")).unwrap();
            std::fs::create_dir_all(root.join("proc")).unwrap();
            Self {
                root,
                config: VmConfig {
                    vcpus: 1,
                    mem_mib: 64,
                    idle_secs: 60,
                    idle_reclaim: false,
                    jail_uid: 31003,
                    jail_gid: 32007,
                },
                commands: Vec::new(),
                collision: "Device or resource busy",
            }
        }

        fn owners(&self, uid: i64, gid: i64) {
            let tap = self.root.join("sys").join(TAP);
            std::fs::create_dir_all(&tap).unwrap();
            std::fs::write(tap.join("owner"), format!("{uid}\n")).unwrap();
            std::fs::write(tap.join("group"), format!("{gid}\n")).unwrap();
        }

        fn hold(&self, tap: &str) {
            let info = self.root.join("proc/42/fdinfo");
            std::fs::create_dir_all(&info).unwrap();
            std::fs::write(
                info.join("7"),
                format!("pos:\t0\nflags:\t0100002\niff:\t{tap}\n"),
            )
            .unwrap();
        }

        fn prepare(&mut self) -> shinu_core::Result<()> {
            let sys = self.root.join("sys");
            prepare_tap(TAP, &self.config, &sys, &self.root.join("proc"), |args| {
                self.commands
                    .push(args.iter().map(|arg| (*arg).to_owned()).collect());
                let collision = args.starts_with(&["tuntap", "add"]) && sys.join(TAP).exists();
                if args.starts_with(&["link", "delete"]) {
                    std::fs::remove_dir_all(sys.join(TAP)).unwrap();
                }
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(if collision { 256 } else { 0 }),
                    stdout: Vec::new(),
                    stderr: if collision {
                        self.collision.as_bytes().to_vec()
                    } else {
                        Vec::new()
                    },
                })
            })
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn fresh_tap_is_owned_by_configured_jail_identity() {
        let mut host = Host::new();
        std::fs::remove_dir(host.root.join("proc")).unwrap();
        std::fs::write(host.root.join("proc"), b"new TAP must not inspect procfs").unwrap();
        host.prepare().unwrap();
        assert_eq!(
            host.commands,
            [vec![
                "tuntap", "add", "dev", TAP, "mode", "tap", "user", "31003", "group", "32007"
            ]]
        );
    }

    #[test]
    fn unused_legacy_tap_is_rebuilt_unless_both_owners_match() {
        for (uid, gid) in [(-1, -1), (31003, -1), (-1, 32007), (123, 456)] {
            let mut host = Host::new();
            host.owners(uid, gid);
            host.hold("other-tap");
            host.prepare().unwrap();
            assert_eq!(
                host.commands,
                [
                    vec![
                        "tuntap", "add", "dev", TAP, "mode", "tap", "user", "31003", "group",
                        "32007"
                    ],
                    vec!["link", "delete", "dev", TAP],
                    vec![
                        "tuntap", "add", "dev", TAP, "mode", "tap", "user", "31003", "group",
                        "32007"
                    ]
                ]
            );
        }
        let mut host = Host::new();
        host.owners(31003, 32007);
        host.prepare().unwrap();
        assert_eq!(host.commands.len(), 1);
    }

    #[test]
    fn occupied_tap_is_rejected_without_mutation_even_with_matching_owners() {
        for (uid, gid) in [(-1, -1), (31003, 32007)] {
            let mut host = Host::new();
            host.owners(uid, gid);
            host.hold(TAP);
            let error = host.prepare().unwrap_err();
            assert!(error.to_string().contains("in use"), "{error}");
            assert!(matches!(error, shinu_core::Error::TapBusy(_)));
            assert_eq!(host.commands.len(), 1);
        }
    }

    #[test]
    fn incomplete_holder_inspection_cannot_delete_a_legacy_tap() {
        let mut host = Host::new();
        host.owners(-1, -1);
        std::fs::create_dir_all(host.root.join("proc/42")).unwrap();
        std::fs::write(
            host.root.join("proc/42/fdinfo"),
            b"not a readable directory",
        )
        .unwrap();
        assert!(host.prepare().is_err());
        assert_eq!(host.commands.len(), 1);
    }

    #[test]
    fn file_exists_collision_rebuilds_an_unowned_tap() {
        let mut host = Host::new();
        host.collision = "File exists";
        host.owners(-1, -1);
        host.prepare().unwrap();
        assert_eq!(host.commands.len(), 3);
        assert_eq!(host.commands[1], ["link", "delete", "dev", TAP]);
    }

    #[test]
    fn tap_claim_stays_linked_and_serializes_separate_open_file_descriptions() {
        let host = Host::new();
        let path = host.root.join("tap.lock");
        let first = claim_tap_file(&path, TAP).unwrap();
        let inode = first.metadata().unwrap().ino();
        assert!(matches!(
            claim_tap_file(&path, TAP),
            Err(shinu_core::Error::TapBusy(_))
        ));
        drop(first);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        let next = claim_tap_file(&path, TAP).unwrap();
        assert_eq!(next.metadata().unwrap().ino(), inode);
        assert_eq!(next.metadata().unwrap().len(), 0);
        drop(next);
        assert!(
            path.exists(),
            "releasing a claim must never unlink its lock inode"
        );
    }
}

#[cfg(test)]
mod lifecycle_ledger_tests {
    //! Host-crash recovery is simulated by writing exactly the on-disk record a
    //! power loss could leave behind, then running the real recovery path. A
    //! fixed foreign boot id stands in for the boot before the crash.
    use super::{
        host_boot_id, ledger_journal, mark_pending, recover_loaded, resume, settle_before_start,
        settle_pending, start, write_phase,
    };
    use crate::{NetConfig, VmConfig};
    use shinu_core::{Image, space_image, vm_dir};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use uuid::Uuid;

    const OLD_BOOT: &str = "00000000-0000-4000-8000-0000000000b0";

    struct Space {
        root: PathBuf,
        id: Uuid,
        dir: PathBuf,
        memory: PathBuf,
        state: PathBuf,
        child: Option<Child>,
    }

    impl Space {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("shinu-ledger-{}", Uuid::new_v4()));
            let id = Uuid::new_v4();
            let dir = vm_dir(&root, id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::create_dir_all(root.join("spaces")).unwrap();
            let image = space_image(&root, id);
            std::fs::write(&image, b"disk").unwrap();
            let memory = image.with_extension("mem");
            let state = image.with_extension("state");
            std::fs::write(&memory, b"pending memory").unwrap();
            std::fs::write(&state, b"pending state").unwrap();
            Self {
                root,
                id,
                dir,
                memory,
                state,
                child: None,
            }
        }

        fn marker(&self, phase: &str, boot_id: &str) {
            self.raw_marker(
                format!("{{\"phase\":\"{phase}\",\"boot_id\":\"{boot_id}\"}}").as_bytes(),
            );
        }

        fn raw_marker(&self, bytes: &[u8]) {
            std::fs::write(self.dir.join("loaded.json"), bytes).unwrap();
        }

        fn pending(&self) -> bool {
            assert_eq!(self.memory.exists(), self.state.exists());
            self.memory.exists()
        }

        /// A live stand-in VMM recognised by the real process identity checks.
        fn spawn_vmm(&mut self) {
            let config = super::config_path(&self.dir);
            std::fs::create_dir_all(config.parent().unwrap()).unwrap();
            std::fs::write(&config, "{}").unwrap();
            let fake = self.root.join("firecracker");
            std::os::unix::fs::symlink("/usr/bin/yes", &fake).unwrap();
            let child = Command::new(&fake)
                .arg(&config)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            std::fs::write(super::pid_path(&self.dir), child.id().to_string()).unwrap();
            while !super::is_running(&self.dir) {
                std::thread::yield_now();
            }
            self.child = Some(child);
        }

        fn index(events: &[String], wanted: &str) -> usize {
            events
                .iter()
                .position(|event| event == wanted)
                .unwrap_or_else(|| panic!("missing {wanted:?} in {events:#?}"))
        }
    }

    impl Drop for Space {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn net() -> NetConfig {
        NetConfig {
            enabled: false,
            base: [172, 30],
            allow: Vec::new(),
            host_allow: Vec::new(),
            uplink: "unused".into(),
        }
    }

    #[test]
    fn recovery_keeps_pending_memory_only_under_a_never_run_record_of_this_boot() {
        let boot = host_boot_id().unwrap().to_string();
        // (record left on disk, pending memory survives recovery)
        for (phase, boot_id, survives) in [
            ("pending", boot.as_str(), true),
            ("loading", boot.as_str(), true),
            ("loaded", boot.as_str(), true),
            ("pending", OLD_BOOT, false),
            ("loading", OLD_BOOT, false),
            ("loaded", OLD_BOOT, false),
            ("resuming", boot.as_str(), false),
            ("resuming", OLD_BOOT, false),
            ("running", boot.as_str(), false),
            ("loaded", "not-a-uuid", false),
        ] {
            let space = Space::new();
            space.marker(phase, boot_id);
            recover_loaded(&space.root, &net()).unwrap();
            assert_eq!(space.pending(), survives, "{phase} {boot_id}");
            assert_eq!(super::lifecycle_state(&space.dir).unwrap(), "stopped");
            // Kept memory is re-recorded as pending for this boot; consumed
            // memory leaves no record behind.
            assert_eq!(space.dir.join("loaded.json").exists(), survives);
        }
    }

    #[test]
    fn missing_invalid_and_pre_upgrade_records_consume_pending_memory() {
        for marker in [
            None,
            Some(&b""[..]),
            Some(&b"{\"phase\":\"load"[..]),
            // Records written before boot ids existed.
            Some(&b"{\"phase\":\"loaded\"}"[..]),
            Some(&b"{\"phase\":\"loading\"}"[..]),
        ] {
            let space = Space::new();
            if let Some(marker) = marker {
                space.raw_marker(marker);
            }
            recover_loaded(&space.root, &net()).unwrap();
            assert!(!space.pending(), "{marker:?}");
            assert!(!space.dir.join("loaded.json").exists());
        }
    }

    #[test]
    fn a_pre_upgrade_fork_without_a_record_is_consumed_on_restart() {
        // Old versions materialized pending files without any record.
        let space = Space::new();
        assert!(!space.dir.join("loaded.json").exists());
        recover_loaded(&space.root, &net()).unwrap();
        assert!(!space.pending());
    }

    #[test]
    fn a_freshly_written_record_from_the_previous_boot_is_consumed() {
        // Written just before the crash, so it reached the disk with its
        // current content, but it names the boot that crashed.
        let space = Space::new();
        mark_pending(&space.dir).unwrap();
        let fresh = std::fs::read_to_string(space.dir.join("loaded.json")).unwrap();
        let boot = host_boot_id().unwrap().to_string();
        assert!(fresh.contains(&boot), "{fresh}");
        space.raw_marker(fresh.replace(&boot, OLD_BOOT).as_bytes());
        recover_loaded(&space.root, &net()).unwrap();
        assert!(!space.pending());
    }

    #[test]
    fn consumed_records_stay_consumed_and_cleared_records_never_resurrect_memory() {
        // Consumed: the pending files are gone; recovery just clears the record.
        let space = Space::new();
        std::fs::remove_file(&space.memory).unwrap();
        std::fs::remove_file(&space.state).unwrap();
        space.marker("resuming", &host_boot_id().unwrap().to_string());
        recover_loaded(&space.root, &net()).unwrap();
        assert!(!space.pending());
        assert!(!space.dir.join("loaded.json").exists());
        recover_loaded(&space.root, &net()).unwrap();
        assert!(!space.pending());
    }

    #[test]
    fn crash_after_a_successful_resume_leaves_no_reloadable_memory() {
        let space = Space::new();
        mark_pending(&space.dir).unwrap();
        write_phase(&space.dir, "resuming").unwrap();
        // Success settles the generation: memory consumed, record cleared.
        settle_pending(&space.dir).unwrap();
        assert!(!space.pending());
        // Power loss may undo any of that. Whatever survives names the old
        // boot, or is missing, and is consumed either way.
        for phase in ["pending", "loaded", "resuming"] {
            std::fs::write(&space.memory, b"pending memory").unwrap();
            std::fs::write(&space.state, b"pending state").unwrap();
            space.marker(phase, OLD_BOOT);
            recover_loaded(&space.root, &net()).unwrap();
            assert!(!space.pending(), "{phase}");
        }
    }

    #[test]
    fn records_are_renamed_into_place_without_any_fsync() {
        let space = Space::new();
        ledger_journal::take();
        for phase in ["pending", "loading", "loaded", "resuming"] {
            write_phase(&space.dir, phase).unwrap();
        }
        settle_pending(&space.dir).unwrap();
        let events = ledger_journal::take();
        assert!(
            events.iter().all(|event| !event.starts_with("sync")),
            "{events:#?}"
        );
        assert_eq!(
            events,
            ["pending", "loading", "loaded", "resuming"].map(|phase| format!("rename {phase}"))
        );
    }

    #[test]
    fn settling_before_a_start_leaves_a_live_pool_generation_alone() {
        let mut space = Space::new();
        space.spawn_vmm();
        space.marker("loaded", &host_boot_id().unwrap().to_string());
        settle_before_start(&space.dir, &net()).unwrap();
        assert!(super::is_running(&space.dir));
        assert_eq!(super::lifecycle_state(&space.dir).unwrap(), "loaded");
        assert!(space.pending());
    }

    #[test]
    fn resume_records_resuming_before_patching_vcpus_running() {
        let mut space = Space::new();
        space.spawn_vmm();
        space.marker("loaded", &host_boot_id().unwrap().to_string());
        ledger_journal::take();
        // The stand-in has no API socket, so PATCH fails after being attempted.
        assert!(resume(&space.root, space.id, None, &net(), |_| Ok(())).is_err());
        let events = ledger_journal::take();
        let recorded = Space::index(&events, "rename resuming");
        let patched = Space::index(&events, "api PATCH /vm");
        assert!(recorded < patched, "{events:#?}");
        // Failure after vCPUs may have run consumes the pending memory.
        assert!(!space.pending());
    }

    #[test]
    fn direct_restore_records_resuming_before_launching_the_vmm() {
        let space = Space::new();
        mark_pending(&space.dir).unwrap();
        let assets = space.root.join("assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(assets.join("vmlinux"), b"kernel").unwrap();
        for name in ["jailer", "firecracker"] {
            let path = assets.join(name);
            std::fs::write(&path, "#!/bin/sh\nexit 1\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let files = super::RestoreFiles {
            mem: &space.memory,
            state: &space.state,
            guest_snapshot_nonce: None,
            anon_holes: false,
        };
        let cfg = VmConfig {
            vcpus: 1,
            mem_mib: 64,
            idle_secs: 3600,
            idle_reclaim: false,
            jail_uid: 30000,
            jail_gid: 30000,
        };
        ledger_journal::take();
        let result = start(
            &space.root,
            space.id,
            Image::Void,
            super::StartOptions {
                restore: Some(&files),
                ..super::StartOptions::default()
            },
            &cfg,
            &net(),
            |_| Ok(()),
        );
        assert!(result.is_err());
        let events = ledger_journal::take();
        // resume_vm=true: vCPUs may run once the VMM receives the load request.
        let recorded = Space::index(&events, "rename resuming");
        let launched = Space::index(&events, "launch");
        assert!(recorded < launched, "{events:#?}");
        assert!(!events.iter().any(|event| event.starts_with("api ")));
        assert!(!space.pending());
    }
}

#[cfg(test)]
mod ready_probe_tests {
    //! The real readiness wait against a fake vsock bridge that counts
    //! connections, so a dropped-and-redone sshd fork is visible.
    use super::wait_ready_observed;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    /// How the guest bridge treats one accepted connection.
    #[derive(Clone, Copy)]
    enum Guest {
        /// Accepts CONNECT, then sends the SSH banner after this delay.
        Banner(Duration),
        /// Refuses CONNECT for the first `n` connections, then banners at once.
        RefuseFirst(usize),
    }

    struct Bridge {
        root: PathBuf,
        dir: PathBuf,
        vsock: PathBuf,
        child: Child,
        connections: Arc<AtomicUsize>,
        stopped: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl Bridge {
        fn new(guest: Guest) -> Self {
            let root = std::env::temp_dir()
                .join(format!("rp-{}", &Uuid::new_v4().simple().to_string()[..8]));
            let id = Uuid::new_v4();
            let dir = shinu_core::vm_dir(&root, id);
            std::fs::create_dir_all(&dir).unwrap();
            // A live stand-in VMM recognised by the real process identity check.
            let config = super::config_path(&dir);
            std::fs::create_dir_all(config.parent().unwrap()).unwrap();
            std::fs::write(&config, "{}").unwrap();
            let fake = root.join("firecracker");
            std::os::unix::fs::symlink("/usr/bin/yes", &fake).unwrap();
            let child = Command::new(&fake)
                .arg(&config)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            std::fs::write(super::pid_path(&dir), child.id().to_string()).unwrap();
            while !super::is_running(&dir) {
                std::thread::yield_now();
            }
            let vsock = super::vsock_path(&dir);
            let listener = UnixListener::bind(&vsock).unwrap();
            listener.set_nonblocking(true).unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let stopped = Arc::new(AtomicBool::new(false));
            let worker = {
                let connections = Arc::clone(&connections);
                let stopped = Arc::clone(&stopped);
                std::thread::spawn(move || {
                    while !stopped.load(Ordering::SeqCst) {
                        let Ok((mut stream, _)) = listener.accept() else {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        };
                        let index = connections.fetch_add(1, Ordering::SeqCst);
                        std::thread::spawn(move || {
                            stream.set_nonblocking(false).unwrap();
                            let mut line = String::new();
                            let _ =
                                BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
                            assert_eq!(line, "CONNECT 2222\n");
                            match guest {
                                Guest::RefuseFirst(refused) if index < refused => {}
                                Guest::RefuseFirst(_) => {
                                    let _ = stream.write_all(b"OK 1\nSSH-2.0-fake\n");
                                }
                                Guest::Banner(delay) => {
                                    let _ = stream.write_all(b"OK 1\n");
                                    std::thread::sleep(delay);
                                    let _ = stream.write_all(b"SSH-2.0-fake\n");
                                }
                            }
                        });
                    }
                })
            };
            Self {
                root,
                dir,
                vsock,
                child,
                connections,
                stopped,
                worker: Some(worker),
            }
        }

        fn wait(&self) -> (bool, Vec<(usize, bool)>) {
            let mut probes = Vec::new();
            let ready = wait_ready_observed(&self.dir, &self.vsock, |attempt, _, ok| {
                probes.push((attempt, ok));
            });
            (ready, probes)
        }
    }

    impl Drop for Bridge {
        fn drop(&mut self) {
            self.stopped.store(true, Ordering::SeqCst);
            self.worker.take().unwrap().join().unwrap();
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_slow_banner_on_an_accepted_connection_is_awaited_not_redialled() {
        let bridge = Bridge::new(Guest::Banner(Duration::from_millis(800)));
        let started = Instant::now();
        let (ready, probes) = bridge.wait();
        assert!(ready);
        assert_eq!(probes, [(1, true)], "one sshd fork, no redial");
        assert_eq!(bridge.connections.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() >= Duration::from_millis(800));
    }

    #[test]
    fn refused_connects_are_still_retried_until_the_banner_arrives() {
        let bridge = Bridge::new(Guest::RefuseFirst(3));
        let (ready, probes) = bridge.wait();
        assert!(ready);
        assert_eq!(probes, [(1, false), (2, false), (3, false), (4, true)]);
        assert_eq!(bridge.connections.load(Ordering::SeqCst), 4);
    }
}
