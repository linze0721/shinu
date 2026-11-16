//! Guest-only static snapshot control and authenticated, argv-only readiness.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const u8, length: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept4(fd: i32, address: *mut u8, length: *mut u32, flags: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const i64, length: u32) -> i32;
    fn mlockall(flags: i32) -> i32;
    fn setpriority(which: i32, who: u32, priority: i32) -> i32;
    fn setrlimit(resource: i32, limits: *const u64) -> i32;
    fn flock(fd: i32, operation: i32) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn alarm(seconds: u32) -> u32;
    fn poll(descriptors: *mut PollDescriptor, count: usize, timeout_ms: i32) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}

#[repr(C)]
struct VsockAddress {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    flags: u8,
    zero: [u8; 3],
}

#[repr(C)]
struct PollDescriptor {
    fd: i32,
    events: i16,
    returned: i16,
}

const SOCKET_CLOEXEC: i32 = 0x80000;
const SOCKET_NONBLOCK: i32 = 0x800;

fn checked(value: i32) -> std::io::Result<i32> {
    if value < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn lock(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let deadline = Instant::now() + Duration::from_secs(115);
    loop {
        // SAFETY: file owns this descriptor; flock uses no pointer arguments.
        if unsafe { flock(file.as_raw_fd(), 2 | 4) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock || Instant::now() >= deadline {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn mount_files(ledger: &Path) -> std::io::Result<Vec<File>> {
    match std::fs::read_to_string(ledger) {
        Ok(paths) => paths.lines().map(File::open).collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn thaw(state: &Path, mounts: &mut Vec<File>) -> std::io::Result<()> {
    let ledger = state.with_file_name("shinu-freeze");
    if !ledger.exists() {
        mounts.clear();
        return Ok(());
    }
    if mounts.is_empty() {
        *mounts = mount_files(&ledger.join("mounts"))?;
    }
    let mut failed = false;
    for mount in mounts.iter() {
        // A wedged ioctl terminates this worker after ten seconds; the host
        // then uses the independent SSH thaw adapter against the same ledger.
        // No hook child exists while the alarm is armed.
        // SAFETY: FITHAW takes an owned filesystem descriptor and no data pointer.
        let error = unsafe {
            alarm(10);
            let result = ioctl(mount.as_raw_fd(), 0xc004_5878_u64, 0);
            let error = (result != 0).then(std::io::Error::last_os_error);
            alarm(0);
            error
        };
        if error.is_some_and(|error| error.raw_os_error() != Some(22)) {
            failed = true;
        }
    }
    if failed {
        return Err(std::io::Error::other("snapshot thaw failed"));
    }
    std::fs::remove_dir_all(ledger)?;
    mounts.clear();
    Ok(())
}

struct SnapshotPaths<'a> {
    state: &'a Path,
    proc_root: &'a Path,
    block_root: &'a Path,
}

fn writable_block_mounts<'a>(
    contents: &'a str,
    block_root: &Path,
    mut visit: impl FnMut(&'a str, &'a str, &'a str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let invalid = || std::io::Error::other("invalid guest mountinfo");
    for line in contents.lines() {
        let (mount, filesystem) = line.split_once(" - ").ok_or_else(invalid)?;
        let mut fields = mount.split_whitespace();
        fields.next().ok_or_else(invalid)?;
        fields.next().ok_or_else(invalid)?;
        let device = fields.next().ok_or_else(invalid)?;
        fields.next().ok_or_else(invalid)?;
        let target = fields.next().ok_or_else(invalid)?;
        let options = fields.next().ok_or_else(invalid)?;
        let mut fields = filesystem.split_whitespace();
        let kind = fields.next().ok_or_else(invalid)?;
        fields.next().ok_or_else(invalid)?;
        let super_options = fields.next().ok_or_else(invalid)?;
        if !options.split(',').any(|option| option == "rw")
            || !super_options.split(',').any(|option| option == "rw")
        {
            continue;
        }
        let (major, minor) = device.split_once(':').ok_or_else(invalid)?;
        let major = major.parse::<u32>().map_err(|_| invalid())?;
        minor.parse::<u32>().map_err(|_| invalid())?;
        // Multi-device/userspace block filesystems may use anonymous st_dev
        // numbers. Ordinary block devices must be visible in sysfs; losing that
        // visibility is an error, not permission to omit a writable filesystem.
        let block_backed = if matches!(kind, "btrfs" | "bcachefs" | "zfs" | "fuseblk") {
            true
        } else if major != 0 {
            std::fs::metadata(block_root.join(device)).map_err(|error| {
                std::io::Error::other(format!("cannot inspect block filesystem {device}: {error}"))
            })?;
            true
        } else {
            false
        };
        if block_backed {
            if target.contains('\\') {
                return Err(std::io::Error::other(
                    "escaped block mount paths are unsupported",
                ));
            }
            visit(device, kind, target)?;
        }
    }
    Ok(())
}

fn freeze_mount_catalog(paths: &SnapshotPaths<'_>) -> std::io::Result<String> {
    if !std::fs::metadata(paths.block_root)?.is_dir() {
        return Err(std::io::Error::other(
            "guest block-device sysfs is unavailable",
        ));
    }
    let initial = paths.proc_root.join("1");
    let initial_namespace = std::fs::metadata(initial.join("ns/mnt"))?.ino();
    if std::fs::metadata(paths.proc_root.join("self/ns/mnt"))?.ino() != initial_namespace {
        return Err(std::io::Error::other(
            "snapshot helper is outside the initial mount namespace",
        ));
    }
    let initial_mounts = std::fs::read_to_string(initial.join("mountinfo"))?;
    let mut planned = BTreeMap::new();
    writable_block_mounts(&initial_mounts, paths.block_root, |device, _, target| {
        let current = planned.entry(device).or_insert(target);
        if target.len() < current.len() {
            *current = target;
        }
        Ok(())
    })?;
    let mut namespaces = BTreeSet::from([initial_namespace]);
    for process in std::fs::read_dir(paths.proc_root)? {
        let process = process?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let namespace = match std::fs::metadata(process.path().join("ns/mnt")) {
            Ok(metadata) => metadata.ino(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if namespaces.contains(&namespace) {
            continue;
        }
        let mounts = match std::fs::read_to_string(process.path().join("mountinfo")) {
            Ok(mounts) => mounts,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        writable_block_mounts(&mounts, paths.block_root, |device, kind, _| {
            if !planned.contains_key(device) {
                return Err(std::io::Error::other(format!(
                    "unsupported private writable block filesystem {device} ({kind})"
                )));
            }
            Ok(())
        })?;
        namespaces.insert(namespace);
    }
    let mut catalog = String::new();
    for (device, target) in planned {
        catalog.push_str(device);
        catalog.push(' ');
        catalog.push_str(target);
        catalog.push('\n');
    }
    Ok(catalog)
}

// Only use this around native stages with no script children: a deadline must
// never kill the lock owner while leaving an unfenced late freeze behind.
fn native_stage<T>(
    deadline: Instant,
    work: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let seconds = u32::try_from(deadline.saturating_duration_since(Instant::now()).as_secs())
        .map_err(|_| std::io::Error::other("snapshot deadline out of range"))?;
    if seconds == 0 {
        return Err(std::io::Error::other("snapshot native stage timed out"));
    }
    // SAFETY: alarm takes an unsigned scalar and terminates only this worker.
    unsafe {
        alarm(seconds);
    }
    let result = work();
    unsafe {
        alarm(0);
    }
    result
}

// The monitored script group, not the resident process, inherits the flock.
// Nested timeout groups retain it until their bounded descendants exit. If
// cleanup wins before the monitor locks, phase/nonce checks cancel the script.
fn snapshot_script(
    paths: &SnapshotPaths<'_>,
    action: &str,
    nonce: &str,
    deadline: Instant,
) -> std::io::Result<()> {
    let phase = match action {
        "freeze" => "freezing",
        "thaw" => "thawed",
        _ => return Err(std::io::Error::other("invalid snapshot script")),
    };
    let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
    if remaining == 0 {
        return Err(std::io::Error::other("snapshot operation timed out"));
    }
    let budget = remaining.to_string();
    let guard = "[ \"$SHINU_SNAPSHOT_NONCE\" = \"$(cat \"$1/nonce\")\" ] && [ \"$2\" = \"$(cat \"$1/phase\")\" ] || exit 1; unset SHINU_SNAPSHOT_NONCE; exec sh \"$1/$3.sh\" \"$4\" /etc/shinu/freeze.d \"$1/mounts\"";
    let status = Command::new("timeout")
        .args(["-k", "5", &budget, "flock", "-F", "-w", &budget])
        .arg(paths.state.with_extension("lock"))
        .args(["sh", "-c", guard, "shinu-snapshot"])
        .arg(paths.state)
        .arg(phase)
        .arg(action)
        .arg(paths.state.with_file_name("shinu-freeze"))
        // Root's environment is private; never expose the nonce in argv, and
        // remove it before executing application hooks.
        .env("SHINU_SNAPSHOT_NONCE", nonce)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "snapshot {action} script failed: {status}"
        )));
    }
    Ok(())
}

fn operation(
    paths: &SnapshotPaths<'_>,
    request: &str,
    mounts: &mut Vec<File>,
    held: bool,
) -> std::io::Result<bool> {
    let state = paths.state;
    let mut words = request.split_whitespace();
    let action = words.next().unwrap_or_default();
    let nonce = words.next().unwrap_or_default();
    let next = words.next();
    if words.next().is_some()
        || !valid_nonce(nonce)
        || !matches!(action, "status" | "freeze" | "thaw")
        || (held && action != "thaw")
    {
        return Err(std::io::Error::other("invalid snapshot request"));
    }
    let mut guard = Some(lock(&state.with_extension("lock"))?);
    if nonce != std::fs::read_to_string(state.join("nonce"))? {
        return Err(std::io::Error::other("snapshot authentication failed"));
    }
    match action {
        "status" => {
            if next == Some("hold") {
                if std::fs::read_to_string(state.join("phase"))? != "frozen" {
                    return Err(std::io::Error::other(
                        "thaw connection requires a frozen generation",
                    ));
                }
                return Ok(true);
            }
            if let Some(next) = next {
                if !valid_nonce(next) || next == nonce {
                    return Err(std::io::Error::other("invalid snapshot nonce rotation"));
                }
                std::fs::write(state.join("nonce.next"), next)?;
                std::fs::rename(state.join("nonce.next"), state.join("nonce"))?;
                std::fs::write(state.join("phase"), "ready")?;
            }
        }
        "freeze" => {
            if next.is_some() || std::fs::read_to_string(state.join("phase"))? != "ready" {
                return Err(std::io::Error::other("snapshot freeze replay"));
            }
            let deadline = Instant::now() + Duration::from_secs(110);
            let catalog = native_stage(deadline, || freeze_mount_catalog(paths))?;
            std::fs::write(state.join("mounts"), &catalog)?;
            std::fs::write(state.join("phase"), "freezing")?;
            mounts.clear();
            drop(guard.take());
            snapshot_script(paths, "freeze", nonce, deadline)?;
            let _relocked = lock(&state.with_extension("lock"))?;
            if std::fs::read_to_string(state.join("nonce"))? != nonce
                || std::fs::read_to_string(state.join("phase"))? != "freezing"
            {
                return Err(std::io::Error::other(
                    "snapshot freeze was cancelled by cleanup",
                ));
            }
            *mounts = mount_files(&state.with_file_name("shinu-freeze").join("mounts"))?;
            let verified = native_stage(deadline, || freeze_mount_catalog(paths))?;
            if verified != catalog {
                return Err(std::io::Error::other(
                    "mount catalog changed during snapshot freeze",
                ));
            }
            std::fs::write(state.join("phase"), "frozen")?;
        }
        "thaw" => {
            if next.is_some() {
                return Err(std::io::Error::other("invalid thaw request"));
            }
            std::fs::write(state.join("phase"), "thawed")?;
            let ledger = state.with_file_name("shinu-freeze");
            let has_hooks = match std::fs::read_to_string(ledger.join("hooks")) {
                Ok(hooks) => !hooks.is_empty(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !ledger.exists() => {
                    false
                }
                Err(error) => return Err(error),
            };
            if has_hooks {
                drop(guard.take());
                snapshot_script(
                    paths,
                    "thaw",
                    nonce,
                    Instant::now() + Duration::from_secs(110),
                )?;
                mounts.clear();
            } else {
                thaw(state, mounts)?;
            }
        }
        _ => unreachable!(),
    }
    Ok(false)
}

fn read_timeout(stream: &File, seconds: i64) -> std::io::Result<()> {
    let timeout = [seconds, 0];
    // SAFETY: timeout is a Linux timeval on supported 64-bit guest architectures.
    unsafe {
        checked(setsockopt(stream.as_raw_fd(), 1, 20, timeout.as_ptr(), 16))?;
    }
    Ok(())
}

// A readiness transaction is never satisfied by resident/captured state. Each
// authenticated request runs argv again and only that command can emit READY.
fn readiness_request(
    stream: &File,
    paths: &SnapshotPaths<'_>,
    request: &str,
) -> std::io::Result<String> {
    let mut words = request.splitn(4, ' ');
    let action = words.next().unwrap_or_default();
    let nonce = words.next().unwrap_or_default();
    let _guard = lock(&paths.state.with_extension("lock"))?;
    if !valid_nonce(nonce) || nonce != std::fs::read_to_string(paths.state.join("nonce"))? {
        return Err(std::io::Error::other("ready-authentication"));
    }
    if action == "capabilities" && words.next().is_none() {
        return Ok("READY-1".into());
    }
    let restore_id = words.next().unwrap_or_default();
    let policy = words.next().unwrap_or_default();
    if action != "ready" || !valid_nonce(restore_id) || restore_id == nonce {
        return Err(std::io::Error::other("ready-request"));
    }
    let spec: shinu_core::ReadySpec =
        serde_json::from_str(policy).map_err(|_| std::io::Error::other("ready-policy"))?;
    if !matches!(
        std::fs::read_to_string(paths.state.join("phase"))?.as_str(),
        "thawed" | "ready"
    ) {
        return Err(std::io::Error::other("ready-before-thaw"));
    }
    let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
    let mut child = Command::new(&spec.command[0])
        .args(&spec.command[1..])
        .env("SHINU_RESTORE_ID", restore_id)
        .env_remove("SHINU_SNAPSHOT_NONCE")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| std::io::Error::other("ready-spawn"))?;
    let group = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    let result = (|| {
        loop {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("ready-timeout"));
            }
            let mut descriptor = PollDescriptor {
                fd: stream.as_raw_fd(),
                events: 1,
                returned: 0,
            };
            // Any input/EOF/HUP before our reply cancels the transaction.
            // SAFETY: descriptor points to one live Linux pollfd record.
            let ready = unsafe { poll(&raw mut descriptor, 1, 0) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if ready != 0 {
                return Err(std::io::Error::other("ready-disconnected"));
            }
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(format!("READY {restore_id}"))
                } else {
                    Err(std::io::Error::other("ready-command-failed"))
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Fence descendants even when their direct parent exits zero. A daemonized
    // application must be started through its supervisor, not escape this group.
    // SAFETY: the child owns its new process group; a negative PID targets it.
    let fenced = unsafe { kill(-group, 9) };
    let fence_error = (fenced < 0)
        .then(std::io::Error::last_os_error)
        .filter(|error| error.raw_os_error() != Some(3));
    let reaped = child.wait();
    match result {
        Err(error) => Err(error),
        Ok(reply) => {
            if let Some(error) = fence_error {
                return Err(error);
            }
            reaped?;
            Ok(reply)
        }
    }
}

fn serve(
    mut stream: File,
    paths: &SnapshotPaths<'_>,
    mounts: &mut Vec<File>,
) -> std::io::Result<Option<File>> {
    stream.write_all(b"SHINU-SNAPSHOT-1\n")?;
    read_request(stream, paths, mounts, false)
}

fn read_request(
    mut stream: File,
    paths: &SnapshotPaths<'_>,
    mounts: &mut Vec<File>,
    held: bool,
) -> std::io::Result<Option<File>> {
    let mut request = [0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(5);
    for length in 0..request.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::other("request-timeout"));
        }
        let timeout = [
            i64::try_from(remaining.as_secs()).unwrap_or(5),
            i64::from(remaining.subsec_micros()).max(1),
        ];
        // SAFETY: timeout is a live 64-bit Linux timeval; stream owns its fd.
        checked(unsafe { setsockopt(stream.as_raw_fd(), 1, 20, timeout.as_ptr(), 16) })?;
        stream.read_exact(&mut request[length..=length])?;
        if request[length] == b'\n' {
            return respond(stream, paths, mounts, &request[..length], held);
        }
    }
    stream.write_all(b"FAILED\n")?;
    Ok(None)
}

fn respond(
    mut stream: File,
    paths: &SnapshotPaths<'_>,
    mounts: &mut Vec<File>,
    request: &[u8],
    held: bool,
) -> std::io::Result<Option<File>> {
    if !held && (request.starts_with(b"ready ") || request.starts_with(b"capabilities ")) {
        match std::str::from_utf8(request)
            .map_err(std::io::Error::other)
            .and_then(|request| readiness_request(&stream, paths, request))
        {
            Ok(reply) => writeln!(stream, "{reply}")?,
            Err(_) => stream.write_all(b"FAILED readiness\n")?,
        }
        return Ok(None);
    }
    let result = std::str::from_utf8(request)
        .map_err(std::io::Error::other)
        .and_then(|request| operation(paths, request, mounts, held));
    match &result {
        Ok(_) => stream.write_all(b"OK\n")?,
        Err(error) => writeln!(stream, "FAILED {error}")?,
    }
    if matches!(result, Ok(true)) {
        read_timeout(&stream, 0)?;
        let nonblocking = 1_i32;
        // SAFETY: FIONBIO reads one int; stream owns a live socket descriptor.
        checked(unsafe { ioctl(stream.as_raw_fd(), 0x5421_u64, &raw const nonblocking) })?;
        return Ok(Some(stream));
    }
    Ok(None)
}

struct PendingRequest {
    bytes: [u8; 128],
    length: usize,
}

fn read_parked(
    mut stream: File,
    paths: &SnapshotPaths<'_>,
    mounts: &mut Vec<File>,
    pending: &mut PendingRequest,
) -> std::io::Result<Option<File>> {
    loop {
        match stream.read(&mut pending.bytes[pending.length..]) {
            Ok(0) => return Ok(None),
            Ok(count) => {
                pending.length += count;
                if let Some(end) = pending.bytes[..pending.length]
                    .iter()
                    .position(|byte| *byte == b'\n')
                {
                    pending.length = 0;
                    return respond(stream, paths, mounts, &pending.bytes[..end], true);
                }
                if pending.length == pending.bytes.len() {
                    stream.write_all(b"FAILED request too long\n")?;
                    return Ok(None);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(Some(stream));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn next_connection(listener: i32, held: &mut Option<File>) -> std::io::Result<(File, bool)> {
    loop {
        let mut descriptors = [
            PollDescriptor {
                fd: listener,
                events: 1,
                returned: 0,
            },
            PollDescriptor {
                fd: held.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: 1,
                returned: 0,
            },
        ];
        // SAFETY: descriptors is a live array of two Linux pollfd records.
        if unsafe { poll(descriptors.as_mut_ptr(), descriptors.len(), -1) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptors[0].returned != 0 {
            // SAFETY: accept4 creates a fresh owned descriptor; null peer addresses are valid.
            let fd = unsafe {
                accept4(
                    listener,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    SOCKET_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            // A new host connection replaces a captured/stale parked peer.
            held.take();
            // SAFETY: fd was just returned by accept4 and has exactly one owner.
            return Ok((unsafe { File::from_raw_fd(fd) }, false));
        }
        if descriptors[1].returned != 0
            && let Some(stream) = held.take()
        {
            return Ok((stream, true));
        }
    }
}

fn serve_connections(listener: &impl AsRawFd, paths: &SnapshotPaths<'_>) -> std::io::Result<()> {
    let mut mounts = Vec::new();
    let mut held = None;
    let mut pending = PendingRequest {
        bytes: [0; 128],
        length: 0,
    };
    loop {
        let (stream, parked) = next_connection(listener.as_raw_fd(), &mut held)?;
        let result = if parked {
            read_parked(stream, paths, &mut mounts, &mut pending)
        } else {
            pending.length = 0;
            read_timeout(&stream, 5)?;
            serve(stream, paths, &mut mounts)
        };
        if let Ok(connection) = result {
            held = connection;
        }
    }
}

fn main() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--capabilities") {
        println!("SHINU-SNAPSHOT-1 READY-1");
        return Ok(());
    }
    // SAFETY: these calls use Linux scalar arguments and valid fixed-size structs.
    let listener = unsafe {
        let limits = [u64::MAX; 2];
        checked(setrlimit(8, limits.as_ptr()))?;
        checked(mlockall(1 | 2))?;
        checked(setpriority(0, 0, -20))?;
        let listener = OwnedFd::from_raw_fd(checked(socket(
            40,
            1 | SOCKET_CLOEXEC | SOCKET_NONBLOCK,
            0,
        ))?);
        let address = VsockAddress {
            family: 40,
            reserved: 0,
            port: 2224,
            cid: u32::MAX,
            flags: 0,
            zero: [0; 3],
        };
        checked(bind(
            listener.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            16,
        ))?;
        checked(listen(listener.as_raw_fd(), 16))?;
        listener
    };
    let paths = SnapshotPaths {
        state: Path::new("/run/shinu-snapshot"),
        proc_root: Path::new("/proc"),
        block_root: Path::new("/sys/dev/block"),
    };
    serve_connections(&listener, &paths)
}

#[cfg(test)]
mod tests {
    use super::{operation, valid_nonce};
    #[test]
    fn protocol_rejects_shell_input_and_noncanonical_nonces() {
        assert!(!valid_nonce("00000000-0000-0000-0000-000000000000\n"));
        assert!(!valid_nonce("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"));
        assert!(valid_nonce("00000000-0000-4000-8000-000000000001"));
        for request in ["exec x", "thaw;touch /tmp/owned", "freeze x y z"] {
            assert!(
                operation(
                    &super::SnapshotPaths {
                        state: std::path::Path::new("/does/not/exist"),
                        proc_root: std::path::Path::new("/does/not/exist"),
                        block_root: std::path::Path::new("/does/not/exist")
                    },
                    request,
                    &mut Vec::new(),
                    false,
                )
                .is_err()
            );
        }
    }

    fn request(state: &std::path::Path, text: &str, mounts: &mut Vec<std::fs::File>) -> String {
        use std::io::{Read, Write};
        let root = state.parent().unwrap();
        if !state.join("thaw.sh").exists() {
            std::fs::write(state.join("thaw.sh"), include_str!("../thaw.sh")).unwrap();
        }
        if !root.join("proc").exists() {
            mount_fixture(root, None);
        }
        let proc_root = root.join("proc");
        let block_root = root.join("sys-block");
        let paths = super::SnapshotPaths {
            state,
            proc_root: &proc_root,
            block_root: &block_root,
        };
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        writeln!(client, "{text}").unwrap();
        let server: std::os::fd::OwnedFd = server.into();
        drop(super::serve(std::fs::File::from(server), &paths, mounts).unwrap());
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn rotated_nonce_rejects_old_requests_and_freeze_replay() {
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        std::fs::create_dir_all(&state).unwrap();
        let old = "00000000-0000-4000-8000-000000000001";
        let new = "00000000-0000-4000-8000-000000000002";
        std::fs::write(state.join("nonce"), old).unwrap();
        std::fs::write(state.join("phase"), "thawed").unwrap();
        std::fs::write(
            state.join("freeze.sh"),
            format!(
                "echo attempt >> '{}'; exit 1",
                root.join("attempts").display()
            ),
        )
        .unwrap();
        let mut mounts = Vec::new();
        assert!(request(&state, &format!("status {old} {new}"), &mut mounts).ends_with("OK\n"));
        assert!(request(&state, &format!("thaw {old}"), &mut mounts).contains("\nFAILED "));
        for _ in 0..2 {
            assert!(request(&state, &format!("freeze {new}"), &mut mounts).contains("\nFAILED "));
        }
        assert_eq!(
            std::fs::read_to_string(root.join("attempts")).unwrap(),
            "attempt\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn ready_fixture() -> (std::path::PathBuf, std::path::PathBuf, &'static str) {
        let root = std::env::temp_dir().join(format!("shinu-ready-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        std::fs::create_dir_all(&state).unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "thawed").unwrap();
        (root, state, nonce)
    }

    #[test]
    fn ready_protocol_authenticates_and_runs_exact_argv_with_fresh_environment() {
        let (root, state, nonce) = ready_fixture();
        let id = "00000000-0000-4000-8000-000000000002";
        let policy = serde_json::json!({"command":["/bin/sh","-c","test \"$SHINU_RESTORE_ID\" = \"$1\" && test \"$2\" = 'one argument'","ready",id,"one argument"],"timeout_seconds":2});
        assert_eq!(
            request(&state, &format!("capabilities {nonce}"), &mut Vec::new()),
            "SHINU-SNAPSHOT-1\nREADY-1\n"
        );
        assert_eq!(
            request(
                &state,
                &format!("ready {nonce} {id} {policy}"),
                &mut Vec::new()
            ),
            format!("SHINU-SNAPSHOT-1\nREADY {id}\n")
        );
        for invalid in [
            format!("ready {id} {id} {policy}"),
            format!("ready {nonce} {nonce} {policy}"),
            format!("ready {nonce} invalid {policy}"),
            format!("ready {nonce} {id} {{}}"),
        ] {
            assert!(request(&state, &invalid, &mut Vec::new()).ends_with("FAILED readiness\n"));
        }
        std::fs::write(state.join("phase"), "frozen").unwrap();
        assert!(
            request(
                &state,
                &format!("ready {nonce} {id} {policy}"),
                &mut Vec::new()
            )
            .ends_with("FAILED readiness\n")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ready_never_accepts_nonzero_or_missing_command_or_shell_metacharacters() {
        let (root, state, nonce) = ready_fixture();
        let id = uuid::Uuid::new_v4();
        let marker = root.join("not-a-shell");
        for command in [
            vec!["/bin/sh".to_owned(), "-c".into(), "exit 7".into()],
            vec!["/not/a/command".into()],
            vec![format!("/bin/true; touch {}", marker.display())],
        ] {
            let policy = serde_json::json!({"command":command,"timeout_seconds":2});
            assert!(
                request(
                    &state,
                    &format!("ready {nonce} {id} {policy}"),
                    &mut Vec::new()
                )
                .ends_with("FAILED readiness\n")
            );
        }
        assert!(!marker.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ready_timeout_fences_the_whole_process_group() {
        let (root, state, nonce) = ready_fixture();
        let marker = root.join("late-descendant");
        let policy = serde_json::json!({"command":["/bin/sh","-c",format!("(sleep 1.3; touch '{}') & wait", marker.display())],"timeout_seconds":1});
        let started = std::time::Instant::now();
        assert!(
            request(
                &state,
                &format!("ready {nonce} {} {policy}", uuid::Uuid::new_v4()),
                &mut Vec::new()
            )
            .ends_with("FAILED readiness\n")
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            !marker.exists(),
            "a timed-out descendant escaped the command group"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ready_success_fences_descendants_before_publishing_ready() {
        let (root, state, nonce) = ready_fixture();
        let marker = root.join("escaped-success");
        let policy = serde_json::json!({"command":["/bin/sh","-c",format!("(sleep 0.2; touch '{}') & exit 0", marker.display())],"timeout_seconds":1});
        let id = uuid::Uuid::new_v4();
        assert!(
            request(
                &state,
                &format!("ready {nonce} {id} {policy}"),
                &mut Vec::new()
            )
            .ends_with(&format!("READY {id}\n"))
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!marker.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ready_disconnect_fences_command_and_cannot_publish_success() {
        use std::io::Write;
        let (root, state, nonce) = ready_fixture();
        let marker = root.join("after-disconnect");
        let policy = serde_json::json!({"command":["/bin/sh","-c",format!("sleep 0.2; touch '{}'", marker.display())],"timeout_seconds":2});
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        writeln!(client, "ready {nonce} {} {policy}", uuid::Uuid::new_v4()).unwrap();
        drop(client);
        let fd: std::os::fd::OwnedFd = server.into();
        let paths = super::SnapshotPaths {
            state: &state,
            proc_root: &root,
            block_root: &root,
        };
        assert!(
            super::read_request(std::fs::File::from(fd), &paths, &mut Vec::new(), false).is_err()
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!marker.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ready_protocol_limits_the_complete_request_not_just_argv() {
        use std::io::{Read, Write};
        let (root, state, nonce) = ready_fixture();
        let oversized = format!(
            "ready {nonce} {} {}",
            uuid::Uuid::new_v4(),
            " ".repeat(65536)
        );
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        writeln!(client, "{oversized}").unwrap();
        let fd: std::os::fd::OwnedFd = server.into();
        let paths = super::SnapshotPaths {
            state: &state,
            proc_root: &root,
            block_root: &root,
        };
        drop(super::serve(std::fs::File::from(fd), &paths, &mut Vec::new()).unwrap());
        let mut response = [0; b"SHINU-SNAPSHOT-1\nFAILED\n".len()];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"SHINU-SNAPSHOT-1\nFAILED\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_thaw_still_runs_later_hooks_and_retains_the_retry_ledger() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        let ledger = root.join("shinu-freeze");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(&ledger).unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(ledger.join("mounts"), "").unwrap();
        let first = root.join("first");
        let last = root.join("last");
        std::fs::write(&first, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::write(
            &last,
            format!(
                "#!/bin/sh\necho last >> '{}'\n",
                root.join("events").display()
            ),
        )
        .unwrap();
        for hook in [&first, &last] {
            std::fs::set_permissions(hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(
            ledger.join("hooks"),
            format!("{}\n{}\n", first.display(), last.display()),
        )
        .unwrap();
        let mut mounts = Vec::new();
        assert!(request(&state, &format!("thaw {nonce}"), &mut mounts).contains("\nFAILED "));
        assert_eq!(
            std::fs::read_to_string(root.join("events")).unwrap(),
            "last\n"
        );
        assert!(ledger.exists());
        std::fs::write(&first, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(request(&state, &format!("thaw {nonce}"), &mut mounts).ends_with("OK\n"));
        assert!(!ledger.exists());
        assert!(request(&state, &format!("thaw {nonce}"), &mut mounts).ends_with("OK\n"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parked_connection_thaws_without_a_second_handshake() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::os::fd::AsRawFd;
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        let ledger = root.join("shinu-freeze");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(&ledger).unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "frozen").unwrap();
        std::fs::write(ledger.join("mounts"), "").unwrap();
        std::fs::write(ledger.join("hooks"), "").unwrap();
        let listener = std::os::unix::net::UnixListener::bind(root.join("listener")).unwrap();
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        writeln!(client, "status {nonce} hold").unwrap();
        let server: std::os::fd::OwnedFd = server.into();
        let mut mounts = Vec::new();
        let proc_root = root.join("proc");
        let block_root = root.join("sys-block");
        let paths = super::SnapshotPaths {
            state: &state,
            proc_root: &proc_root,
            block_root: &block_root,
        };
        let mut held = super::serve(std::fs::File::from(server), &paths, &mut mounts).unwrap();
        assert!(held.is_some());
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut banner = String::new();
        reader.read_line(&mut banner).unwrap();
        assert_eq!(banner, "SHINU-SNAPSHOT-1\n");
        banner.clear();
        reader.read_line(&mut banner).unwrap();
        assert_eq!(banner, "OK\n");
        client.write_all(b"th").unwrap();
        let (stream, parked) = super::next_connection(listener.as_raw_fd(), &mut held).unwrap();
        assert!(parked);
        let mut pending = super::PendingRequest {
            bytes: [0; 128],
            length: 0,
        };
        held = super::read_parked(stream, &paths, &mut mounts, &mut pending).unwrap();
        assert!(held.is_some());
        assert_eq!(pending.length, 2);
        writeln!(client, "aw {nonce}").unwrap();
        let (stream, parked) = super::next_connection(listener.as_raw_fd(), &mut held).unwrap();
        assert!(parked);
        assert!(
            super::read_parked(stream, &paths, &mut mounts, &mut pending)
                .unwrap()
                .is_none()
        );
        let mut response = String::new();
        reader.read_to_string(&mut response).unwrap();
        assert_eq!(response, "OK\n");
        assert!(!ledger.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn new_host_connection_replaces_a_captured_stale_parked_peer() {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("listener");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (mut old_client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let server: std::os::fd::OwnedFd = server.into();
        let mut held = Some(std::fs::File::from(server));
        let _incoming = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (_stream, parked) = super::next_connection(listener.as_raw_fd(), &mut held).unwrap();
        assert!(!parked);
        assert!(held.is_none());
        old_client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        assert_eq!(old_client.read(&mut [0u8; 1]).unwrap(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn mount_fixture(root: &std::path::Path, private: Option<&str>) {
        let proc = root.join("proc");
        std::fs::create_dir_all(proc.join("1/ns")).unwrap();
        std::fs::create_dir_all(proc.join("self/ns")).unwrap();
        std::fs::create_dir_all(root.join("sys-block/254:0")).unwrap();
        std::fs::create_dir_all(root.join("sys-block/254:1")).unwrap();
        std::fs::write(proc.join("1/ns/mnt"), "initial").unwrap();
        std::fs::hard_link(proc.join("1/ns/mnt"), proc.join("self/ns/mnt")).unwrap();
        std::fs::write(
            proc.join("1/mountinfo"),
            "1 0 254:0 / / rw,relatime - ext4 /dev/vda rw\n2 1 0:1 / /run rw - tmpfs tmpfs rw\n",
        )
        .unwrap();
        if let Some(private) = private {
            std::fs::create_dir_all(proc.join("2/ns")).unwrap();
            std::fs::write(proc.join("2/ns/mnt"), "private").unwrap();
            std::fs::write(proc.join("2/mountinfo"), private).unwrap();
        }
    }

    #[test]
    fn private_writable_ext4_is_refused_before_application_freeze() {
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        std::fs::create_dir_all(&state).unwrap();
        mount_fixture(&root, Some("3 0 254:1 / /private rw - ext4 /dev/vdb rw\n"));
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "ready").unwrap();
        std::fs::write(
            state.join("freeze.sh"),
            format!("echo ran > '{}'", root.join("freeze-ran").display()),
        )
        .unwrap();
        let response = request(&state, &format!("freeze {nonce}"), &mut Vec::new());
        assert!(
            response.contains("private writable block filesystem"),
            "{response}"
        );
        assert!(!root.join("freeze-ran").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_crash_cannot_allow_late_freeze_after_ssh_cleanup() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "SHINU_AGENT_CRASH_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let state = std::path::Path::new(&root).join("shinu-snapshot");
            let _ = request(
                &state,
                "freeze 00000000-0000-4000-8000-000000000001",
                &mut Vec::new(),
            );
            return;
        }
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("shinu-snapshot");
        let ledger = root.join("shinu-freeze");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(&ledger).unwrap();
        mount_fixture(&root, None);
        std::fs::write(state.join("nonce"), "00000000-0000-4000-8000-000000000001").unwrap();
        std::fs::write(state.join("phase"), "ready").unwrap();
        std::fs::write(
            state.join("freeze.sh"),
            format!(
                "echo entered > '{}'; sleep 0.2; echo freeze >> '{}'; echo done > '{}'",
                root.join("entered").display(),
                root.join("events").display(),
                root.join("done").display()
            ),
        )
        .unwrap();
        let hook = root.join("hook");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\necho thaw >> '{}'\n",
                root.join("events").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(ledger.join("hooks"), format!("{}\n", hook.display())).unwrap();
        std::fs::write(ledger.join("mounts"), "").unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::worker_crash_cannot_allow_late_freeze_after_ssh_cleanup",
            ])
            .env(CHILD, &root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !root.join("entered").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            std::process::Command::new("flock")
                .args(["-o", "-w", "2"])
                .arg(state.with_extension("lock"))
                .args(["sh", "-c", include_str!("../thaw.sh"), "snapshot-thaw"])
                .arg(&ledger)
                .status()
                .unwrap()
                .success()
        );
        while !root.join("done").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(
            std::fs::read_to_string(root.join("events")).unwrap(),
            "freeze\nthaw\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn covered_private_binds_and_readonly_mounts_allow_all_initial_block_filesystems() {
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        std::fs::create_dir_all(&state).unwrap();
        mount_fixture(
            &root,
            Some(
                "5 0 254:0 / /bind rw - ext4 /dev/vda rw\n6 0 254:2 / /readonly ro - xfs /dev/vdc rw\n7 0 0:44 / /subvol rw - btrfs /dev/vdd rw\n8 0 0:90 / / rw - overlay overlay rw\n",
            ),
        );
        std::fs::write(root.join("proc/1/mountinfo"), "1 0 254:0 / / rw - ext4 /dev/vda rw\n2 1 254:0 / /bind rw - ext4 /dev/vda rw\n3 1 254:1 / /data rw - xfs /dev/vdb rw\n4 1 0:44 / /vol rw - btrfs /dev/vdd rw\n").unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "ready").unwrap();
        std::fs::write(
            state.join("freeze.sh"),
            format!(
                "cat '{}' > '{}'",
                state.join("mounts").display(),
                root.join("catalog-used").display()
            ),
        )
        .unwrap();
        assert!(request(&state, &format!("freeze {nonce}"), &mut Vec::new()).ends_with("OK\n"));
        assert_eq!(
            std::fs::read_to_string(root.join("catalog-used")).unwrap(),
            "0:44 /vol\n254:0 /\n254:1 /data\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_without_a_ledger_cancels_a_monitor_that_has_not_locked_yet() {
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("shinu-snapshot");
        std::fs::create_dir_all(&state).unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "freezing").unwrap();
        std::fs::write(
            state.join("freeze.sh"),
            format!("echo ran > '{}'", root.join("ran").display()),
        )
        .unwrap();
        assert!(
            std::process::Command::new("flock")
                .arg("-F")
                .arg(state.with_extension("lock"))
                .args(["sh", "-c", include_str!("../thaw.sh"), "snapshot-thaw"])
                .arg(root.join("shinu-freeze"))
                .status()
                .unwrap()
                .success()
        );
        let paths = super::SnapshotPaths {
            state: &state,
            proc_root: &root,
            block_root: &root,
        };
        assert!(
            super::snapshot_script(
                &paths,
                "freeze",
                nonce,
                std::time::Instant::now() + std::time::Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(!root.join("ran").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn script_timeout_keeps_nested_process_groups_fenced_until_they_finish() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("shinu-snapshot");
        let ledger = root.join("shinu-freeze");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(&ledger).unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "freezing").unwrap();
        std::fs::write(state.join("freeze.sh"), format!("timeout -k 1 2 sh -c 'sleep 1.2; echo freeze >> \"$1/events\"; echo done > \"$1/done\"' nested '{}'", root.display())).unwrap();
        let hook = root.join("hook");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\necho thaw >> '{}'\n",
                root.join("events").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(ledger.join("hooks"), format!("{}\n", hook.display())).unwrap();
        std::fs::write(ledger.join("mounts"), "").unwrap();
        let paths = super::SnapshotPaths {
            state: &state,
            proc_root: &root,
            block_root: &root,
        };
        assert!(
            super::snapshot_script(
                &paths,
                "freeze",
                nonce,
                std::time::Instant::now() + std::time::Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(
            std::process::Command::new("flock")
                .args(["-F", "-w", "2"])
                .arg(state.with_extension("lock"))
                .args(["sh", "-c", include_str!("../thaw.sh"), "snapshot-thaw"])
                .arg(&ledger)
                .status()
                .unwrap()
                .success()
        );
        assert!(root.join("done").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("events")).unwrap(),
            "freeze\nthaw\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mount_changes_during_freeze_are_refused_before_acknowledgement() {
        for private in [true, false] {
            let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
            let state = root.join("agent");
            std::fs::create_dir_all(&state).unwrap();
            mount_fixture(&root, Some("3 0 254:0 / /bind rw - ext4 /dev/vda rw\n"));
            let nonce = "00000000-0000-4000-8000-000000000001";
            std::fs::write(state.join("nonce"), nonce).unwrap();
            std::fs::write(state.join("phase"), "ready").unwrap();
            let script = if private {
                format!(
                    "printf '%s\\n' '4 0 254:1 / /private rw - ext4 /dev/vdb rw' > '{}'",
                    root.join("proc/2/mountinfo").display()
                )
            } else {
                format!(
                    "printf '%s\\n' '4 1 254:1 / /data rw - xfs /dev/vdb rw' >> '{}'",
                    root.join("proc/1/mountinfo").display()
                )
            };
            std::fs::write(state.join("freeze.sh"), script).unwrap();
            let response = request(&state, &format!("freeze {nonce}"), &mut Vec::new());
            assert!(response.contains("\nFAILED "), "{response}");
            if private {
                assert!(
                    response.contains("private writable block filesystem"),
                    "{response}"
                );
            } else {
                assert!(response.contains("mount catalog changed"), "{response}");
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn partial_parked_request_cannot_block_a_replacement_connection() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::fd::AsRawFd;
        const CHILD: &str = "SHINU_AGENT_PARTIAL_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = std::path::Path::new(&root);
            let state = root.join("agent");
            let paths = super::SnapshotPaths {
                state: &state,
                proc_root: root,
                block_root: root,
            };
            let listener = std::os::unix::net::UnixListener::bind(root.join("listener")).unwrap();
            super::serve_connections(&listener, &paths).unwrap();
            return;
        }
        let root = std::env::temp_dir().join(format!("shinu-agent-{}", uuid::Uuid::new_v4()));
        let state = root.join("agent");
        let ledger = root.join("shinu-freeze");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(&ledger).unwrap();
        let nonce = "00000000-0000-4000-8000-000000000001";
        std::fs::write(state.join("nonce"), nonce).unwrap();
        std::fs::write(state.join("phase"), "frozen").unwrap();
        std::fs::write(ledger.join("mounts"), "").unwrap();
        std::fs::write(ledger.join("hooks"), "").unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::partial_parked_request_cannot_block_a_replacement_connection",
            ])
            .env(CHILD, &root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let result = (|| -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !root.join("listener").exists() {
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::other("protocol fixture startup timed out"));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let mut old = std::os::unix::net::UnixStream::connect(root.join("listener"))?;
            old.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
            let mut reader = BufReader::new(old.try_clone()?);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            writeln!(old, "status {nonce} hold")?;
            line.clear();
            reader.read_line(&mut line)?;
            if line != "OK\n" {
                return Err(std::io::Error::other("hold fixture authentication failed"));
            }
            old.write_all(b"th")?;
            loop {
                let mut queued = 0_i32;
                // SAFETY: TIOCOUTQ writes one int; old owns a live Unix socket.
                super::checked(unsafe {
                    super::ioctl(old.as_raw_fd(), 0x5411_u64, &raw mut queued)
                })?;
                if queued == 0 {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::other("partial frame was not consumed"));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let mut fresh = std::os::unix::net::UnixStream::connect(root.join("listener"))?;
            fresh.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
            let mut response = BufReader::new(fresh.try_clone()?);
            line.clear();
            response.read_line(&mut line)?;
            if line != "SHINU-SNAPSHOT-1\n" {
                return Err(std::io::Error::other("replacement handshake failed"));
            }
            writeln!(fresh, "thaw {nonce}")?;
            line.clear();
            response.read_line(&mut line)?;
            if line != "OK\n" {
                return Err(std::io::Error::other("replacement thaw failed"));
            }
            Ok(())
        })();
        let _ = child.kill();
        child.wait().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }
}
