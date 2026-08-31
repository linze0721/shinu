use chrono::Utc;
use clap::Parser;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

use rusqlite::Connection;
use shinu::{
    Image, http,
    proto::{Req, SnapshotMode},
    quota::{self, Limits, RateLimiter},
    registry::Registry,
    state::{self, Ckpt, Space, State},
};
use shinu_image::{
    DEFAULT_DIFF_LIMIT, DEFAULT_EXCLUSIONS, DiffEntry, DiffOptions, DiffResult, DiffStatus,
    MAX_DIFF_LIMIT, diff_images,
};

const AUTH_HTML: &str = include_str!("../console/auth.html");
const APP_HTML: &str = include_str!("../console/index.html");
const APP_CSS: &str = include_str!("../console/app.css");
const APP_JS: &str = include_str!("../console/app.js");
const SESSION_COOKIE: &str = "shinu_session";
const SESSION_DEFAULT_DAYS: i64 = 7;
const SESSION_MAX_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;
const REGISTER_REQUESTS_PER_HOUR: usize = 5;
const LOGIN_FAILURE_MESSAGE: &str = "invalid email or password";
const DUMMY_PASSWORD_HASH: &str = "pbkdf2$210000$0000000000000000000000000000000000000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
// Normal requests complete in milliseconds; fifteen seconds leaves room for a
// slow client without letting an incomplete request retain a worker. This
// deadline is cleared before any unbounded stream begins.
/// Maximum number of diff snapshots anchored to one full base before a new
/// full snapshot is captured. `SHINU_FULL_EVERY` overrides this value; zero
/// disables automatic degradation.
const DEFAULT_FULL_EVERY: usize = 8;
const DIFF_TMP_DIR: &str = "diff-tmp";

#[derive(Parser)]
#[command(name = "shinud")]
struct Cli {
    #[arg(long)]
    root: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let root = shinu::resolve_root(cli.root.as_deref());
    shinu::init_daemon_layout(&root)?;
    purge_diff_temp(&root)?;
    let connection = state::open(&root)?;
    if state::migrate_from_json(&root, &connection)? {
        eprintln!("imported state.json into shinu.db (renamed to state.json.migrated)");
    }
    // Rename the one legacy Void base before any lazy image lookup; this is
    // idempotent so restarts never rebuild or fork the old filename.
    shinu::migrate_base(&root)?;
    // A base built before the current egress policy carries a resolver the
    // guest firewall now blocks — or, since IPv6 entries began counting as
    // unreachable, one the guest cannot route at all. Either silently breaks
    // package installs in every VM forked from it. Images that were never
    // built are skipped, so this stays compatible with lazy base creation.
    // Best effort: a busy or damaged base is an operator problem, not a
    // reason to refuse service.
    match shinu::repair_base_resolv(&root) {
        Ok(true) => eprintln!("rewrote a base image resolv.conf to a reachable resolver"),
        Ok(false) => {}
        Err(error) => eprintln!("base resolv repair: {error}"),
    }
    // Assets are shared by all guests and cheap compared with rootfs builds;
    // image bases themselves are ensured only when their first space is made.
    shinu::ensure_assets(&root)?;
    let vm_cfg = shinu::VmConfig::from_env();
    let net_cfg = shinu::NetConfig::from_env()?;
    let limits = Limits::from_env();
    // Only the deployment admin may mutate quotas; an unset secret fails closed.
    let admin_token = std::env::var("SHINU_ADMIN_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let rate = RateLimiter::new();
    // Registration has its own IP-keyed limiter so API traffic cannot consume
    // the account-creation allowance (and vice versa).
    let register_rate = RegistrationLimiter::new();

    let listen = std::env::var("SHINU_LISTEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1:7878".to_owned());
    let listener = TcpListener::bind(&listen)?;
    let root = Arc::new(root);
    let db = Arc::new(Mutex::new(connection));
    let vm_cfg = Arc::new(vm_cfg);
    let net_cfg = Arc::new(net_cfg);
    let limits = Arc::new(limits);
    let rate = Arc::new(rate);
    let register_rate = Arc::new(register_rate);
    let admin_token = Arc::new(admin_token);
    let registry = Arc::new(Registry::new());

    let sweep_root = Arc::clone(&root);
    let sweep_vm_cfg = Arc::clone(&vm_cfg);
    let sweep_net_cfg = Arc::clone(&net_cfg);
    let sweep_db = Arc::clone(&db);
    let sweep_registry = Arc::clone(&registry);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(shinu::USAGE_SAMPLE_SECS));
            match shinu::vm::sweep_idle(
                sweep_root.as_path(),
                sweep_vm_cfg.idle_secs,
                sweep_net_cfg.as_ref(),
            ) {
                Ok(stopped) => {
                    for dir in &stopped {
                        eprintln!("idle sweep stopped {}", dir.display());
                    }
                    if let Err(error) = refresh_idle_networks(
                        sweep_root.as_path(),
                        &sweep_db,
                        &sweep_registry,
                        sweep_net_cfg.as_ref(),
                        &stopped,
                    ) {
                        eprintln!("idle network refresh: {error}");
                    }
                }
                Err(error) => eprintln!("idle sweep: {error}"),
            }
            if let Err(error) = record_sweep_usage(sweep_root.as_path(), &sweep_db, &sweep_registry)
            {
                eprintln!("usage sweep: {error}");
            }
            let purge_result = {
                let connection = lock_db(&sweep_db);
                state::purge_expired_sessions(&connection)
            };
            match purge_result {
                Ok(removed) if removed > 0 => {
                    eprintln!("session sweep removed {removed} expired sessions");
                }
                Ok(_) => {}
                Err(error) => eprintln!("session sweep: {error}"),
            }
        }
    });

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let timeout_setup = stream
                    .set_read_timeout(Some(REQUEST_TIMEOUT))
                    .and_then(|()| stream.set_write_timeout(Some(REQUEST_TIMEOUT)));
                if let Err(error) = timeout_setup {
                    eprintln!("connection timeout setup: {error}");
                    continue;
                }
                let connection_root = Arc::clone(&root);
                let connection_db = Arc::clone(&db);
                let connection_vm_cfg = Arc::clone(&vm_cfg);
                let connection_net_cfg = Arc::clone(&net_cfg);
                let connection_limits = Arc::clone(&limits);
                let connection_rate = Arc::clone(&rate);
                let connection_register_rate = Arc::clone(&register_rate);
                let connection_registry = Arc::clone(&registry);
                let connection_admin_token = Arc::clone(&admin_token);
                thread::spawn(move || {
                    let ctx = Ctx {
                        root: connection_root.as_path(),
                        db: connection_db.as_ref(),
                        vm_cfg: connection_vm_cfg.as_ref(),
                        net_cfg: connection_net_cfg.as_ref(),
                        limits: connection_limits.as_ref(),
                        rate: connection_rate.as_ref(),
                        register_rate: connection_register_rate.as_ref(),
                        registry: connection_registry.as_ref(),
                        admin_token: connection_admin_token.as_deref(),
                    };
                    if let Err(error) = serve_connection(stream, &ctx) {
                        eprintln!("connection: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept: {error}"),
        }
    }
}

struct Ctx<'a> {
    root: &'a Path,
    db: &'a Mutex<Connection>,
    vm_cfg: &'a shinu::VmConfig,
    net_cfg: &'a shinu::NetConfig,
    limits: &'a Limits,
    rate: &'a RateLimiter,
    register_rate: &'a RegistrationLimiter,
    registry: &'a Registry,
    admin_token: Option<&'a str>,
}

/// Keeps the parsed header bytes available for proxy forwarding while leaving
/// normal routes on the shared HTTP parser and body reader.
struct RequestReader<'a> {
    inner: BufReader<&'a mut TcpStream>,
    captured: Vec<u8>,
    capture: bool,
}

impl<'a> RequestReader<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self {
            inner: BufReader::new(stream),
            captured: Vec::new(),
            capture: true,
        }
    }

    fn stop_capture(&mut self) {
        self.capture = false;
        self.captured.clear();
    }

    fn take_headers(&mut self) -> Vec<u8> {
        self.capture = false;
        std::mem::take(&mut self.captured)
    }
    fn clear_socket_timeouts(&mut self) -> shinu::Result<()> {
        clear_stream_timeouts(&**self.inner.get_mut())
    }
}

impl Read for RequestReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        if self.capture {
            self.captured.extend_from_slice(&buffer[..count]);
        }
        Ok(count)
    }
}

impl BufRead for RequestReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        if self.capture
            && let Ok(buffer) = self.inner.fill_buf()
        {
            self.captured.extend_from_slice(&buffer[..amount]);
        }
        self.inner.consume(amount);
    }
}

struct RegistrationLimiter {
    // quota::RateLimiter is a 60-second per-project limiter; registration is
    // intentionally a separate one-hour per-IP policy, so the semantics differ.
    requests: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RegistrationLimiter {
    fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, ip: &str) -> shinu::Result<()> {
        const WINDOW: Duration = Duration::from_hours(1);
        let now = Instant::now();
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for timestamps in requests.values_mut() {
            while timestamps.front().is_some_and(|at| {
                now.checked_duration_since(*at)
                    .is_some_and(|elapsed| elapsed >= WINDOW)
            }) {
                timestamps.pop_front();
            }
        }
        requests.retain(|_, timestamps| !timestamps.is_empty());
        if let Some(timestamps) = requests.get_mut(ip) {
            if timestamps.len() >= REGISTER_REQUESTS_PER_HOUR {
                return Err(shinu::Error::Quota(
                    "registration rate limit exceeded: 5 registrations per hour".into(),
                ));
            }
            timestamps.push_back(now);
            return Ok(());
        }
        requests.insert(ip.to_owned(), VecDeque::from([now]));
        Ok(())
    }
}

fn lock_db(db: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_state(registry: &Registry) -> MutexGuard<'_, ()> {
    registry
        .state_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn snapshot(db: &Mutex<Connection>, registry: &Registry) -> shinu::Result<State> {
    let _state_guard = lock_state(registry);
    state::load(&lock_db(db))
}

fn update_state<T>(
    db: &Mutex<Connection>,
    registry: &Registry,
    update: impl FnOnce(&mut State) -> shinu::Result<T>,
) -> shinu::Result<T> {
    let _state_guard = lock_state(registry);
    let connection = lock_db(db);
    let mut state = state::load(&connection)?;
    let value = update(&mut state)?;
    state::store(&connection, &state)?;
    Ok(value)
}

fn update_state_with_quota<T>(
    root: &Path,
    db: &Mutex<Connection>,
    registry: &Registry,
    project: &str,
    limits: &Limits,
    adding_mib: u64,
    update: impl FnOnce(&mut State) -> shinu::Result<T>,
) -> shinu::Result<T> {
    let _state_guard = lock_state(registry);
    let connection = lock_db(db);
    check_space_quota(root, &connection, project, limits, adding_mib)?;
    let mut state = state::load(&connection)?;
    let value = update(&mut state)?;
    state::store(&connection, &state)?;
    Ok(value)
}

const BYTES_PER_MIB: u64 = 1024 * 1024;

fn bytes_to_mib(bytes: u64) -> u64 {
    bytes.saturating_add(BYTES_PER_MIB - 1) / BYTES_PER_MIB
}

fn image_size_mib(path: &Path) -> u64 {
    path.metadata().map_or_else(
        |_| shinu::btrfs::exclusive(path).map_or(0, bytes_to_mib),
        |metadata| bytes_to_mib(metadata.len()),
    )
}
fn space_snapshot_mem(root: &Path, id: Uuid) -> PathBuf {
    shinu::space_image(root, id).with_extension("mem")
}

fn space_snapshot_state(root: &Path, id: Uuid) -> PathBuf {
    shinu::space_image(root, id).with_extension("state")
}

fn remove_file_if_missing(path: &Path) -> shinu::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn diff_temp_dir(root: &Path) -> PathBuf {
    root.join(DIFF_TMP_DIR)
}

fn purge_diff_temp(root: &Path) -> shinu::Result<()> {
    match std::fs::remove_dir_all(diff_temp_dir(root)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn diff_temp_path(root: &Path) -> PathBuf {
    diff_temp_dir(root).join(format!("input-{}.ext4", Uuid::new_v4()))
}

fn remove_space_snapshot_files(root: &Path, id: Uuid) -> shinu::Result<()> {
    remove_file_if_missing(&space_snapshot_mem(root, id))?;
    remove_file_if_missing(&space_snapshot_state(root, id))
}
const NETWORK_HOSTS_BEGIN: &str = "# BEGIN SHINU NETWORK PEERS";
const NETWORK_HOSTS_END: &str = "# END SHINU NETWORK PEERS";

fn network_members(state: &State, project: &str, network: Option<&str>) -> Vec<Space> {
    let Some(network) = network else {
        return Vec::new();
    };
    state
        .spaces
        .iter()
        .filter(|space| space.project == project && space.network.as_deref() == Some(network))
        .cloned()
        .collect()
}

fn guest_ip(id: Uuid, cfg: &shinu::NetConfig) -> Option<String> {
    shinu::net_spec(id, cfg).and_then(|spec| {
        spec.guest_cidr
            .split_once('/')
            .map(|(address, _)| address.to_owned())
    })
}

fn peer_ips(space: &Space, members: &[Space], cfg: &shinu::NetConfig) -> Vec<String> {
    members
        .iter()
        .filter(|peer| peer.id != space.id)
        .filter_map(|peer| guest_ip(peer.id, cfg))
        .collect()
}

fn running_network_members(
    root: &Path,
    state: &State,
    project: &str,
    network: Option<&str>,
) -> Vec<Space> {
    let Some(network) = network else {
        return Vec::new();
    };
    state
        .spaces
        .iter()
        .filter(|space| {
            space.project == project
                && space.network.as_deref() == Some(network)
                && shinu::vm::is_running(&shinu::vm_dir(root, space.id))
        })
        .cloned()
        .collect()
}

fn refresh_network_rules_with(
    root: &Path,
    cfg: &shinu::NetConfig,
    state: &State,
    project: &str,
    network: Option<&str>,
    previous_running: &[Space],
) -> shinu::Result<Vec<Space>> {
    let current_running = running_network_members(root, state, project, network);
    for member in &current_running {
        let old_peers = peer_ips(member, previous_running, cfg);
        let new_peers = peer_ips(member, &current_running, cfg);
        let departed = old_peers
            .iter()
            .filter(|peer| !new_peers.contains(peer))
            .cloned()
            .collect::<Vec<_>>();
        shinu::vm::remove_peer_rules(member.id, cfg, &departed);
        shinu::vm::refresh_peer_rules(member.id, cfg, &new_peers)?;
    }
    Ok(current_running)
}

fn refresh_network_rules(
    ctx: &Ctx<'_>,
    state: &State,
    project: &str,
    network: Option<&str>,
    previous_running: &[Space],
) -> shinu::Result<Vec<Space>> {
    refresh_network_rules_with(
        ctx.root,
        ctx.net_cfg,
        state,
        project,
        network,
        previous_running,
    )
}

fn network_hosts_command<'a>(
    member: &Space,
    members: impl Iterator<Item = &'a Space>,
    cfg: &shinu::NetConfig,
) -> Option<Vec<String>> {
    let mut script = format!(
        r#"set -e
tmp=/tmp/shinu-hosts.$$
awk '
$0 == {:?} {{ inside=1; next }}
$0 == {:?} {{ inside=0; next }}
!inside {{ print }}
' /etc/hosts > "$tmp"
{{
printf '%s\n' {}
"#,
        NETWORK_HOSTS_BEGIN,
        NETWORK_HOSTS_END,
        shinu::shell_quote_word(NETWORK_HOSTS_BEGIN),
    );
    for peer in members.filter(|peer| peer.id != member.id) {
        let ip = guest_ip(peer.id, cfg)?;
        script.push_str(&format!(
            "printf '%s %s\\n' {} {}\n",
            shinu::shell_quote_word(&ip),
            shinu::shell_quote_word(&peer.name),
        ));
    }
    script.push_str(&format!(
        "printf '%s\\n' {}\n}} >> \"$tmp\"\ncat \"$tmp\" > /etc/hosts\nrm -f \"$tmp\"",
        shinu::shell_quote_word(NETWORK_HOSTS_END),
    ));
    Some(vec!["sh".to_owned(), "-c".to_owned(), script])
}

fn sync_network_hosts_with(
    root: &Path,
    cfg: &shinu::NetConfig,
    running_members: &[Space],
    all_members: &[Space],
) {
    for member in running_members {
        let Some(network) = member.network.as_deref() else {
            continue;
        };
        let Some(command) = network_hosts_command(
            member,
            all_members
                .iter()
                .filter(|peer| peer.network.as_deref() == Some(network)),
            cfg,
        ) else {
            continue;
        };
        match shinu::exec_in_vm(
            &shinu::vm::vsock_path(&shinu::vm_dir(root, member.id)),
            &shinu::vm::key_path(&shinu::vm_dir(root, member.id)),
            shinu::VSOCK_SSH_PORT,
            &command,
        ) {
            Ok(0) => {}
            Ok(status) => eprintln!(
                "failed to update /etc/hosts for network member {}: exit status {status}",
                member.name
            ),
            Err(error) => eprintln!(
                "failed to update /etc/hosts for network member {}: {error}",
                member.name
            ),
        }
    }
}

fn sync_network_hosts(ctx: &Ctx<'_>, running_members: &[Space], all_members: &[Space]) {
    sync_network_hosts_with(ctx.root, ctx.net_cfg, running_members, all_members);
}
fn refresh_idle_networks(
    root: &Path,
    db: &Mutex<Connection>,
    registry: &Registry,
    cfg: &shinu::NetConfig,
    stopped: &[PathBuf],
) -> shinu::Result<()> {
    if stopped.is_empty() {
        return Ok(());
    }
    let state = snapshot(db, registry)?;
    let stopped_ids = stopped
        .iter()
        .filter_map(|dir| {
            dir.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| Uuid::parse_str(name).ok())
        })
        .collect::<Vec<_>>();
    let mut groups = Vec::<(String, String)>::new();
    for space in &state.spaces {
        let Some(network) = space.network.as_deref() else {
            continue;
        };
        if stopped_ids.contains(&space.id)
            && !groups
                .iter()
                .any(|(project, name)| project == &space.project && name == network)
        {
            groups.push((space.project.clone(), network.to_owned()));
        }
    }
    for (project, network) in groups {
        let all_members = network_members(&state, &project, Some(&network));
        let mut previous_running = running_network_members(root, &state, &project, Some(&network));
        for member in &all_members {
            if stopped_ids.contains(&member.id)
                && !previous_running
                    .iter()
                    .any(|running| running.id == member.id)
            {
                previous_running.push(member.clone());
            }
        }
        let current_running = refresh_network_rules_with(
            root,
            cfg,
            &state,
            &project,
            Some(&network),
            &previous_running,
        )?;
        sync_network_hosts_with(root, cfg, &current_running, &all_members);
    }
    Ok(())
}

fn checkpoint_exclusive(root: &Path, id: Uuid) -> shinu::Result<u64> {
    let mut total: u64 = 0;
    for path in [
        shinu::ckpt_image(root, id),
        shinu::ckpt_mem(root, id),
        shinu::ckpt_state(root, id),
    ] {
        total = total.saturating_add(shinu::btrfs::exclusive(&path)?);
    }
    Ok(total)
}

/// Takes a stable reflink of one checkpoint image for a read-only diff.
///
/// A diff needs two images at once, while the lock contract forbids holding
/// multiple checkpoint locks. Copying each image while holding only its own
/// lock gives the comparison a stable input without deadlocking GC/removal.
fn copy_checkpoint_image_for_diff(ctx: &Ctx<'_>, id: Uuid) -> shinu::Result<PathBuf> {
    let temp_dir = diff_temp_dir(ctx.root);
    std::fs::create_dir_all(&temp_dir)?;
    let destination = diff_temp_path(ctx.root);
    let checkpoint_guard = ctx.registry.checkpoint_lock(id);
    let _checkpoint_guard = checkpoint_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let result = shinu::btrfs::clone_for(&shinu::ckpt_image(ctx.root, id), &destination, 0, 0);
    if result.is_err() {
        let _ = std::fs::remove_file(&destination);
    }
    result.map(|()| destination)
}

fn space_size_mib(root: &Path, space: &Space) -> u64 {
    space
        .disk_mib
        .unwrap_or_else(|| image_size_mib(&shinu::space_image(root, space.id)))
}

fn current_disk_mib(root: &Path, state: &State, project: &str) -> shinu::Result<u64> {
    let spaces = state
        .spaces
        .iter()
        .filter(|space| space.project == project)
        .map(|space| space_size_mib(root, space))
        .sum::<u64>();
    let mut checkpoints = 0u64;
    for checkpoint in state
        .ckpts
        .iter()
        .filter(|checkpoint| checkpoint.project == project)
    {
        checkpoints =
            checkpoints.saturating_add(bytes_to_mib(checkpoint_exclusive(root, checkpoint.id)?));
    }
    Ok(spaces.saturating_add(checkpoints))
}

fn check_space_quota(
    root: &Path,
    connection: &Connection,
    project: &str,
    limits: &Limits,
    adding_mib: u64,
) -> shinu::Result<()> {
    let spaces = state::count_spaces(connection, project)?;
    quota::check_space_limit(spaces, limits)?;
    let state = state::load(connection)?;
    let disk_mib = current_disk_mib(root, &state, project)?;
    // Capacity quota is an instantaneous allocation check, separate from the
    // usage_events.disk_mib_hour billing time series.
    quota::check_disk_limit(disk_mib, adding_mib, limits)
}

fn effective_limits(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Limits> {
    let connection = lock_db(ctx.db);
    let (max_spaces, max_disk_mib, max_running, api_per_min) =
        state::project_limits(&connection, project)?.unwrap_or((
            ctx.limits.max_spaces,
            ctx.limits.max_disk_mib,
            ctx.limits.max_running,
            ctx.limits.api_per_min,
        ));
    Ok(Limits {
        max_spaces,
        max_disk_mib,
        max_vcpus: ctx.limits.max_vcpus,
        max_mem_mib: ctx.limits.max_mem_mib,
        max_running,
        api_per_min,
    })
}

fn ensure_positive_size(name: &str, value: Option<u64>) -> shinu::Result<()> {
    if value == Some(0) {
        return Err(shinu::Error::Invalid(format!(
            "{name} must be greater than zero"
        )));
    }
    Ok(())
}

fn check_vm_sizing(
    ctx: &Ctx<'_>,
    limits: &Limits,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
) -> shinu::Result<()> {
    let vcpus = vcpus.unwrap_or(ctx.vm_cfg.vcpus);
    let mem_mib = mem_mib.unwrap_or(ctx.vm_cfg.mem_mib);
    quota::check_vcpu_limit(vcpus, limits)?;
    quota::check_mem_limit(mem_mib, limits)
}

fn count_running(root: &Path, state: &State, project: &str) -> u32 {
    let count = state
        .spaces
        .iter()
        .filter(|space| {
            space.project == project && shinu::vm::is_running(&shinu::vm_dir(root, space.id))
        })
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn space_start_state(
    ctx: &Ctx<'_>,
    project: &str,
    space: &Space,
    limits: &Limits,
) -> shinu::Result<(bool, State, Vec<Space>)> {
    // Keep the running-slot check under the state lock, but release it before
    // vm::start waits for the guest's SSH service.
    let _state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    let state = state::load(&connection)?;
    let previous_running =
        running_network_members(ctx.root, &state, project, space.network.as_deref());
    let already_running = shinu::vm::is_running(&shinu::vm_dir(ctx.root, space.id));
    if !already_running {
        quota::check_running_limit(count_running(ctx.root, &state, project), limits)?;
    }
    Ok((already_running, state, previous_running))
}

fn record_sweep_usage(
    root: &Path,
    db: &Mutex<Connection>,
    registry: &Registry,
) -> shinu::Result<()> {
    // Only identity is needed to associate a sample with a usage event. Do
    // not retain state/DB locks while btrfs or VM probes inspect the host.
    let spaces = {
        let _state_guard = lock_state(registry);
        let connection = lock_db(db);
        state::load(&connection)?
            .spaces
            .into_iter()
            .map(|space| (space.id, space.project))
            .collect::<Vec<_>>()
    };
    let mut samples = Vec::with_capacity(spaces.len());
    for (id, project) in spaces {
        #[cfg(test)]
        tests::during_sweep_probe();
        let image = shinu::space_image(root, id);
        // A disk-usage probe failure must not abort the 30-second sweep.
        let disk_mib = bytes_to_mib(shinu::btrfs::exclusive(&image).unwrap_or(0));
        let running = shinu::vm::is_running(&shinu::vm_dir(root, id));
        samples.push((id, project, disk_mib, running));
    }

    // A space may have been removed while probes ran. Re-check both identity
    // fields before recording, so an old sample cannot be charged to a
    // replacement or to a tenant that no longer owns the id.
    let _state_guard = lock_state(registry);
    let connection = lock_db(db);
    let state = state::load(&connection)?;
    for (id, project, disk_mib, running) in samples {
        if !state
            .spaces
            .iter()
            .any(|space| space.id == id && space.project == project)
        {
            continue;
        }
        // `disk_mib_hour` stores one MiB snapshot per sweep, not a duration;
        // later pricing can multiply the sum by the 30-second sample period.
        state::record_usage(
            &connection,
            &project,
            "disk_mib_hour",
            Some(id),
            i64::try_from(disk_mib).unwrap_or(i64::MAX),
        )?;
        if running {
            state::record_usage(
                &connection,
                &project,
                "vm_seconds",
                Some(id),
                i64::try_from(shinu::USAGE_SAMPLE_SECS).unwrap_or(30),
            )?;
        }
    }
    Ok(())
}

fn check_name(state: &State, name: &str, project: &str) -> shinu::Result<()> {
    if name.trim().is_empty() {
        return Err(shinu::Error::Invalid("space name cannot be empty".into()));
    }
    if state
        .spaces
        .iter()
        .any(|space| space.project == project && space.name == name)
    {
        return Err(shinu::Error::Invalid(format!(
            "space name already exists: {name}"
        )));
    }
    Ok(())
}

fn require_checkpoint_note(note: &str) -> shinu::Result<()> {
    if note.trim().is_empty() {
        return Err(shinu::Error::Invalid("checkpoint needs a note".into()));
    }
    Ok(())
}
/// Refuses to hand an incompatible memory snapshot to Firecracker.
///
/// Firecracker validates the snapshot data format version on
/// `PUT /snapshot/load`. Upgrading the binary can strand old memory state, so
/// a typed refusal is safer than surfacing an opaque load failure; the
/// checkpoint's disk image remains usable.
fn ensure_snapshot_loadable(ckpt: &state::Ckpt) -> shinu::Result<()> {
    if !ckpt.full || ckpt.snapshot_version.as_deref() == Some(shinu::FC_SNAPSHOT_VERSION) {
        return Ok(());
    }
    let recorded = ckpt.snapshot_version.as_deref().unwrap_or("unrecorded");
    Err(shinu::Error::Invalid(format!(
        "checkpoint {} memory state uses snapshot format {recorded}, but running Firecracker uses {}; the checkpoint's disk image is still usable",
        ckpt.id,
        shinu::FC_SNAPSHOT_VERSION
    )))
}

/// The checkpoint metadata needed when appending a state transition.
struct CkptFlags {
    /// Written by the daemon itself rather than requested by a caller.
    auto: bool,
    /// Has memory and vCPU state beside the disk image.
    full: bool,
    /// Full checkpoint whose memory this diff overlays, if any.
    base: Option<Uuid>,
    /// Moves the space's head to this checkpoint.
    update_head: bool,
}

fn append_checkpoint(
    state: &mut State,
    space_id: Uuid,
    project: &str,
    id: Uuid,
    note: String,
    flags: CkptFlags,
) -> shinu::Result<Ckpt> {
    let space_index = state
        .spaces
        .iter()
        .position(|space| space.id == space_id && space.project == project)
        .ok_or_else(|| shinu::Error::NotFound(space_id.to_string()))?;
    let parent = state.spaces[space_index].head;
    let checkpoint = Ckpt {
        id,
        space: space_id,
        project: project.to_owned(),
        parent,
        auto: flags.auto,
        full: flags.full,
        base: flags.base,
        note,
        snapshot_version: flags.full.then(|| shinu::FC_SNAPSHOT_VERSION.to_owned()),
        created_at: Utc::now(),
    };
    state.ckpts.push(checkpoint.clone());
    if flags.update_head {
        state.spaces[space_index].head = Some(id);
    }
    Ok(checkpoint)
}

fn full_every_from(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FULL_EVERY)
}

fn full_every() -> usize {
    full_every_from(std::env::var("SHINU_FULL_EVERY").ok().as_deref())
}

fn is_usable_full_base(root: &Path, space: &Space, checkpoint: &Ckpt) -> bool {
    let space_id = space.id;
    let project = space.project.as_str();
    checkpoint.full
        && checkpoint.base.is_none()
        && checkpoint.space == space_id
        && checkpoint.project == project
        && checkpoint.snapshot_version.as_deref() == Some(shinu::FC_SNAPSHOT_VERSION)
        && shinu::ckpt_mem(root, checkpoint.id).is_file()
        && shinu::ckpt_state(root, checkpoint.id).is_file()
}

/// Finds the nearest valid full ancestor and counts diffs anchored to it.
///
/// [`shinu::log_chain`] stops on malformed parent links and cycles, so a
/// damaged history cannot make this walk unbounded.
fn latest_usable_full_checkpoint(
    root: &Path,
    state: &State,
    space: &Space,
) -> Option<(Ckpt, usize)> {
    let chain = shinu::log_chain(state, space);
    let base_index = chain
        .iter()
        .position(|checkpoint| is_usable_full_base(root, space, checkpoint))?;
    let base = chain[base_index];
    let space_id = space.id;
    let project = space.project.as_str();
    let diff_count = chain[..base_index]
        .iter()
        .filter(|checkpoint| {
            checkpoint.full
                && checkpoint.space == space_id
                && checkpoint.project == project
                && checkpoint.base == Some(base.id)
        })
        .count();
    Some((base.clone(), diff_count))
}

fn resolve_snapshot_mode(
    root: &Path,
    state: &State,
    space: &Space,
    requested: SnapshotMode,
    full_every: usize,
) -> shinu::Result<(SnapshotMode, Option<Ckpt>)> {
    // The frequency budget only governs transparent Full-to-Diff degradation;
    // an explicit Diff request intentionally bypasses it.
    match requested {
        SnapshotMode::None => Ok((SnapshotMode::None, None)),
        SnapshotMode::Full => {
            let Some((base, diff_count)) = latest_usable_full_checkpoint(root, state, space) else {
                return Ok((SnapshotMode::Full, None));
            };
            if full_every > 0 && diff_count < full_every {
                Ok((SnapshotMode::Diff, Some(base)))
            } else {
                Ok((SnapshotMode::Full, None))
            }
        }
        SnapshotMode::Diff => {
            let Some((base, _)) = latest_usable_full_checkpoint(root, state, space) else {
                return Err(shinu::Error::Invalid(
                    "a diff checkpoint needs an existing full checkpoint in this space's history"
                        .into(),
                ));
            };
            Ok((SnapshotMode::Diff, Some(base)))
        }
    }
}

fn checkpoint_snapshot_mode(checkpoint: &Ckpt) -> &'static str {
    if !checkpoint.full {
        "none"
    } else if checkpoint.base.is_some() {
        "diff"
    } else {
        "full"
    }
}

fn materialize_checkpoint_memory(
    root: &Path,
    checkpoint: &Ckpt,
    destination: &Path,
) -> shinu::Result<()> {
    ensure_snapshot_loadable(checkpoint)?;
    if !checkpoint.full {
        return Err(shinu::Error::Invalid(format!(
            "checkpoint {} has no memory snapshot",
            checkpoint.id
        )));
    }
    let memory = shinu::ckpt_mem(root, checkpoint.id);
    if let Some(base) = checkpoint.base {
        let base_memory = shinu::ckpt_mem(root, base);
        if !base_memory.exists() {
            return Err(shinu::Error::Invalid(format!(
                "diff checkpoint {} requires missing base checkpoint {}",
                checkpoint.id, base
            )));
        }
        shinu::vm::merge_snapshot_memory(&base_memory, &memory, destination)
    } else {
        shinu::btrfs::clone_for(&memory, destination, 0, 0)
    }
}

fn set_head(state: &mut State, space_id: Uuid, project: &str, head: Uuid) -> shinu::Result<()> {
    let space = state
        .spaces
        .iter_mut()
        .find(|space| space.id == space_id && space.project == project)
        .ok_or_else(|| shinu::Error::NotFound(space_id.to_string()))?;
    space.head = Some(head);
    Ok(())
}
fn record_usage(
    db: &Mutex<Connection>,
    project: &str,
    kind: &str,
    space: Option<Uuid>,
    amount: i64,
) -> shinu::Result<()> {
    state::record_usage(&lock_db(db), project, kind, space, amount)
}

fn find_space(db: &Mutex<Connection>, name: &str, project: &str) -> shinu::Result<Space> {
    state::find_space(&lock_db(db), name, project)?
        .ok_or_else(|| shinu::Error::NotFound(name.to_owned()))
}

/// Re-resolves a space by its stable id after the per-space lock is held.
///
/// The name lookup that precedes lock acquisition only chooses which lock to
/// wait on.  A deletion or metadata update can complete while that lookup is
/// waiting, so lifecycle operations must use this state snapshot for every
/// sizing, network, and checkpoint-head decision.  The original name is kept
/// only for the tenant-scoped 404 response.
fn revalidate_space(
    ctx: &Ctx<'_>,
    project: &str,
    id: Uuid,
    not_found: &str,
) -> shinu::Result<Space> {
    let _state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    let state = state::load(&connection)?;
    state
        .spaces
        .into_iter()
        .find(|space| space.id == id && space.project == project)
        .ok_or_else(|| shinu::Error::NotFound(not_found.to_owned()))
}

fn resize_disk_image(image: &Path, disk_mib: u64) -> shinu::Result<()> {
    let size = format!("{disk_mib}M");
    let truncate = std::process::Command::new("truncate")
        .args(["-s", &size])
        .arg(image)
        .status()?;
    if !truncate.success() {
        return Err(shinu::Error::Invalid(format!(
            "truncate failed while growing {}",
            image.display()
        )));
    }
    let fsck = std::process::Command::new("e2fsck")
        .args(["-fp"])
        .arg(image)
        .status()?;
    if !matches!(fsck.code(), Some(0 | 1)) {
        return Err(shinu::Error::Invalid(format!(
            "e2fsck failed while growing {} (exit status {})",
            image.display(),
            fsck.code().unwrap_or(-1)
        )));
    }
    let resize = std::process::Command::new("resize2fs")
        .arg(image)
        .status()?;
    if !resize.success() {
        return Err(shinu::Error::Invalid(format!(
            "resize2fs failed while growing {}",
            image.display()
        )));
    }
    Ok(())
}

struct SpaceSpec {
    name: String,
    image: Option<Image>,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_mib: Option<u64>,
    network: Option<String>,
}

fn create_space(ctx: &Ctx<'_>, project: &str, spec: SpaceSpec) -> shinu::Result<Value> {
    let SpaceSpec {
        name,
        image,
        vcpus,
        mem_mib,
        disk_mib,
        network,
    } = spec;
    state::validate_network_name(network.as_deref())?;
    ensure_positive_size("vcpus", vcpus.map(u64::from))?;
    ensure_positive_size("mem_mib", mem_mib.map(u64::from))?;
    ensure_positive_size("disk_mib", disk_mib)?;
    let limits = effective_limits(ctx, project)?;
    check_vm_sizing(ctx, &limits, vcpus, mem_mib)?;
    let image = image.unwrap_or(Image::Void);
    let base_cfg = shinu::BaseConfig::from_env()?;
    // Building only this requested image avoids turning daemon startup into a
    // four-distro network/download operation.
    shinu::ensure_base(ctx.root, image, &base_cfg)?;
    let base = shinu::base_path(ctx.root, image);
    let base_mib = image_size_mib(&base);
    let requested_disk = disk_mib.unwrap_or(base_mib);
    if requested_disk < base_mib {
        return Err(shinu::Error::Invalid(
            "disk cannot shrink at creation because that could cause data loss".into(),
        ));
    }
    {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        check_space_quota(ctx.root, &connection, project, &limits, requested_disk)?;
    }
    let id = Uuid::new_v4();
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let image_path = shinu::space_image(ctx.root, id);
    shinu::btrfs::clone_for(&base, &image_path, 0, 0)?;
    let mount = ctx.root.join(format!("authorize.{id}.mnt"));
    let result = (|| -> shinu::Result<Value> {
        if requested_disk > base_mib {
            resize_disk_image(&image_path, requested_disk)?;
        }
        let public_key = shinu::vm::prepare(&shinu::vm_dir(ctx.root, id), 0, 0)?;
        // Each image gets its own key: the base is a common ancestor, so a key
        // baked into it would otherwise be shared by every space.
        shinu::vm::authorize(&image_path, &public_key, &mount)?;
        let space = update_state_with_quota(
            ctx.root,
            ctx.db,
            ctx.registry,
            project,
            &limits,
            requested_disk,
            |state| {
                check_name(state, &name, project)?;
                let space = Space {
                    id,
                    name: name.clone(),
                    project: project.to_owned(),
                    image,
                    parent: None,
                    head: None,
                    vcpus,
                    mem_mib,
                    disk_mib,
                    network: network.clone(),
                    expires_at: None,

                    created_at: Utc::now(),
                };
                state.spaces.push(space.clone());
                Ok(space)
            },
        )?;
        record_usage(ctx.db, project, "space_created", Some(id), 1)?;
        Ok(serde_json::to_value(space)?)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&image_path);
        let _ = std::fs::remove_dir_all(shinu::vm_dir(ctx.root, id));
        let _ = std::fs::remove_dir_all(&mount);
    }
    result
}

fn fork_space(ctx: &Ctx<'_>, project: &str, ckpt: Uuid, name: String) -> shinu::Result<Value> {
    let limits = effective_limits(ctx, project)?;
    let id = Uuid::new_v4();
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The source checkpoint owns the files cloned below. Holding its lock
    // through the authoritative lookup and final state claim prevents
    // rmckpt/gc from unlinking them between validation and materialization.
    let checkpoint_guard = ctx.registry.checkpoint_lock(ckpt);
    let _checkpoint_guard = checkpoint_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (source_checkpoint, source_space) = {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        let state = state::load(&connection)?;
        let checkpoint = state
            .ckpts
            .iter()
            .find(|checkpoint| checkpoint.id == ckpt && checkpoint.project == project)
            .cloned()
            .ok_or_else(|| shinu::Error::NotFound(ckpt.to_string()))?;
        ensure_snapshot_loadable(&checkpoint)?;
        if let Some(base_id) = checkpoint.base {
            let base = state
                .ckpts
                .iter()
                .find(|candidate| candidate.id == base_id && candidate.project == project)
                .ok_or_else(|| shinu::Error::NotFound(base_id.to_string()))?;
            ensure_snapshot_loadable(base)?;
        }
        let source_space = state
            .spaces
            .iter()
            .find(|space| space.id == checkpoint.space && space.project == project)
            .cloned()
            .ok_or_else(|| shinu::Error::NotFound(checkpoint.space.to_string()))?;
        let source_disk = source_space
            .disk_mib
            .unwrap_or_else(|| image_size_mib(&shinu::ckpt_image(ctx.root, checkpoint.id)));
        check_space_quota(ctx.root, &connection, project, &limits, source_disk)?;
        check_vm_sizing(ctx, &limits, source_space.vcpus, source_space.mem_mib)?;
        (checkpoint, source_space)
    };
    let source = source_checkpoint.id;
    let source_full = source_checkpoint.full;
    let image_path = shinu::space_image(ctx.root, id);
    let snapshot_mem = space_snapshot_mem(ctx.root, id);
    let snapshot_state = space_snapshot_state(ctx.root, id);
    let source_image = shinu::ckpt_image(ctx.root, source);
    shinu::btrfs::clone_for(&source_image, &image_path, 0, 0)?;
    let mount = ctx.root.join(format!("authorize.{id}.mnt"));
    let result = (|| -> shinu::Result<Value> {
        if source_full {
            // A restored guest keeps the sshd and page cache captured in the
            // snapshot, so rewriting authorized_keys on the reflinked disk
            // would be invisible to it and every exec would fall back to a
            // password prompt. Inheriting the source key instead keeps the
            // fork's credentials consistent with the memory it resumes from;
            // the disk already trusts that key because it is a reflink.
            let source_dir = shinu::vm_dir(ctx.root, source_space.id);
            let fork_dir = shinu::vm_dir(ctx.root, id);
            std::fs::create_dir_all(&fork_dir)?;
            for suffix in ["id_ed25519", "id_ed25519.pub"] {
                std::fs::copy(source_dir.join(suffix), fork_dir.join(suffix))?;
            }
        }
        let public_key = shinu::vm::prepare(&shinu::vm_dir(ctx.root, id), 0, 0)?;
        if !source_full {
            // A disk-only fork boots cold, so it can safely be given a
            // distinct key even though its disk starts as a reflink.
            shinu::vm::authorize(&image_path, &public_key, &mount)?;
        }
        if source_full {
            materialize_checkpoint_memory(ctx.root, &source_checkpoint, &snapshot_mem)?;
            shinu::btrfs::clone_for(&shinu::ckpt_state(ctx.root, source), &snapshot_state, 0, 0)?;
        }
        let source_disk = source_space
            .disk_mib
            .unwrap_or_else(|| image_size_mib(&source_image));
        let space = update_state_with_quota(
            ctx.root,
            ctx.db,
            ctx.registry,
            project,
            &limits,
            source_disk,
            |state| {
                check_name(state, &name, project)?;
                shinu::find_ckpt(state, source, project)?;
                let space = Space {
                    id,
                    name: name.clone(),
                    project: project.to_owned(),
                    image: source_space.image,
                    parent: Some(source),
                    head: Some(source),
                    vcpus: source_space.vcpus,
                    mem_mib: source_space.mem_mib,
                    disk_mib: source_space.disk_mib,
                    network: source_space.network.clone(),
                    expires_at: None,

                    created_at: Utc::now(),
                };
                state.spaces.push(space.clone());
                Ok(space)
            },
        )?;
        record_usage(ctx.db, project, "space_created", Some(id), 1)?;
        Ok(serde_json::to_value(space)?)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&image_path);
        let _ = remove_space_snapshot_files(ctx.root, id);
        let _ = std::fs::remove_dir_all(shinu::vm_dir(ctx.root, id));
        let _ = std::fs::remove_dir_all(&mount);
    }
    result
}

fn commit_space(
    ctx: &Ctx<'_>,
    project: &str,
    space: String,
    note: String,
    hot: bool,
    mode: SnapshotMode,
) -> shinu::Result<Value> {
    require_checkpoint_note(&note)?;
    let (space_id, space_name) = {
        let entry = find_space(ctx.db, &space, project)?;
        (entry.id, entry.name)
    };
    let space_guard = ctx.registry.space_lock(space_id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let vm_dir = shinu::vm_dir(ctx.root, space_id);
    let (mode, diff_base) = match mode {
        SnapshotMode::None => (SnapshotMode::None, None),
        requested => {
            let state = snapshot(ctx.db, ctx.registry)?;
            let current_space = state
                .spaces
                .iter()
                .find(|entry| entry.id == space_id && entry.project == project)
                .ok_or_else(|| shinu::Error::NotFound(space_name.clone()))?;
            resolve_snapshot_mode(ctx.root, &state, current_space, requested, full_every())?
        }
    };
    let running = shinu::vm::is_running(&vm_dir);
    let has_snapshot = !matches!(mode, SnapshotMode::None);
    if has_snapshot && !running {
        let kind = match mode {
            SnapshotMode::Full => "full",
            SnapshotMode::Diff => "diff",
            SnapshotMode::None => unreachable!(),
        };
        return Err(shinu::Error::Invalid(format!(
            "a {kind} checkpoint needs a running space; start it or drop --{kind}"
        )));
    }
    if running && !hot && !has_snapshot {
        return Err(shinu::Error::Invalid(format!(
            "stop the space before checkpointing it: {space_name}"
        )));
    }
    if running {
        // A hot commit flushes once, but writes after sync and before reflink
        // completion remain outside the image by design.
        let status = shinu::exec_in_vm(
            &shinu::vm::vsock_path(&vm_dir),
            &shinu::vm::key_path(&vm_dir),
            shinu::VSOCK_SSH_PORT,
            &["sync".to_owned()],
        )?;
        if status != 0 {
            return Err(shinu::Error::Invalid(format!(
                "sync failed for running space {space_name} (exit status {status})"
            )));
        }
    }
    let id = Uuid::new_v4();
    let snapshot_limits = has_snapshot
        .then(|| effective_limits(ctx, project))
        .transpose()?;
    let image = shinu::ckpt_image(ctx.root, id);
    let jail_snapshot_mem = shinu::vm::jail_root(ctx.root, space_id).join("snap.mem");
    let jail_snapshot_state = shinu::vm::jail_root(ctx.root, space_id).join("snap.state");
    let result = (|| -> shinu::Result<Value> {
        shinu::btrfs::clone_for(&shinu::space_image(ctx.root, space_id), &image, 0, 0)?;
        if has_snapshot {
            let kind = match mode {
                SnapshotMode::Full => shinu::vm::SnapshotKind::Full,
                SnapshotMode::Diff => shinu::vm::SnapshotKind::Diff,
                SnapshotMode::None => unreachable!(),
            };
            let (snapshot_mem, snapshot_state) = shinu::vm::snapshot(&vm_dir, kind)?;
            std::fs::rename(snapshot_mem, shinu::ckpt_mem(ctx.root, id))?;
            std::fs::rename(snapshot_state, shinu::ckpt_state(ctx.root, id))?;
        }
        let checkpoint = update_state(ctx.db, ctx.registry, |state| {
            if let Some(limits) = snapshot_limits.as_ref() {
                let new_checkpoint_mib = bytes_to_mib(checkpoint_exclusive(ctx.root, id)?);
                quota::check_disk_limit(
                    current_disk_mib(ctx.root, state, project)?.saturating_add(new_checkpoint_mib),
                    0,
                    limits,
                )?;
            }
            if let Some(base) = diff_base.as_ref() {
                let still_present = state.ckpts.iter().any(|checkpoint| {
                    checkpoint.id == base.id
                        && checkpoint.space == space_id
                        && checkpoint.project == project
                });
                if !still_present {
                    return Err(shinu::Error::Invalid(format!(
                        "diff checkpoint base {} was deleted before commit completed",
                        base.id
                    )));
                }
            }
            append_checkpoint(
                state,
                space_id,
                project,
                id,
                note,
                CkptFlags {
                    auto: false,
                    full: has_snapshot,
                    base: diff_base.as_ref().map(|checkpoint| checkpoint.id),
                    update_head: true,
                },
            )
        })?;
        checkpoint_json(&checkpoint)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&image);
        let _ = remove_file_if_missing(&shinu::ckpt_mem(ctx.root, id));
        let _ = remove_file_if_missing(&shinu::ckpt_state(ctx.root, id));
        let _ = remove_file_if_missing(&jail_snapshot_mem);
        let _ = remove_file_if_missing(&jail_snapshot_state);
    }
    result
}

fn checkout_space(
    ctx: &Ctx<'_>,
    project: &str,
    space: String,
    commit: Uuid,
) -> shinu::Result<Value> {
    let initial = find_space(ctx.db, &space, project)?;
    let space_id = initial.id;
    let space_guard = ctx.registry.space_lock(space_id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The target files remain live through the auto-commit, reflink, memory
    // materialization, and final HEAD update. GC/rmckpt use this same lock
    // before claiming the target row.
    let checkpoint_guard = ctx.registry.checkpoint_lock(commit);
    let _checkpoint_guard = checkpoint_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (target, current_head, space_name, image_kind, vcpus, mem_mib) = {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        let state = state::load(&connection)?;
        let entry = state
            .spaces
            .iter()
            .find(|entry| entry.id == space_id && entry.project == project)
            .ok_or_else(|| shinu::Error::NotFound(space.clone()))?;
        let vm_dir = shinu::vm_dir(ctx.root, entry.id);
        if shinu::vm::is_running(&vm_dir) {
            return Err(shinu::Error::Invalid(format!(
                "stop the space before checking it out: {}",
                entry.name
            )));
        }
        let target = state
            .ckpts
            .iter()
            .find(|checkpoint| checkpoint.id == commit && checkpoint.project == project)
            .cloned()
            .ok_or_else(|| shinu::Error::NotFound(commit.to_string()))?;
        (
            target,
            entry.head,
            entry.name.clone(),
            entry.image,
            entry.vcpus,
            entry.mem_mib,
        )
    };
    ensure_snapshot_loadable(&target)?;
    if let Some(base_id) = target.base {
        // `target` retains a reference to its base in state, so the base's
        // files cannot be claimed while the target checkpoint lock is held.
        let base = {
            let _state_guard = lock_state(ctx.registry);
            let connection = lock_db(ctx.db);
            let state = state::load(&connection)?;
            state
                .ckpts
                .iter()
                .find(|checkpoint| checkpoint.id == base_id && checkpoint.project == project)
                .cloned()
                .ok_or_else(|| shinu::Error::NotFound(base_id.to_string()))?
        };
        ensure_snapshot_loadable(&base)?;
        if !base.full || base.base.is_some() {
            return Err(shinu::Error::Invalid(format!(
                "diff checkpoint {} does not have a standalone full base {}",
                target.id, base_id
            )));
        }
    }

    let auto_id = Uuid::new_v4();
    let auto_image = shinu::ckpt_image(ctx.root, auto_id);
    shinu::btrfs::clone_for(&shinu::space_image(ctx.root, space_id), &auto_image, 0, 0)?;
    let short_id = commit.to_string().chars().take(8).collect::<String>();
    let auto_note = format!("auto before checkout {short_id}");
    let auto_checkpoint = update_state(ctx.db, ctx.registry, |state| {
        let entry = shinu::find(state, &space_name, project)?;
        if entry.id != space_id {
            return Err(shinu::Error::NotFound(space_name.clone()));
        }
        let checkpoint = Ckpt {
            id: auto_id,
            space: space_id,
            project: project.to_owned(),
            parent: current_head,
            auto: true,
            full: false,
            base: None,
            note: auto_note,
            created_at: Utc::now(),
            snapshot_version: None,
        };
        state.ckpts.push(checkpoint.clone());
        Ok(checkpoint)
    })?;

    // Keep the VM directory and keypair: changing that identity would
    // invalidate credentials already used by the daemon to reach this space.
    let vm_dir = shinu::vm_dir(ctx.root, space_id);
    let public_key = std::fs::read_to_string(shinu::vm::key_path(&vm_dir).with_extension("pub"))?;
    let image = shinu::space_image(ctx.root, space_id);
    shinu::btrfs::clone_for(&shinu::ckpt_image(ctx.root, target.id), &image, 0, 0)?;
    let mount = ctx.root.join(format!("authorize.checkout.{space_id}.mnt"));
    shinu::vm::authorize(&image, &public_key, &mount)?;
    let snapshot_mem = space_snapshot_mem(ctx.root, space_id);
    let snapshot_state = space_snapshot_state(ctx.root, space_id);
    remove_space_snapshot_files(ctx.root, space_id)?;
    if target.full {
        if let Err(error) = materialize_checkpoint_memory(ctx.root, &target, &snapshot_mem) {
            let _ = remove_space_snapshot_files(ctx.root, space_id);
            return Err(error);
        }
        if let Err(error) = shinu::btrfs::clone_for(
            &shinu::ckpt_state(ctx.root, target.id),
            &snapshot_state,
            0,
            0,
        ) {
            let _ = remove_space_snapshot_files(ctx.root, space_id);
            return Err(error);
        }
    }
    update_state(ctx.db, ctx.registry, |state| {
        shinu::find_ckpt(state, target.id, project)?;
        set_head(state, space_id, project, target.id)?;
        Ok(())
    })?;
    if target.full {
        let (network, previous_running) = {
            let state = snapshot(ctx.db, ctx.registry)?;
            let network = state
                .spaces
                .iter()
                .find(|space| space.id == space_id && space.project == project)
                .and_then(|space| space.network.clone());
            let previous_running =
                running_network_members(ctx.root, &state, project, network.as_deref());
            (network, previous_running)
        };
        let _ = start_vm_with_pending_restore(
            ctx,
            space_id,
            image_kind,
            vcpus,
            mem_mib,
            Some(&target),
        )?;
        let state = snapshot(ctx.db, ctx.registry)?;
        let current_running =
            refresh_network_rules(ctx, &state, project, network.as_deref(), &previous_running)?;
        let all_members = network_members(&state, project, network.as_deref());
        sync_network_hosts(ctx, &current_running, &all_members);
    }
    Ok(json!({ "head": target.id, "auto_commit": auto_checkpoint.id }))
}

fn remove_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
    let initial = find_space(ctx.db, &name, project)?;
    let id = initial.id;
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current = revalidate_space(ctx, project, id, &name)?;
    let resolved_name = current.name;
    let network = current.network;
    // Capture previous_running before removal for the network rule diff.
    let (state, previous_running, peers) = {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        let mut state = state::load(&connection)?;
        let space = state
            .spaces
            .iter()
            .find(|space| space.id == id && space.project == project)
            .cloned()
            .ok_or_else(|| shinu::Error::NotFound(id.to_string()))?;
        let previous_running =
            running_network_members(ctx.root, &state, project, network.as_deref());
        let peers = peer_ips(&space, &previous_running, ctx.net_cfg);
        state.spaces.retain(|space| space.id != id);
        state::store(&connection, &state)?;
        (state, previous_running, peers)
    };
    shinu::vm::stop_with_peers(&shinu::vm_dir(ctx.root, id), ctx.net_cfg, &peers)?;
    let current_running =
        refresh_network_rules(ctx, &state, project, network.as_deref(), &previous_running)?;
    // The claimed state omits this space, so these are post-removal peers.
    let all_members = network_members(&state, project, network.as_deref());
    sync_network_hosts(ctx, &current_running, &all_members);
    // Any deletion failure leaves an orphan for gc, not a dangling record.
    let image = shinu::space_image(ctx.root, id);
    remove_file_if_missing(&image)?;
    remove_space_snapshot_files(ctx.root, id)?;
    match std::fs::remove_dir_all(shinu::vm_dir(ctx.root, id)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(json!({ "removed": resolved_name, "id": id }))
}
fn remove_checkpoint(ctx: &Ctx<'_>, project: &str, id: Uuid) -> shinu::Result<Value> {
    // Serialize the claim with every consumer that can read these files. The
    // row and its references are re-evaluated under state+DB locks, after the
    // checkpoint lock has excluded checkout, fork, GC, and other removals.
    let checkpoint_guard = ctx.registry.checkpoint_lock(id);
    let _checkpoint_guard = checkpoint_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    update_state(ctx.db, ctx.registry, |state| {
        let checkpoint = state
            .ckpts
            .iter()
            .find(|checkpoint| checkpoint.id == id && checkpoint.project == project)
            .ok_or_else(|| shinu::Error::NotFound(id.to_string()))?;
        let referenced = shinu::is_referenced(state, checkpoint.id);
        if !referenced.is_empty() {
            return Err(shinu::Error::Invalid(format!(
                "checkpoint {id} is still referenced by: {}",
                referenced.join(", ")
            )));
        }
        state.ckpts.retain(|entry| entry.id != id);
        Ok(())
    })?;
    // Keep the checkpoint lock through unlinking. A consumer that already
    // holds it finishes before the claim; later consumers see the missing row.
    remove_file_if_missing(&shinu::ckpt_image(ctx.root, id))?;
    remove_file_if_missing(&shinu::ckpt_mem(ctx.root, id))?;
    remove_file_if_missing(&shinu::ckpt_state(ctx.root, id))?;
    Ok(json!({ "removed": id }))
}

fn list_spaces(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let state = snapshot(ctx.db, ctx.registry)?;
    let mut spaces = Vec::new();
    for space in state.spaces.iter().filter(|space| space.project == project) {
        let mut value = serde_json::to_value(space)?;
        if let Some(object) = value.as_object_mut() {
            let size =
                shinu::btrfs::exclusive(&shinu::space_image(ctx.root, space.id)).unwrap_or(0);
            object.insert("exclusive".into(), Value::from(size));
            object.insert(
                "running".into(),
                Value::from(shinu::vm::is_running(&shinu::vm_dir(ctx.root, space.id))),
            );
        }
        spaces.push(value);
    }
    let mut checkpoints = Vec::new();
    for checkpoint in state
        .ckpts
        .iter()
        .filter(|checkpoint| checkpoint.project == project)
    {
        let mut value = checkpoint_json(checkpoint)?;
        if let Some(object) = value.as_object_mut() {
            // Missing checkpoint files are represented as zero by the probe;
            // listing must not wait behind a long-running materialization.
            let size = checkpoint_exclusive(ctx.root, checkpoint.id).unwrap_or(0);
            object.insert("exclusive".into(), Value::from(size));
        }
        checkpoints.push(value);
    }
    Ok(json!({ "spaces": spaces, "ckpts": checkpoints }))
}
fn list_images(ctx: &Ctx<'_>) -> Value {
    let images = Image::all()
        .iter()
        .copied()
        .map(|image| {
            json!({
                "image": image.to_string(),
                "built": shinu::base_path(ctx.root, image).exists(),
            })
        })
        .collect::<Vec<_>>();
    Value::Array(images)
}

fn start_vm_with_pending_restore(
    ctx: &Ctx<'_>,
    id: Uuid,
    image: Image,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    restore_checkpoint: Option<&Ckpt>,
) -> shinu::Result<(PathBuf, bool)> {
    let snapshot_mem = space_snapshot_mem(ctx.root, id);
    let snapshot_state = space_snapshot_state(ctx.root, id);
    let has_mem = snapshot_mem.exists();
    let has_state = snapshot_state.exists();
    if has_mem != has_state {
        remove_space_snapshot_files(ctx.root, id)?;
    }
    let has_restore = has_mem && has_state;
    if has_restore {
        restore_checkpoint.map_or(Ok(()), ensure_snapshot_loadable)?;
    }
    let restore = has_restore.then(|| shinu::vm::RestoreFiles {
        mem: &snapshot_mem,
        state: &snapshot_state,
    });
    let result = shinu::vm::start(
        ctx.root,
        id,
        image,
        shinu::vm::Sizing { vcpus, mem_mib },
        ctx.vm_cfg,
        ctx.net_cfg,
        restore.as_ref(),
    );
    if has_restore {
        let cleanup = remove_space_snapshot_files(ctx.root, id);
        return match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), _) => Err(error),
        };
    }
    result
}

fn start_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
    let initial = {
        let connection = lock_db(ctx.db);
        state::find_space(&connection, &name, project)?
            .ok_or_else(|| shinu::Error::NotFound(name.clone()))?
    };
    let space_guard = ctx.registry.space_lock(initial.id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let space = revalidate_space(ctx, project, initial.id, &name)?;
    let limits = effective_limits(ctx, project)?;
    check_vm_sizing(ctx, &limits, space.vcpus, space.mem_mib)?;
    let (already_running, state, previous_running) =
        space_start_state(ctx, project, &space, &limits)?;
    let restore_checkpoint = space
        .head
        .and_then(|head| state.ckpts.iter().find(|checkpoint| checkpoint.id == head));
    let booted = if already_running {
        false
    } else {
        start_vm_with_pending_restore(
            ctx,
            space.id,
            space.image,
            space.vcpus,
            space.mem_mib,
            restore_checkpoint,
        )?
        .1
    };
    let current_running = refresh_network_rules(
        ctx,
        &state,
        project,
        space.network.as_deref(),
        &previous_running,
    )?;
    let all_members = network_members(&state, project, space.network.as_deref());
    sync_network_hosts(ctx, &current_running, &all_members);
    Ok(json!({ "booted": booted }))
}
fn stop_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
    let initial = {
        let connection = lock_db(ctx.db);
        state::find_space(&connection, &name, project)?
            .ok_or_else(|| shinu::Error::NotFound(name.clone()))?
    };
    let space_guard = ctx.registry.space_lock(initial.id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let space = revalidate_space(ctx, project, initial.id, &name)?;
    let (state, previous_running, peers) = {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        let state = state::load(&connection)?;
        let previous_running =
            running_network_members(ctx.root, &state, project, space.network.as_deref());
        let peers = peer_ips(&space, &previous_running, ctx.net_cfg);
        (state, previous_running, peers)
    };
    let was_running =
        shinu::vm::stop_with_peers(&shinu::vm_dir(ctx.root, space.id), ctx.net_cfg, &peers)?;
    let current_running = refresh_network_rules(
        ctx,
        &state,
        project,
        space.network.as_deref(),
        &previous_running,
    )?;
    let all_members = network_members(&state, project, space.network.as_deref());
    sync_network_hosts(ctx, &current_running, &all_members);
    Ok(json!({ "was_running": was_running }))
}

fn resize_space(
    ctx: &Ctx<'_>,
    project: &str,
    name: String,
    vcpus: Option<Option<u32>>,
    mem_mib: Option<Option<u32>>,
    disk_mib: Option<Option<u64>>,
) -> shinu::Result<Value> {
    let existing = find_space(ctx.db, &name, project)?;
    let limits = effective_limits(ctx, project)?;
    let space_guard = ctx.registry.space_lock(existing.id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if shinu::vm::is_running(&shinu::vm_dir(ctx.root, existing.id)) {
        return Err(shinu::Error::Invalid(format!(
            "stop the space before resizing it: {name}"
        )));
    }
    // The grow cannot hold the state lock: truncate, e2fsck and resize2fs run
    // for minutes on a multi-gigabyte image. So the allowance is checked twice
    // — once here to fail fast, and again under the lock that stores the new
    // sizes. Only the second check is authoritative: two concurrent grows can
    // both clear this one against the same stale state.
    let (new_vcpus, new_mem_mib, new_disk_mib, image_path, actual_disk, target_disk, grew) = {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        let state = state::load(&connection)?;
        let index = state
            .spaces
            .iter()
            .position(|space| space.id == existing.id && space.project == project)
            .ok_or_else(|| shinu::Error::NotFound(name.clone()))?;
        let current = state.spaces[index].clone();
        let new_vcpus = vcpus.map_or(current.vcpus, |value| value);
        let new_mem_mib = mem_mib.map_or(current.mem_mib, |value| value);
        ensure_positive_size("vcpus", new_vcpus.map(u64::from))?;
        ensure_positive_size("mem_mib", new_mem_mib.map(u64::from))?;
        check_vm_sizing(ctx, &limits, new_vcpus, new_mem_mib)?;

        let image_path = shinu::space_image(ctx.root, current.id);
        let current_disk = space_size_mib(ctx.root, &current);
        let actual_disk = image_size_mib(&image_path);
        // A fork may inherit a larger allocation than an older checkpoint file;
        // compare requested capacity with both the declaration and the file so a
        // resize to the declared value still grows the guest disk.
        let minimum_disk = current_disk.max(actual_disk);
        let (new_disk_mib, target_disk) = match disk_mib {
            None => (current.disk_mib, current_disk),
            Some(None) => {
                let base = shinu::base_path(ctx.root, current.image);
                let default_disk = if base.exists() {
                    image_size_mib(&base)
                } else {
                    current_disk
                };
                if minimum_disk > default_disk {
                    return Err(shinu::Error::Invalid(
                        "disk cannot shrink because that could cause data loss".into(),
                    ));
                }
                (None, default_disk)
            }
            Some(Some(requested)) => {
                ensure_positive_size("disk_mib", Some(requested))?;
                if requested < minimum_disk {
                    return Err(shinu::Error::Invalid(
                        "disk cannot shrink because that could cause data loss".into(),
                    ));
                }
                (Some(requested), requested)
            }
        };
        let grew = target_disk > current_disk;
        if grew {
            let used_without_current =
                current_disk_mib(ctx.root, &state, project)?.saturating_sub(current_disk);
            quota::check_disk_limit(used_without_current, target_disk, &limits)?;
        }
        (
            new_vcpus,
            new_mem_mib,
            new_disk_mib,
            image_path,
            actual_disk,
            target_disk,
            grew,
        )
    };
    if target_disk > actual_disk {
        resize_disk_image(&image_path, target_disk)?;
    }
    // The grow above runs unguarded for minutes on a real image, which is the
    // window another request can commit an allocation in. Tests stand in for
    // that duration by committing one here.
    #[cfg(test)]
    tests::during_resize_grow();
    let (updated, exceeded) = update_state(ctx.db, ctx.registry, |state| {
        let space = state
            .spaces
            .iter_mut()
            .find(|space| space.id == existing.id && space.project == project)
            .ok_or_else(|| shinu::Error::NotFound(name.clone()))?;
        space.vcpus = new_vcpus;
        space.mem_mib = new_mem_mib;
        space.disk_mib = new_disk_mib;
        let updated = space.clone();
        // Only a grow reserves anything, matching the pre-check: a request that
        // just changes vcpus must not start failing because the project is
        // already over its ceiling for unrelated reasons.
        //
        // The image is already grown by this point, so the bytes are spent
        // whether or not the check passes. Record them either way and report the
        // overrun afterwards: dropping the write would leave the larger file
        // uncounted and let the next request overshoot from a stale total.
        let exceeded = if grew {
            quota::check_disk_limit(current_disk_mib(ctx.root, state, project)?, 0, &limits)
        } else {
            Ok(())
        };
        Ok((updated, exceeded))
    })?;
    exceeded?;
    Ok(serde_json::to_value(updated)?)
}

fn touch_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
    let id = {
        let connection = lock_db(ctx.db);
        state::find_space(&connection, &name, project)?
            .ok_or_else(|| shinu::Error::NotFound(name.clone()))?
            .id
    };
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let space = revalidate_space(ctx, project, id, &name)?;
    shinu::vm::touch(&shinu::vm_dir(ctx.root, space.id))?;
    Ok(json!({ "ok": true }))
}

fn gc(ctx: &Ctx<'_>, project: &str, free_below: u64, dry_run: bool) -> shinu::Result<Value> {
    let available = shinu::avail_bytes(ctx.root)?;
    if available >= free_below {
        return Ok(json!({ "dry_run": dry_run, "reclaimed": 0, "deleted": [] }));
    }
    let state = snapshot(ctx.db, ctx.registry)?;
    let retention_days = std::env::var("SHINU_REFLOG_DAYS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(7);
    let retention_secs = retention_days.saturating_mul(24 * 60 * 60);
    let now = Utc::now();
    // Take only ids from the initial snapshot. Each candidate is then
    // re-evaluated under state+DB before its best-effort size probe; this list
    // is only a work queue and never an authority for deletion.
    let candidate_ids = state
        .ckpts
        .iter()
        .filter(|checkpoint| checkpoint.project == project && checkpoint.auto)
        .map(|checkpoint| checkpoint.id)
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for id in candidate_ids {
        let candidate = {
            let _state_guard = lock_state(ctx.registry);
            let connection = lock_db(ctx.db);
            let state = state::load(&connection)?;
            let Some(checkpoint) = state
                .ckpts
                .iter()
                .find(|checkpoint| checkpoint.id == id && checkpoint.project == project)
            else {
                continue;
            };
            let age = now
                .signed_duration_since(checkpoint.created_at)
                .num_seconds();
            if age <= i64::try_from(retention_secs).unwrap_or(i64::MAX)
                || !shinu::is_referenced(&state, checkpoint.id).is_empty()
            {
                continue;
            }
            checkpoint.note.clone()
        };
        // Missing files are represented as zero by this read-only probe. The
        // claim below takes the checkpoint lock only when deletion is needed,
        // so dry-run never waits behind checkout/fork materialization.
        let exclusive = checkpoint_exclusive(ctx.root, id)?;
        candidates.push((id, candidate, exclusive));
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.2));
    if dry_run {
        let deleted = candidates
            .iter()
            .map(|(id, note, exclusive)| json!({ "id": id, "note": note, "exclusive": exclusive }))
            .collect::<Vec<_>>();
        return Ok(json!({ "dry_run": true, "reclaimed": 0, "deleted": deleted }));
    }
    let need = free_below.saturating_sub(available);
    let mut reclaimed = 0;
    let mut deleted = Vec::new();
    for (id, _candidate_note, exclusive) in candidates {
        if reclaimed >= need {
            break;
        }
        let checkpoint_guard = ctx.registry.checkpoint_lock(id);
        let _checkpoint_guard = checkpoint_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Claim one row at a time. No checkpoint lock is retained while a
        // different checkpoint is considered, and no state/DB lock spans the
        // file unlink below.
        let note = {
            let _state_guard = lock_state(ctx.registry);
            let connection = lock_db(ctx.db);
            let mut state = state::load(&connection)?;
            let Some(checkpoint) = state
                .ckpts
                .iter()
                .find(|checkpoint| checkpoint.id == id && checkpoint.project == project)
            else {
                continue;
            };
            let age = now
                .signed_duration_since(checkpoint.created_at)
                .num_seconds();
            if age <= i64::try_from(retention_secs).unwrap_or(i64::MAX)
                || !shinu::is_referenced(&state, id).is_empty()
            {
                continue;
            }
            let note = checkpoint.note.clone();
            state.ckpts.retain(|checkpoint| checkpoint.id != id);
            state::store(&connection, &state)?;
            note
        };
        remove_file_if_missing(&shinu::ckpt_image(ctx.root, id))?;
        remove_file_if_missing(&shinu::ckpt_mem(ctx.root, id))?;
        remove_file_if_missing(&shinu::ckpt_state(ctx.root, id))?;
        reclaimed = reclaimed.saturating_add(exclusive);
        deleted.push(json!({ "id": id, "note": note, "exclusive": exclusive }));
    }
    Ok(json!({ "dry_run": false, "reclaimed": reclaimed, "deleted": deleted }))
}

fn checkpoint_json(checkpoint: &Ckpt) -> shinu::Result<Value> {
    let mut value = serde_json::to_value(checkpoint)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "snapshot".into(),
            Value::String(checkpoint_snapshot_mode(checkpoint).to_owned()),
        );
    }
    Ok(value)
}

fn limits_value(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let limits = effective_limits(ctx, project)?;
    let _state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    let state = state::load(&connection)?;
    let used_spaces = state::count_spaces(&connection, project)?;
    let used_disk = current_disk_mib(ctx.root, &state, project)?;
    let used_running = count_running(ctx.root, &state, project);
    Ok(json!({
        "max_spaces": limits.max_spaces,
        "max_disk_mib": limits.max_disk_mib,
        "max_vcpus": limits.max_vcpus,
        "max_mem_mib": limits.max_mem_mib,
        "max_running": limits.max_running,
        "api_per_min": limits.api_per_min,
        "used": {
            "spaces": used_spaces,
            "disk_mib": used_disk,
            "running": used_running,
        },
    }))
}
fn patch_project_limits(ctx: &Ctx<'_>, project: &str, body: &[u8]) -> shinu::Result<Value> {
    let value = parse_body(body)?;
    let max_spaces = value_patch_u32(&value, "max_spaces")?;
    let max_disk_mib = value_patch_u64(&value, "max_disk_mib")?;
    let max_running = value_patch_u32(&value, "max_running")?;
    let api_per_min = value_patch_u32(&value, "api_per_min")?;
    if max_spaces.is_none()
        && max_disk_mib.is_none()
        && max_running.is_none()
        && api_per_min.is_none()
    {
        return Err(shinu::Error::Invalid(
            "limits set requires at least one limit field".into(),
        ));
    }

    // Serialize the nullable read-modify-write with the same state-then-db
    // order used by all other state mutations.
    let state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    let existing = state::project_limit_overrides(&connection, project)?;
    let (current_spaces, current_disk_mib, current_running, current_api_per_min) =
        existing.unwrap_or((None, None, None, None));
    state::set_project_limits(
        &connection,
        project,
        max_spaces.unwrap_or(current_spaces),
        max_disk_mib.unwrap_or(current_disk_mib),
        max_running.unwrap_or(current_running),
        api_per_min.unwrap_or(current_api_per_min),
    )?;
    drop(connection);
    drop(state_guard);
    limits_value(ctx, project)
}

fn clear_project_limits(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let _state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    state::clear_project_limits(&connection, project)?;
    Ok(json!({ "project": project, "cleared": true }))
}

struct DiffSpec {
    space: String,
    from: Option<Uuid>,
    to: Option<Uuid>,
    all: bool,
    limit: usize,
}

fn diff_space(ctx: &Ctx<'_>, project: &str, spec: DiffSpec) -> shinu::Result<Value> {
    let state = snapshot(ctx.db, ctx.registry)?;
    let mut temporary_images = Vec::new();
    let result = (|| -> shinu::Result<DiffResult> {
        let mut checkpoint_image = |id| -> shinu::Result<PathBuf> {
            let path = copy_checkpoint_image_for_diff(ctx, id)?;
            temporary_images.push(path.clone());
            Ok(path)
        };
        let (old_image, new_image) = match (spec.from, spec.to) {
            (Some(from), Some(to)) => {
                shinu::find_ckpt(&state, from, project)?;
                shinu::find_ckpt(&state, to, project)?;
                (checkpoint_image(from)?, checkpoint_image(to)?)
            }
            (Some(from), None) => {
                let space = shinu::find(&state, &spec.space, project)?;
                shinu::find_ckpt(&state, from, project)?;
                (
                    checkpoint_image(from)?,
                    shinu::space_image(ctx.root, space.id),
                )
            }
            (None, Some(to)) => {
                if let Ok(from) = spec.space.parse::<Uuid>() {
                    shinu::find_ckpt(&state, from, project)?;
                    shinu::find_ckpt(&state, to, project)?;
                    (checkpoint_image(from)?, checkpoint_image(to)?)
                } else {
                    let space = shinu::find(&state, &spec.space, project)?;
                    shinu::find_ckpt(&state, to, project)?;
                    (
                        shinu::space_image(ctx.root, space.id),
                        checkpoint_image(to)?,
                    )
                }
            }
            (None, None) => {
                let space = shinu::find(&state, &spec.space, project)?;
                let head = space.head.ok_or_else(|| {
                    shinu::Error::Invalid(format!("space {} has no HEAD checkpoint", space.name))
                })?;
                shinu::find_ckpt(&state, head, project)?;
                (
                    checkpoint_image(head)?,
                    shinu::space_image(ctx.root, space.id),
                )
            }
        };
        let limit = spec.limit.min(MAX_DIFF_LIMIT);
        diff_images(
            &old_image,
            &new_image,
            ctx.root,
            DiffOptions {
                all: spec.all,
                limit,
            },
        )
    })();
    for path in temporary_images {
        let _ = std::fs::remove_file(path);
    }
    let result = result?;
    let limit = spec.limit.min(MAX_DIFF_LIMIT);
    Ok(diff_json(&result, spec.all, limit))
}

fn diff_json(result: &DiffResult, all: bool, limit: usize) -> Value {
    let entries = result
        .entries
        .iter()
        .map(|entry| {
            json!({
                "status": diff_status_marker(entry),
                "path": entry.path,
            })
        })
        .collect::<Vec<_>>();
    let exclusions = if all {
        Vec::new()
    } else {
        DEFAULT_EXCLUSIONS.to_vec()
    };
    let total = result.added + result.removed + result.modified;
    json!({
        "comparison": "size_or_mtime",
        "entries": entries,
        "added": result.added,
        "removed": result.removed,
        "modified": result.modified,
        "total": total,
        "reported": result.entries.len(),
        "summary": {
            "added": result.added,
            "removed": result.removed,
            "modified": result.modified,
            "total": total,
            "reported": result.entries.len(),
        },
        "limit": limit,
        "truncated": result.truncated,
        "excluded": exclusions,
    })
}

fn diff_status_marker(entry: &DiffEntry) -> &'static str {
    match entry.status {
        DiffStatus::Added => "+",
        DiffStatus::Removed => "-",
        DiffStatus::Modified => "M",
    }
}

fn handle(ctx: &Ctx<'_>, req: Req, project: &str) -> shinu::Result<Value> {
    match req {
        Req::New {
            name,
            image,
            vcpus,
            mem_mib,
            disk_mib,
            network,
        } => create_space(
            ctx,
            project,
            SpaceSpec {
                name,
                image,
                vcpus,
                mem_mib,
                disk_mib,
                network,
            },
        ),
        Req::Resize {
            space,
            vcpus,
            mem_mib,
            disk_mib,
        } => resize_space(ctx, project, space, vcpus, mem_mib, disk_mib),
        Req::Images => Ok(list_images(ctx)),
        Req::Fork { ckpt, name } => fork_space(ctx, project, ckpt, name),
        Req::Commit {
            space,
            note,
            hot,
            snapshot,
        } => commit_space(ctx, project, space, note, hot, snapshot),
        Req::Checkout { space, commit } => checkout_space(ctx, project, space, commit),
        Req::Log { space } => {
            let state = snapshot(ctx.db, ctx.registry)?;
            let entry = shinu::find(&state, &space, project)?;
            let commits = shinu::log_chain(&state, entry)
                .into_iter()
                .map(checkpoint_json)
                .collect::<shinu::Result<Vec<_>>>()?;
            Ok(json!({ "commits": commits }))
        }
        Req::Reflog { space } => {
            let state = snapshot(ctx.db, ctx.registry)?;
            let entry = shinu::find(&state, &space, project)?;
            let entries = shinu::reflog_entries(&state, entry)
                .into_iter()
                .map(checkpoint_json)
                .collect::<shinu::Result<Vec<_>>>()?;
            Ok(json!({ "entries": entries }))
        }
        Req::Diff {
            space,
            from,
            to,
            all,
            limit,
        } => diff_space(
            ctx,
            project,
            DiffSpec {
                space,
                from,
                to,
                all,
                limit,
            },
        ),
        Req::Rm { space } => remove_space(ctx, project, space),
        Req::RmCkpt { ckpt } => remove_checkpoint(ctx, project, ckpt),
        Req::Ls => list_spaces(ctx, project),
        Req::Start { space } => start_space(ctx, project, space),
        Req::Stop { space } => stop_space(ctx, project, space),
        Req::Touch { space } => touch_space(ctx, project, space),
        Req::Exec { .. } => Err(shinu::Error::Invalid(
            "exec requires the streaming handler".into(),
        )),
        Req::Gc {
            free_below,
            dry_run,
        } => gc(ctx, project, free_below, dry_run),
        Req::Usage { from, to } => {
            let connection = lock_db(ctx.db);
            state::usage_summary(&connection, project, from, to)
        }
        Req::Limits => limits_value(ctx, project),
    }
}
const MAX_EXEC_SESSION_ID_BYTES: usize = 64;

fn validate_exec_session_id(session: &str) -> shinu::Result<()> {
    if session.is_empty() {
        return Err(shinu::Error::Invalid("session id must not be empty".into()));
    }
    if session.len() > MAX_EXEC_SESSION_ID_BYTES {
        return Err(shinu::Error::Invalid(format!(
            "session id must be at most {MAX_EXEC_SESSION_ID_BYTES} bytes"
        )));
    }
    if !session
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(shinu::Error::Invalid(
            "session id may contain only ASCII letters, digits, '-' and '_'".into(),
        ));
    }
    Ok(())
}

fn exec_session_value(value: &Value) -> shinu::Result<Option<String>> {
    match value.get("session") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let session = value
                .as_str()
                .ok_or_else(|| shinu::Error::Invalid("session must be a string".into()))?;
            validate_exec_session_id(session)?;
            Ok(Some(session.to_owned()))
        }
    }
}

fn exec_request(body: &[u8], space: String) -> shinu::Result<Req> {
    let value = parse_body(body)?;
    let (cmd, stdin) = exec_command_value(&value)?;
    let session = exec_session_value(&value)?;
    Ok(Req::Exec {
        space,
        cmd,
        stdin,
        session,
    })
}

fn exec_command_value(value: &Value) -> shinu::Result<(Vec<String>, Option<String>)> {
    let command = value
        .get("cmd")
        .and_then(Value::as_array)
        .ok_or_else(|| shinu::Error::Invalid("body field cmd must be an array".into()))?;
    let command = command
        .iter()
        .map(|argument| {
            argument
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| shinu::Error::Invalid("cmd arguments must be strings".into()))
        })
        .collect::<shinu::Result<Vec<_>>>()?;
    if command.is_empty() {
        return Err(shinu::Error::Invalid("exec needs a command".into()));
    }
    let stdin = match value.get("stdin") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| shinu::Error::Invalid("stdin must be a string".into()))?
                .to_owned(),
        ),
    };
    Ok((command, stdin))
}

#[derive(Debug)]
enum Endpoint {
    Root,
    LoginPage,
    RegisterPage,
    AppPage,
    Asset(&'static str),
    ConsoleRegister,
    ConsoleLogin,
    ConsoleLogout,
    ConsoleMe,
    ConsoleTokens,
    ConsoleToken(String),
    Spaces,
    Images,
    Usage,
    Limits,
    ProjectLimits(String),
    Rm(String),
    Start(String),
    Stop(String),
    Exec(String),
    Proxy {
        space: String,
        port: u16,
        path: String,
    },
    Push(String),
    Pull(String),
    Vnc(String),
    Commit(String),
    Log(String),
    Reflog(String),
    Diff(String),
    Checkout(String),
    Fork(String),
    RmCkpt(String),
    Gc,
}

fn route(path: &str) -> Option<Endpoint> {
    let (path_without_query, query) = path.split_once('?').map_or((path, ""), |parts| parts);
    match path_without_query {
        "/" => return Some(Endpoint::Root),
        "/login" => return Some(Endpoint::LoginPage),
        "/register" => return Some(Endpoint::RegisterPage),
        "/app" => return Some(Endpoint::AppPage),
        "/assets/app.css" => return Some(Endpoint::Asset("/assets/app.css")),
        "/assets/app.js" => return Some(Endpoint::Asset("/assets/app.js")),
        "/console/register" => return Some(Endpoint::ConsoleRegister),
        "/console/login" => return Some(Endpoint::ConsoleLogin),
        "/console/logout" => return Some(Endpoint::ConsoleLogout),
        "/console/me" => return Some(Endpoint::ConsoleMe),
        "/console/tokens" => return Some(Endpoint::ConsoleTokens),
        _ => {}
    }
    if let Some(endpoint) = proxy_route(path_without_query, query) {
        return Some(endpoint);
    }
    let segments = path_without_query
        .split('/')
        .map(decode_segment)
        .collect::<Option<Vec<_>>>()?;
    if segments.first().map(String::as_str) != Some("")
        || segments.get(1).map(String::as_str) != Some("v1")
    {
        if segments.len() == 4
            && segments[0].is_empty()
            && segments[1] == "console"
            && segments[2] == "tokens"
            && !segments[3].is_empty()
        {
            return Some(Endpoint::ConsoleToken(segments[3].clone()));
        }
        return None;
    }
    if segments.len() == 3 && segments[2] == "spaces" {
        return Some(Endpoint::Spaces);
    }
    if segments.len() == 3 && segments[2] == "images" {
        return Some(Endpoint::Images);
    }
    if segments.len() == 3 && segments[2] == "usage" {
        return Some(Endpoint::Usage);
    }
    if segments.len() == 5
        && segments[2] == "projects"
        && segments[4] == "limits"
        && !segments[3].is_empty()
    {
        return Some(Endpoint::ProjectLimits(segments[3].clone()));
    }
    if segments.len() == 3 && segments[2] == "limits" {
        return Some(Endpoint::Limits);
    }
    if segments.len() == 3 && segments[2] == "gc" {
        return Some(Endpoint::Gc);
    }
    if segments.len() == 4 && segments[2] == "spaces" {
        return Some(Endpoint::Rm(segments[3].clone()));
    }
    if segments.len() == 5 && segments[2] == "spaces" {
        let name = segments[3].clone();
        return match segments[4].as_str() {
            "start" => Some(Endpoint::Start(name)),
            "stop" => Some(Endpoint::Stop(name)),
            "exec" => Some(Endpoint::Exec(name)),
            "push" => Some(Endpoint::Push(name)),
            "pull" => Some(Endpoint::Pull(name)),
            "vnc" => Some(Endpoint::Vnc(name)),
            "commits" => Some(Endpoint::Commit(name)),
            "log" => Some(Endpoint::Log(name)),
            "reflog" => Some(Endpoint::Reflog(name)),
            "diff" => Some(Endpoint::Diff(name)),
            "checkout" => Some(Endpoint::Checkout(name)),
            _ => None,
        };
    }
    if segments.len() == 4 && segments[2] == "commits" {
        return Some(Endpoint::RmCkpt(segments[3].clone()));
    }
    if segments.len() == 5 && segments[2] == "commits" && segments[4] == "fork" {
        return Some(Endpoint::Fork(segments[3].clone()));
    }
    None
}

fn proxy_route(path: &str, query: &str) -> Option<Endpoint> {
    let mut segments = path.splitn(7, '/');
    if segments.next() != Some("")
        || segments.next() != Some("v1")
        || segments.next() != Some("spaces")
    {
        return None;
    }
    let space = decode_segment(segments.next()?)?;
    if space.is_empty() || segments.next() != Some("proxy") {
        return None;
    }
    let port = decode_segment(segments.next()?)?.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    let guest_path = segments
        .next()
        .map_or_else(|| "/".to_owned(), |suffix| format!("/{suffix}"));
    let path = if query.is_empty() {
        guest_path
    } else {
        format!("{guest_path}?{query}")
    };
    Some(Endpoint::Proxy { space, port, path })
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    if !bytes.contains(&b'%') {
        return Some(segment.to_owned());
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let high = hex_digit(bytes[index + 1])?;
            let low = hex_digit(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}
fn usage_query(path: &str) -> shinu::Result<(Option<i64>, Option<i64>)> {
    let Some((_, query)) = path.split_once('?') else {
        return Ok((None, None));
    };
    let mut from = None;
    let mut to = None;
    if query.is_empty() {
        return Ok((None, None));
    }
    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| shinu::Error::Invalid("usage query must use key=value".into()))?;
        let parsed = value.parse::<i64>().map_err(|error| {
            shinu::Error::Invalid(format!(
                "usage query {key} must be a unix timestamp: {error}"
            ))
        })?;
        match key {
            "from" if from.is_none() => from = Some(parsed),
            "to" if to.is_none() => to = Some(parsed),
            "from" | "to" => {
                return Err(shinu::Error::Invalid(format!(
                    "duplicate usage query key: {key}"
                )));
            }
            _ => {
                return Err(shinu::Error::Invalid(format!(
                    "unknown usage query key: {key}"
                )));
            }
        }
    }
    Ok((from, to))
}
fn diff_request(path: &str, space: String) -> shinu::Result<Req> {
    let mut from = None;
    let mut to = None;
    let mut all = false;
    let mut limit = DEFAULT_DIFF_LIMIT;
    if let Some((_, query)) = path.split_once('?') {
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (raw_key, raw_value) = pair
                .split_once('=')
                .ok_or_else(|| shinu::Error::Invalid("diff query must use key=value".into()))?;
            let key = decode_segment(raw_key)
                .ok_or_else(|| shinu::Error::Invalid("diff query key is not valid UTF-8".into()))?;
            let value = decode_segment(raw_value).ok_or_else(|| {
                shinu::Error::Invalid(format!("diff query value for {key} is invalid"))
            })?;
            match key.as_str() {
                "from" | "commit" => {
                    if from.is_some() {
                        return Err(shinu::Error::Invalid(
                            "duplicate diff query key: from".into(),
                        ));
                    }
                    from = Some(parse_diff_commit(&key, &value)?);
                }
                "to" => {
                    if to.is_some() {
                        return Err(shinu::Error::Invalid("duplicate diff query key: to".into()));
                    }
                    to = Some(parse_diff_commit(&key, &value)?);
                }
                "all" => {
                    all = match value.as_str() {
                        "1" | "true" => true,
                        "0" | "false" => false,
                        _ => {
                            return Err(shinu::Error::Invalid(
                                "diff query all must be true or false".into(),
                            ));
                        }
                    };
                }
                "limit" => {
                    let parsed = value.parse::<usize>().map_err(|error| {
                        shinu::Error::Invalid(format!("diff query limit is invalid: {error}"))
                    })?;
                    limit = parsed.min(MAX_DIFF_LIMIT);
                }
                _ => {
                    return Err(shinu::Error::Invalid(format!(
                        "unknown diff query key: {key}"
                    )));
                }
            }
        }
    }
    Ok(Req::Diff {
        space,
        from,
        to,
        all,
        limit,
    })
}

fn parse_diff_commit(key: &str, value: &str) -> shinu::Result<Uuid> {
    Uuid::parse_str(value).map_err(|error| {
        shinu::Error::Invalid(format!("diff query {key} is not a commit id: {error}"))
    })
}

fn method_allowed(endpoint: &Endpoint, method: &str) -> bool {
    match endpoint {
        Endpoint::Root
        | Endpoint::LoginPage
        | Endpoint::RegisterPage
        | Endpoint::AppPage
        | Endpoint::Asset(_)
        | Endpoint::ConsoleMe
        | Endpoint::Images => method == "GET",
        Endpoint::ConsoleRegister | Endpoint::ConsoleLogin | Endpoint::ConsoleLogout => {
            method == "POST"
        }
        Endpoint::ConsoleTokens => method == "GET" || method == "POST",
        Endpoint::ConsoleToken(_) => method == "DELETE",
        Endpoint::Spaces => method == "GET" || method == "POST",
        Endpoint::Usage
        | Endpoint::Limits
        | Endpoint::Log(_)
        | Endpoint::Reflog(_)
        | Endpoint::Diff(_) => method == "GET",
        Endpoint::ProjectLimits(_) => matches!(method, "GET" | "PATCH" | "DELETE"),
        Endpoint::Rm(_) => method == "DELETE" || method == "PATCH",
        Endpoint::RmCkpt(_) => method == "DELETE",
        Endpoint::Start(_)
        | Endpoint::Stop(_)
        | Endpoint::Exec(_)
        | Endpoint::Push(_)
        | Endpoint::Commit(_)
        | Endpoint::Checkout(_)
        | Endpoint::Fork(_)
        | Endpoint::Gc => method == "POST",
        Endpoint::Pull(_) | Endpoint::Vnc(_) => method == "GET",
        Endpoint::Proxy { .. } => {
            matches!(method, "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD")
        }
    }
}

fn parse_body(body: &[u8]) -> shinu::Result<Value> {
    if body.is_empty() {
        return Err(shinu::Error::Invalid("request body is required".into()));
    }
    serde_json::from_slice(body)
        .map_err(|error| shinu::Error::Invalid(format!("invalid JSON body: {error}")))
}

fn value_string(value: &Value, field: &str) -> shinu::Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| shinu::Error::Invalid(format!("body field {field} must be a string")))
}

fn body_string(body: &[u8], field: &str) -> shinu::Result<String> {
    value_string(&parse_body(body)?, field)
}

fn value_bool(value: &Value, field: &str) -> shinu::Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| shinu::Error::Invalid(format!("body field {field} must be a boolean")))
}

fn value_snapshot_mode(value: &Value) -> shinu::Result<SnapshotMode> {
    match value.get("snapshot") {
        None => Ok(SnapshotMode::None),
        Some(Value::String(mode)) => match mode.as_str() {
            "none" => Ok(SnapshotMode::None),
            "full" => Ok(SnapshotMode::Full),
            "diff" => Ok(SnapshotMode::Diff),
            _ => Err(shinu::Error::Invalid(
                "body field snapshot must be one of: none, full, diff".into(),
            )),
        },
        Some(_) => Err(shinu::Error::Invalid(
            "body field snapshot must be a string".into(),
        )),
    }
}

fn value_u64(value: &Value, field: &str) -> shinu::Result<u64> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        shinu::Error::Invalid(format!("body field {field} must be an unsigned integer"))
    })
}

fn value_optional_u32(value: &Value, field: &str) -> shinu::Result<Option<u32>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(|| {
                shinu::Error::Invalid(format!(
                    "body field {field} must be an unsigned 32-bit integer"
                ))
            })
            .map(Some),
    }
}

fn value_optional_u64(value: &Value, field: &str) -> shinu::Result<Option<u64>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => raw
            .as_u64()
            .ok_or_else(|| {
                shinu::Error::Invalid(format!("body field {field} must be an unsigned integer"))
            })
            .map(Some),
    }
}

fn value_patch_u32(value: &Value, field: &str) -> shinu::Result<Option<Option<u32>>> {
    // Absent, null and a number are three distinct PATCH intents: leave alone,
    // reset to the daemon default, or set explicitly.
    match value.get(field) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(raw) => raw
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(|| {
                shinu::Error::Invalid(format!(
                    "body field {field} must be an unsigned 32-bit integer or null"
                ))
            })
            .map(|number| Some(Some(number))),
    }
}

fn value_patch_u64(value: &Value, field: &str) -> shinu::Result<Option<Option<u64>>> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(raw) => raw
            .as_u64()
            .ok_or_else(|| {
                shinu::Error::Invalid(format!(
                    "body field {field} must be an unsigned integer or null"
                ))
            })
            .map(|number| Some(Some(number))),
    }
}

fn new_request(body: &[u8]) -> shinu::Result<Req> {
    let value = parse_body(body)?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| shinu::Error::Invalid("body field name must be a string".into()))?;
    let image = match value.get("image") {
        None | Some(Value::Null) => None,
        Some(raw) => {
            let id = raw
                .as_str()
                .ok_or_else(|| shinu::Error::Invalid("body field image must be a string".into()))?;
            Some(id.parse::<Image>().map_err(|error| {
                shinu::Error::Invalid(format!("body field image is invalid: {error}"))
            })?)
        }
    };
    let network = match value.get("network") {
        None | Some(Value::Null) => None,
        Some(raw) => Some(
            raw.as_str()
                .ok_or_else(|| shinu::Error::Invalid("body field network must be a string".into()))?
                .to_owned(),
        ),
    };
    state::validate_network_name(network.as_deref())?;
    Ok(Req::New {
        name,
        image,
        vcpus: value_optional_u32(&value, "vcpus")?,
        mem_mib: value_optional_u32(&value, "mem_mib")?,
        disk_mib: value_optional_u64(&value, "disk_mib")?,
        network,
    })
}

fn resize_request(body: &[u8], space: String) -> shinu::Result<Req> {
    let value = parse_body(body)?;
    if value.get("image").is_some() {
        return Err(shinu::Error::Invalid(
            "image is immutable after space creation".into(),
        ));
    }
    Ok(Req::Resize {
        space,
        vcpus: value_patch_u32(&value, "vcpus")?,
        mem_mib: value_patch_u32(&value, "mem_mib")?,
        disk_mib: value_patch_u64(&value, "disk_mib")?,
    })
}
fn commit_request(body: &[u8], space: String) -> shinu::Result<Req> {
    let value = parse_body(body)?;
    let note = value_string(&value, "note")?;
    let hot = value_bool(&value, "hot")?;
    let snapshot = value_snapshot_mode(&value)?;
    Ok(Req::Commit {
        space,
        note,
        hot,
        snapshot,
    })
}

fn gc_request(body: &[u8]) -> shinu::Result<Req> {
    let value = parse_body(body)?;
    let free_below = value_u64(&value, "free_below")?;
    let dry_run = value_bool(&value, "dry_run")?;
    Ok(Req::Gc {
        free_below,
        dry_run,
    })
}

fn request_for(
    endpoint: Endpoint,
    method: &str,
    body: &[u8],
    from: Option<i64>,
    to: Option<i64>,
) -> shinu::Result<(Req, u16)> {
    match endpoint {
        Endpoint::Spaces if method == "GET" => Ok((Req::Ls, 200)),
        Endpoint::Spaces => Ok((new_request(body)?, 201)),
        Endpoint::Images => Ok((Req::Images, 200)),
        Endpoint::Usage => Ok((Req::Usage { from, to }, 200)),
        Endpoint::Limits => Ok((Req::Limits, 200)),
        Endpoint::Rm(space) if method == "PATCH" => Ok((resize_request(body, space)?, 200)),
        Endpoint::Rm(space) => Ok((Req::Rm { space }, 200)),
        Endpoint::Start(space) => Ok((Req::Start { space }, 200)),
        Endpoint::Stop(space) => Ok((Req::Stop { space }, 200)),
        Endpoint::Commit(space) => Ok((commit_request(body, space)?, 201)),
        Endpoint::Log(space) => Ok((Req::Log { space }, 200)),
        Endpoint::Reflog(space) => Ok((Req::Reflog { space }, 200)),
        Endpoint::Diff(space) => Ok((diff_request("", space)?, 200)),
        Endpoint::Checkout(space) => Ok((
            Req::Checkout {
                space,
                commit: Uuid::parse_str(&body_string(body, "commit")?).map_err(|error| {
                    shinu::Error::Invalid(format!("invalid commit id: {error}"))
                })?,
            },
            200,
        )),
        Endpoint::Fork(commit) => Ok((
            Req::Fork {
                ckpt: Uuid::parse_str(&commit).map_err(|error| {
                    shinu::Error::Invalid(format!("invalid commit id: {error}"))
                })?,
                name: body_string(body, "name")?,
            },
            201,
        )),
        Endpoint::RmCkpt(commit) => Ok((
            Req::RmCkpt {
                ckpt: Uuid::parse_str(&commit).map_err(|error| {
                    shinu::Error::Invalid(format!("invalid commit id: {error}"))
                })?,
            },
            200,
        )),
        Endpoint::Gc => Ok((gc_request(body)?, 200)),
        Endpoint::Exec(space) => Ok((exec_request(body, space)?, 200)),
        _ => Err(shinu::Error::Invalid("endpoint is not an API route".into())),
    }
}

fn transfer_path(path: &str) -> shinu::Result<String> {
    let query = path
        .split_once('?')
        .map(|(_, query)| query)
        .ok_or_else(|| shinu::Error::Invalid("path query parameter is required".into()))?;
    let mut guest_path = None;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| shinu::Error::Invalid("transfer query must use key=value".into()))?;
        let key = decode_segment(raw_key)
            .ok_or_else(|| shinu::Error::Invalid("transfer query is not valid UTF-8".into()))?;
        let value = decode_segment(raw_value)
            .ok_or_else(|| shinu::Error::Invalid("transfer path is not valid UTF-8".into()))?;
        if key != "path" {
            return Err(shinu::Error::Invalid(format!(
                "unknown transfer query key: {key}"
            )));
        }
        if guest_path.replace(value).is_some() {
            return Err(shinu::Error::Invalid(
                "duplicate transfer query key: path".into(),
            ));
        }
    }
    let guest_path = guest_path
        .ok_or_else(|| shinu::Error::Invalid("path query parameter is required".into()))?;
    if !guest_path.starts_with('/') {
        return Err(shinu::Error::Invalid("path must be absolute".into()));
    }
    Ok(guest_path)
}
fn upload_length(content_length: Option<usize>) -> shinu::Result<usize> {
    match content_length {
        None => Err(shinu::Error::Invalid(
            "Content-Length is required for push".into(),
        )),
        Some(length) if length > shinu::MAX_UPLOAD_BYTES => Err(shinu::Error::Invalid(
            "Content-Length exceeds 256 MiB".into(),
        )),
        Some(length) => Ok(length),
    }
}

struct SshTarget {
    vm_dir: PathBuf,
    proxy: String,
}

fn prepare_ssh(ctx: &Ctx<'_>, project: &str, space: &str) -> shinu::Result<SshTarget> {
    let initial = find_space(ctx.db, space, project)?;
    let space_id = initial.id;
    let space_guard = ctx.registry.space_lock(space_id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = revalidate_space(ctx, project, space_id, space)?;
    let limits = effective_limits(ctx, project)?;
    check_vm_sizing(ctx, &limits, entry.vcpus, entry.mem_mib)?;
    let (already_running, state, previous_running) =
        space_start_state(ctx, project, &entry, &limits)?;
    let restore_checkpoint = entry
        .head
        .and_then(|head| state.ckpts.iter().find(|checkpoint| checkpoint.id == head));
    if !already_running {
        start_vm_with_pending_restore(
            ctx,
            space_id,
            entry.image,
            entry.vcpus,
            entry.mem_mib,
            restore_checkpoint,
        )?;
    }
    let current_running = refresh_network_rules(
        ctx,
        &state,
        project,
        entry.network.as_deref(),
        &previous_running,
    )?;
    let all_members = network_members(&state, project, entry.network.as_deref());
    sync_network_hosts(ctx, &current_running, &all_members);
    let vm_dir = shinu::vm_dir(ctx.root, space_id);
    let helper = shinu::vsock_helper()?;
    let proxy = format!(
        "ProxyCommand={} {} {}",
        shinu::shell_quote_word(&helper.to_string_lossy()),
        shinu::shell_quote_word(&shinu::vm::vsock_path(&vm_dir).to_string_lossy()),
        shinu::VSOCK_SSH_PORT
    );
    Ok(SshTarget { vm_dir, proxy })
}

fn ssh_command(target: &SshTarget, remote: &[String]) -> Command {
    let mut command = Command::new("ssh");
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
        .arg(&target.proxy)
        .arg("-i")
        .arg(shinu::vm::key_path(&target.vm_dir))
        .arg("root@shinu")
        .arg("--")
        .arg(shinu::shell_quote(remote));
    command
}

fn session_remote_command(session: &str, command: &[String], has_stdin: bool) -> Vec<String> {
    let session_dir = format!("/tmp/shinu-session-{session}");
    let request_id = Uuid::new_v4().to_string();
    let input_path = format!("{session_dir}/input");
    let pid_path = format!("{session_dir}/pid");
    let lock_path = format!("{session_dir}/lock");
    let stdout_path = format!("{session_dir}/stdout-{request_id}");
    let stderr_path = format!("{session_dir}/stderr-{request_id}");
    let status_path = format!("{session_dir}/status-{request_id}");
    let stdin_path = format!("{session_dir}/stdin-{request_id}");
    let quote = |value: &str| shinu::shell_quote_word(value);
    let input = quote(&input_path);
    let pid = quote(&pid_path);
    let lock = quote(&lock_path);
    let stdout = quote(&stdout_path);
    let stderr = quote(&stderr_path);
    let status = quote(&status_path);
    let stdin = quote(&stdin_path);
    let command = shinu::shell_quote(command);
    let command_line = format!(
        "{command} < {stdin} > {stdout} 2> {stderr}",
        stdin = if has_stdin {
            stdin.as_str()
        } else {
            "'/dev/null'"
        },
    );
    let exit_trap = format!("trap 'printf \"%s\\n\" \"$?\" > {status_path}' 0");
    let status_line = format!("status=$?\ntrap - 0\nprintf '%s\\n' \"$status\" > {status}");
    let command_payload = quote(&format!("{exit_trap}\n{command_line}\n{status_line}"));

    let mut script = String::new();
    script.push_str("session_dir=");
    script.push_str(&quote(&session_dir));
    script.push_str("\ninput_path=");
    script.push_str(&input);
    script.push_str("\npid_path=");
    script.push_str(&pid);
    script.push_str("\nlock_path=");
    script.push_str(&lock);
    script.push_str("\nstdout_path=");
    script.push_str(&stdout);
    script.push_str("\nstderr_path=");
    script.push_str(&stderr);
    script.push_str("\nstatus_path=");
    script.push_str(&status);
    script.push_str("\nstdin_path=");
    script.push_str(&stdin);
    script.push_str("\nstdin_present=");
    script.push_str(if has_stdin { "1" } else { "0" });
    script.push_str("\nstdout_cat=");
    script.push_str("\nstderr_cat=");
    script.push_str(
        r#"
cleanup() {
    if [ -n "$stdout_cat" ]; then
        kill "$stdout_cat" 2>/dev/null || :
    fi
    if [ -n "$stderr_cat" ]; then
        kill "$stderr_cat" 2>/dev/null || :
    fi
    rm -f "$stdout_path" "$stderr_path" "$status_path"
    if [ "$stdin_present" = 1 ]; then
        rm -f "$stdin_path"
    fi
    rm -rf "$lock_path"
}
mkdir -p "$session_dir" || {
    echo "could not create guest session directory" >&2
    exit 255
}
trap cleanup 0 1 2 3 15
if [ "$stdin_present" = 1 ]; then
    cat > "$stdin_path" || exit 255
fi
while ! mkdir "$lock_path" 2>/dev/null; do
    owner=$(cat "$lock_path/pid" 2>/dev/null || :)
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
        rm -rf "$lock_path"
    else
        sleep 0.01
    fi
done
printf '%s\n' "$$" > "$lock_path/pid" || exit 255
if [ ! -p "$input_path" ]; then
    rm -f "$input_path" "$pid_path"
    mkfifo "$input_path" || {
        echo "could not create guest session pipe" >&2
        exit 255
    }
fi
shell_pid=$(cat "$pid_path" 2>/dev/null || :)
if [ -z "$shell_pid" ] || ! kill -0 "$shell_pid" 2>/dev/null; then
    rm -f "$input_path" "$pid_path"
    mkfifo "$input_path" || {
        echo "could not recreate guest session pipe" >&2
        exit 255
    }
    nohup sh -c 'exec 3<> "$1"; exec sh <&3' sh "$input_path" >/dev/null 2>&1 &
    shell_pid=$!
    printf '%s\n' "$shell_pid" > "$pid_path" || exit 255
fi
rm -f "$stdout_path" "$stderr_path" "$status_path" || exit 255
mkfifo "$stdout_path" "$stderr_path" || exit 255
cat "$stdout_path" &
stdout_cat=$!
cat "$stderr_path" >&2 &
stderr_cat=$!
exec 4>"$input_path" || exit 255
"#,
    );
    script.push_str("printf '%s\\n' ");
    script.push_str(&command_payload);
    script.push_str(
        r#" >&4
exec 4>&-
while [ ! -s "$status_path" ]; do
    if ! kill -0 "$shell_pid" 2>/dev/null; then
        echo "guest session shell exited unexpectedly" >&2
        printf '%s\n' 255 > "$status_path"
        break
    fi
    sleep 0.01
done
drain_loops=0
while [ -n "$stdout_cat" ] || [ -n "$stderr_cat" ]; do
    if [ -n "$stdout_cat" ] && ! kill -0 "$stdout_cat" 2>/dev/null; then
        stdout_cat=
    fi
    if [ -n "$stderr_cat" ] && ! kill -0 "$stderr_cat" 2>/dev/null; then
        stderr_cat=
    fi
    if [ -z "$stdout_cat" ] && [ -z "$stderr_cat" ]; then
        break
    fi
    if [ "$drain_loops" -ge 100 ]; then
        break
    fi
    drain_loops=$((drain_loops + 1))
    sleep 0.01
done
if [ -n "$stdout_cat" ]; then
    kill "$stdout_cat" 2>/dev/null || :
    wait "$stdout_cat" 2>/dev/null || :
fi
if [ -n "$stderr_cat" ]; then
    kill "$stderr_cat" 2>/dev/null || :
    wait "$stderr_cat" 2>/dev/null || :
fi
status=$(cat "$status_path" 2>/dev/null || :)
case "$status" in
    ''|*[!0-9]*) status=255 ;;
esac
exit "$status"
"#,
    );
    vec!["sh".to_owned(), "-c".to_owned(), script]
}

fn spawn_ssh(
    target: &SshTarget,
    remote: &[String],
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
) -> shinu::Result<Child> {
    Ok(ssh_command(target, remote)
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()?)
}

fn ssh_output(target: &SshTarget, remote: &[String]) -> shinu::Result<std::process::Output> {
    Ok(ssh_command(target, remote)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

fn remote_path_command(prefix: &str, path: &str) -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        format!("{prefix} {}", shinu::shell_quote_word(path)),
    ]
}

fn guest_stderr(stderr: Vec<u8>, exit: Option<i32>) -> String {
    let message = String::from_utf8_lossy(&stderr).trim().to_owned();
    if message.is_empty() {
        format!(
            "guest command failed with exit status {}",
            exit.unwrap_or(255)
        )
    } else {
        message
    }
}

fn push_file(
    reader: &mut impl Read,
    target: &SshTarget,
    path: &str,
    length: usize,
) -> shinu::Result<usize> {
    let remote = remote_path_command("cat >", path);
    let mut child = spawn_ssh(
        target,
        &remote,
        Stdio::piped(),
        Stdio::null(),
        Stdio::piped(),
    )?;
    let mut stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            abort_child(&mut child);
            return Err(shinu::Error::Invalid("ssh stdin pipe unavailable".into()));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            abort_child(&mut child);
            return Err(shinu::Error::Invalid("ssh stderr pipe unavailable".into()));
        }
    };
    let stderr_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let _ = BufReader::new(stderr).read_to_end(&mut output);
        output
    });
    let mut remaining = length;
    let mut buffer = [0u8; 64 * 1024];
    let copy_result = (|| -> shinu::Result<()> {
        while remaining > 0 {
            let read_len = remaining.min(buffer.len());
            let count = reader.read(&mut buffer[..read_len])?;
            if count == 0 {
                return Err(shinu::Error::Invalid(
                    "request body is shorter than Content-Length".into(),
                ));
            }
            stdin.write_all(&buffer[..count])?;
            remaining -= count;
        }
        Ok(())
    })();
    if let Err(error) = copy_result {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        let _ = stderr_reader.join();
        return Err(error);
    }
    // Closing stdin is the guest command's EOF signal; without it `cat` waits
    // forever even after the declared request body has been copied.
    drop(stdin);
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            let _ = stderr_reader.join();
            return Err(error.into());
        }
    };
    let stderr = stderr_reader
        .join()
        .unwrap_or_else(|_| b"guest stderr reader failed".to_vec());
    if !status.success() {
        return Err(shinu::Error::Invalid(guest_stderr(stderr, status.code())));
    }
    Ok(length)
}
fn abort_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

enum PullFailure {
    BeforeResponse(shinu::Error),
    AfterResponse,
}

fn pull_file(stream: &mut TcpStream, target: &SshTarget, path: &str) -> Result<(), PullFailure> {
    let probe = ssh_output(target, &remote_path_command("test -f", path))
        .map_err(PullFailure::BeforeResponse)?;
    if !probe.status.success() {
        let exists = ssh_output(target, &remote_path_command("test -e", path))
            .map_err(PullFailure::BeforeResponse)?;
        if exists.status.success() {
            return Err(PullFailure::BeforeResponse(shinu::Error::Invalid(
                "path is a directory; tar it first".into(),
            )));
        }
        return Err(PullFailure::BeforeResponse(shinu::Error::NotFound(
            path.to_owned(),
        )));
    }

    let mut child = spawn_ssh(
        target,
        &remote_path_command("cat", path),
        Stdio::null(),
        Stdio::piped(),
        Stdio::piped(),
    )
    .map_err(PullFailure::BeforeResponse)?;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            abort_child(&mut child);
            return Err(PullFailure::BeforeResponse(shinu::Error::Invalid(
                "ssh stdout pipe unavailable".into(),
            )));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            abort_child(&mut child);
            return Err(PullFailure::BeforeResponse(shinu::Error::Invalid(
                "ssh stderr pipe unavailable".into(),
            )));
        }
    };
    let stderr_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let _ = BufReader::new(stderr).read_to_end(&mut output);
        output
    });
    if http::respond_chunked_binary_start(stream).is_err() {
        abort_child(&mut child);
        let _ = stderr_reader.join();
        return Err(PullFailure::AfterResponse);
    }
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = match stdout.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => {
                abort_child(&mut child);
                let _ = stderr_reader.join();
                return Err(PullFailure::AfterResponse);
            }
        };
        if count == 0 {
            break;
        }
        if http::respond_chunk_bytes(stream, &buffer[..count]).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stderr_reader.join();
            return Err(PullFailure::AfterResponse);
        }
    }
    let status = match child.wait() {
        Ok(status) => status,
        Err(_) => {
            abort_child(&mut child);
            let _ = stderr_reader.join();
            return Err(PullFailure::AfterResponse);
        }
    };
    let _stderr = stderr_reader
        .join()
        .unwrap_or_else(|_| b"guest stderr reader failed".to_vec());
    if !status.success() {
        return Err(PullFailure::AfterResponse);
    }
    http::respond_chunked_end(stream).map_err(|_| PullFailure::AfterResponse)
}
fn respond_vnc_start(stream: &mut TcpStream) -> std::io::Result<()> {
    // RFB has its own byte stream framing, so HTTP must not add a length or
    // chunk boundaries that a native VNC client would interpret as payload.
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
    )?;
    stream.flush()
}

fn stream_vnc(stream: &mut TcpStream, mut vsock: UnixStream) -> shinu::Result<()> {
    let mut client_to_guest = stream.try_clone()?;
    let mut guest_writer = vsock.try_clone()?;
    let stop_client_reader = Arc::new(AtomicBool::new(false));
    let stop_client_reader_thread = Arc::clone(&stop_client_reader);
    let client_reader = thread::spawn(move || {
        // A timeout lets the copy stop after the guest closes without
        // half-closing either socket, which Firecracker's multiplexer cannot
        // represent without tearing down the opposite direction.
        if client_to_guest
            .set_read_timeout(Some(Duration::from_millis(100)))
            .is_err()
        {
            return;
        }
        let mut buffer = [0u8; 64 * 1024];
        loop {
            match client_to_guest.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if guest_writer.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    if stop_client_reader_thread.load(Ordering::Acquire) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut buffer = [0u8; 64 * 1024];
    loop {
        match vsock.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                if stream.write_all(&buffer[..count]).is_err() {
                    break;
                }
            }
        }
    }
    stop_client_reader.store(true, Ordering::Release);
    let _ = client_reader.join();
    Ok(())
}

fn vnc_bridge_error(space: &str, error: &shinu::Error) -> shinu::Error {
    shinu::Error::Invalid(format!(
        "VNC bridge unavailable for {space}; start the guest desktop with `shinu desktop {space}`: {error}"
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProxyHeader {
    name: String,
    value: String,
}

#[derive(Debug)]
struct ProxyRequestHead {
    method: String,
    path: String,
    headers: Vec<ProxyHeader>,
    content_length: Option<usize>,
    chunked: bool,
}

#[derive(Debug)]
struct ProxyResponseHead {
    status_line: String,
    status: u16,
    headers: Vec<ProxyHeader>,
}

#[derive(Debug)]
enum ProxyBody {
    None,
    Length(usize),
    Chunked,
    Close,
}

#[derive(Debug)]
enum ProxyRelayFailure {
    BeforeResponse(String),
    GuestClosed(String),
    Transport(String),
}

fn proxy_header(name: &str, value: &str) -> ProxyHeader {
    ProxyHeader {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

fn is_proxy_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("expect")
}

fn proxy_connection_tokens(headers: &[ProxyHeader]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Connection"))
        .flat_map(|header| header.value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn proxy_is_filtered(header: &ProxyHeader, connection_tokens: &[String]) -> bool {
    is_proxy_hop_header(&header.name)
        || connection_tokens
            .iter()
            .any(|token| header.name.eq_ignore_ascii_case(token))
}

fn proxy_cookie_name(value: &str) -> Option<&str> {
    value.split_once('=').map(|(name, _)| name.trim())
}

fn proxy_cookie_without_session(value: &str) -> Option<String> {
    let cookies = value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter(|part| proxy_cookie_name(part) != Some(SESSION_COOKIE))
        .collect::<Vec<_>>();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

fn is_reserved_session_set_cookie(header: &ProxyHeader) -> bool {
    header.name.eq_ignore_ascii_case("Set-Cookie")
        && proxy_cookie_name(header.value.split(';').next().unwrap_or_default())
            == Some(SESSION_COOKIE)
}

fn parse_proxy_request_head(
    raw: &[u8],
    method: &str,
    path: &str,
) -> shinu::Result<ProxyRequestHead> {
    let mut lines = raw.split(|byte| *byte == b'\n');
    lines
        .next()
        .ok_or_else(|| shinu::Error::Invalid("proxy request headers are empty".into()))?;
    let mut headers = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| shinu::Error::Invalid("proxy request header has no colon".into()))?;
        let name = String::from_utf8(line[..colon].to_vec())
            .map_err(|_| shinu::Error::Invalid("proxy request header name is not UTF-8".into()))?;
        let value = String::from_utf8(line[colon + 1..].to_vec())
            .map_err(|_| shinu::Error::Invalid("proxy request header value is not UTF-8".into()))?
            .trim()
            .to_owned();
        headers.push(ProxyHeader { name, value });
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    for header in &headers {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(shinu::Error::Invalid(
                    "proxy request has duplicate Content-Length".into(),
                ));
            }
            content_length = Some(header.value.parse::<usize>().map_err(|error| {
                shinu::Error::Invalid(format!("proxy request has invalid Content-Length: {error}"))
            })?);
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding")
            && transfer_encoding.is_some()
        {
            return Err(shinu::Error::Invalid(
                "proxy request has duplicate Transfer-Encoding".into(),
            ));
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoding = Some(header.value.as_str());
        }
    }
    let chunked = transfer_encoding.is_some_and(|value| {
        value
            .split(',')
            .all(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    });
    if transfer_encoding.is_some() && !chunked {
        return Err(shinu::Error::Invalid(
            "proxy request uses an unsupported transfer encoding".into(),
        ));
    }
    if chunked && content_length.is_some() {
        return Err(shinu::Error::Invalid(
            "proxy request cannot combine Transfer-Encoding and Content-Length".into(),
        ));
    }
    Ok(ProxyRequestHead {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        content_length,
        chunked,
    })
}
fn proxy_request_headers(request: &ProxyRequestHead, port: u16) -> Vec<ProxyHeader> {
    let connection_tokens = proxy_connection_tokens(&request.headers);
    let mut headers = Vec::with_capacity(request.headers.len() + 3);
    for header in &request.headers {
        if proxy_is_filtered(header, &connection_tokens)
            || header.name.eq_ignore_ascii_case("Host")
            || header.name.eq_ignore_ascii_case("Content-Length")
            || header.name.eq_ignore_ascii_case("Authorization")
        {
            continue;
        }
        if header.name.eq_ignore_ascii_case("Cookie") {
            if let Some(value) = proxy_cookie_without_session(&header.value) {
                headers.push(proxy_header("Cookie", &value));
            }
            continue;
        }
        headers.push(header.clone());
    }
    headers.push(proxy_header("Host", &format!("127.0.0.1:{port}")));
    if request.chunked {
        headers.push(proxy_header("Transfer-Encoding", "chunked"));
    } else if let Some(length) = request.content_length {
        headers.push(proxy_header("Content-Length", &length.to_string()));
    }
    headers.push(proxy_header("Connection", "close"));
    headers
}

fn send_proxy_request_head(
    writer: &mut impl Write,
    request: &ProxyRequestHead,
    port: u16,
) -> std::io::Result<()> {
    write!(writer, "{} {} HTTP/1.1\r\n", request.method, request.path)?;
    for header in proxy_request_headers(request, port) {
        write!(writer, "{}: {}\r\n", header.name, header.value)?;
    }
    writer.write_all(b"\r\n")
}

fn copy_proxy_content_length(
    reader: &mut impl Read,
    writer: &mut impl Write,
    mut remaining: usize,
) -> Result<(), String> {
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let amount = remaining.min(buffer.len());
        let count = reader
            .read(&mut buffer[..amount])
            .map_err(|error| format!("could not read proxy request body: {error}"))?;
        if count == 0 {
            return Err("proxy request body ended before Content-Length".into());
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| format!("could not send proxy request body: {error}"))?;
        remaining -= count;
    }
    Ok(())
}

fn read_proxy_line(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .map_err(|error| format!("could not read proxy body framing: {error}"))?;
    if line.is_empty() {
        return Err("proxy chunked body ended before a chunk size".into());
    }
    if line.len() > 64 * 1024 {
        return Err("proxy chunked body line exceeds 64 KiB".into());
    }
    Ok(line)
}

fn parse_proxy_chunk_size(line: &[u8]) -> Result<usize, String> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
    let size = std::str::from_utf8(size)
        .map_err(|_| "proxy chunk size is not ASCII".to_string())?
        .trim();
    usize::from_str_radix(size, 16)
        .map_err(|error| format!("invalid proxy chunk size {size:?}: {error}"))
}

fn copy_proxy_chunked(reader: &mut impl BufRead, writer: &mut impl Write) -> Result<(), String> {
    loop {
        let size_line = read_proxy_line(reader)?;
        let size = parse_proxy_chunk_size(&size_line)?;
        writer
            .write_all(&size_line)
            .map_err(|error| format!("could not send proxy chunk size: {error}"))?;
        if size == 0 {
            loop {
                let trailer = read_proxy_line(reader)?;
                writer
                    .write_all(&trailer)
                    .map_err(|error| format!("could not send proxy trailer: {error}"))?;
                if trailer == b"\r\n" || trailer == b"\n" {
                    return Ok(());
                }
            }
        }
        let mut remaining = size;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            reader
                .read_exact(&mut buffer[..amount])
                .map_err(|error| format!("proxy chunk ended before its declared size: {error}"))?;
            writer
                .write_all(&buffer[..amount])
                .map_err(|error| format!("could not send proxy chunk: {error}"))?;
            remaining -= amount;
        }
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|error| format!("proxy chunk is missing its CRLF: {error}"))?;
        if crlf != *b"\r\n" {
            return Err("proxy chunk is missing its CRLF".into());
        }
        writer
            .write_all(&crlf)
            .map_err(|error| format!("could not send proxy chunk CRLF: {error}"))?;
    }
}

fn send_proxy_request(
    reader: &mut RequestReader<'_>,
    child: &mut Child,
    request: &ProxyRequestHead,
    port: u16,
) -> Result<(), String> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "ssh proxy stdin pipe unavailable".to_string())?;
    send_proxy_request_head(&mut stdin, request, port)
        .map_err(|error| format!("could not send proxy request headers: {error}"))?;
    if request.chunked {
        copy_proxy_chunked(reader, &mut stdin)?;
    } else if let Some(length) = request.content_length {
        copy_proxy_content_length(reader, &mut stdin, length)?;
    }
    stdin
        .flush()
        .map_err(|error| format!("could not flush proxy request: {error}"))?;
    drop(stdin);
    Ok(())
}

/// SSH direct stream forwarding keeps the guest's network private while
/// reusing the already authenticated vsock channel for every arbitrary port.
fn spawn_proxy_forward(target: &SshTarget, port: u16) -> shinu::Result<Child> {
    let key = shinu::vm::key_path(&target.vm_dir);
    let mut command = Command::new("ssh");
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
        .arg(&target.proxy)
        .arg("-i")
        .arg(key)
        .arg("-W")
        .arg(format!("127.0.0.1:{port}"))
        .arg("root@shinu")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command.spawn()?)
}

fn read_proxy_response_line(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let line = read_proxy_line(reader)?;
    if line.len() > 64 * 1024 {
        return Err("proxy response header line exceeds 64 KiB".into());
    }
    Ok(line)
}

fn parse_proxy_response_head(reader: &mut impl BufRead) -> Result<ProxyResponseHead, String> {
    let status_line = read_proxy_response_line(reader)?;
    let status_text = std::str::from_utf8(&status_line)
        .map_err(|_| "guest response status line is not UTF-8".to_string())?
        .trim_end_matches(&['\r', '\n'][..]);
    if status_text
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n')
    {
        return Err("guest returned a status line with embedded line breaks".into());
    }
    let mut fields = status_text.splitn(3, ' ');
    let version = fields.next().unwrap_or_default();
    let code = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.")
        || code.len() != 3
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "guest returned an invalid HTTP status line: {status_text:?}"
        ));
    }
    let status = code
        .parse::<u16>()
        .map_err(|error| format!("guest returned an invalid HTTP status code: {error}"))?;
    if !(100..=599).contains(&status) {
        return Err(format!(
            "guest returned an invalid HTTP status code: {status}"
        ));
    }
    let mut headers = Vec::new();
    loop {
        let line = read_proxy_response_line(reader)?;
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().any(|byte| *byte == b'\r' || *byte == b'\n') {
            return Err("guest returned a response header with embedded line breaks".into());
        }
        if line.is_empty() {
            break;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| "guest returned a malformed HTTP response header".to_string())?;
        let name = String::from_utf8(line[..colon].to_vec())
            .map_err(|_| "guest response header name is not UTF-8".to_string())?;
        let value = String::from_utf8(line[colon + 1..].to_vec())
            .map_err(|_| "guest response header value is not UTF-8".to_string())?
            .trim()
            .to_owned();
        if headers.len() >= 100 {
            return Err("guest returned more than 100 response headers".into());
        }
        headers.push(ProxyHeader { name, value });
    }
    Ok(ProxyResponseHead {
        status_line: status_text.to_owned(),
        status,
        headers,
    })
}

fn proxy_response_body(response: &ProxyResponseHead, method: &str) -> Result<ProxyBody, String> {
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&response.status)
        || matches!(response.status, 204 | 304)
    {
        return Ok(ProxyBody::None);
    }
    let mut content_length = None;
    let mut transfer_encoding = None;
    for header in &response.headers {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err("guest response has duplicate Content-Length".into());
            }
            content_length =
                Some(header.value.parse::<usize>().map_err(|error| {
                    format!("guest response has invalid Content-Length: {error}")
                })?);
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding")
            && transfer_encoding.is_some()
        {
            return Err("guest response has duplicate Transfer-Encoding".into());
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoding = Some(header.value.as_str());
        }
    }
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err("guest response combines Transfer-Encoding and Content-Length".into());
    }
    if let Some(encoding) = transfer_encoding {
        if encoding
            .split(',')
            .all(|value| value.trim().eq_ignore_ascii_case("chunked"))
        {
            return Ok(ProxyBody::Chunked);
        }
        return Err("guest response uses an unsupported transfer encoding".into());
    }
    Ok(content_length.map_or(ProxyBody::Close, ProxyBody::Length))
}
fn proxy_response_header_is_filtered(
    header: &ProxyHeader,
    connection_tokens: &[String],
    body: &ProxyBody,
) -> bool {
    proxy_is_filtered(header, connection_tokens)
        || is_reserved_session_set_cookie(header)
        || header.name.eq_ignore_ascii_case("Content-Length") && matches!(body, ProxyBody::Close)
}

fn write_proxy_response_head(
    stream: &mut TcpStream,
    response: &ProxyResponseHead,
    body: &ProxyBody,
) -> std::io::Result<()> {
    write!(stream, "{}\r\n", response.status_line)?;
    let connection_tokens = proxy_connection_tokens(&response.headers);
    for header in &response.headers {
        if proxy_response_header_is_filtered(header, &connection_tokens, body) {
            continue;
        }
        write!(stream, "{}: {}\r\n", header.name, header.value)?;
    }
    if matches!(body, ProxyBody::Chunked) {
        stream.write_all(b"Transfer-Encoding: chunked\r\n")?;
    }
    stream.write_all(b"Connection: close\r\n\r\n")?;
    stream.flush()
}

fn relay_proxy_length(
    reader: &mut impl Read,
    stream: &mut TcpStream,
    mut remaining: usize,
) -> Result<(), ProxyRelayFailure> {
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let amount = remaining.min(buffer.len());
        let count = reader
            .read(&mut buffer[..amount])
            .map_err(|error| ProxyRelayFailure::GuestClosed(error.to_string()))?;
        if count == 0 {
            return Err(ProxyRelayFailure::GuestClosed(
                "response ended before Content-Length".into(),
            ));
        }
        stream
            .write_all(&buffer[..count])
            .map_err(|error| ProxyRelayFailure::Transport(error.to_string()))?;
        remaining -= count;
    }
    Ok(())
}

fn relay_proxy_chunked(
    reader: &mut impl BufRead,
    stream: &mut TcpStream,
) -> Result<(), ProxyRelayFailure> {
    loop {
        let size_line = read_proxy_response_line(reader).map_err(ProxyRelayFailure::GuestClosed)?;
        let size = parse_proxy_chunk_size(&size_line).map_err(ProxyRelayFailure::GuestClosed)?;
        stream
            .write_all(&size_line)
            .map_err(|error| ProxyRelayFailure::Transport(error.to_string()))?;
        if size == 0 {
            loop {
                let trailer =
                    read_proxy_response_line(reader).map_err(ProxyRelayFailure::GuestClosed)?;
                stream
                    .write_all(&trailer)
                    .map_err(|error| ProxyRelayFailure::Transport(error.to_string()))?;
                if trailer == b"\r\n" || trailer == b"\n" {
                    return Ok(());
                }
            }
        }
        let mut remaining = size;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            reader
                .read_exact(&mut buffer[..amount])
                .map_err(|error| ProxyRelayFailure::GuestClosed(error.to_string()))?;
            stream
                .write_all(&buffer[..amount])
                .map_err(|error| ProxyRelayFailure::Transport(error.to_string()))?;
            remaining -= amount;
        }
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|error| ProxyRelayFailure::GuestClosed(error.to_string()))?;
        if crlf != *b"\r\n" {
            return Err(ProxyRelayFailure::GuestClosed(
                "chunked response is missing its CRLF".into(),
            ));
        }
        stream
            .write_all(&crlf)
            .map_err(|error| ProxyRelayFailure::Transport(error.to_string()))?;
    }
}

fn relay_proxy_close(
    reader: &mut impl Read,
    stream: &mut TcpStream,
) -> Result<(), ProxyRelayFailure> {
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| ProxyRelayFailure::GuestClosed(error.to_string()))?;
        if count == 0 {
            return Ok(());
        }
        stream
            .write_all(&buffer[..count])
            .map_err(|error| ProxyRelayFailure::Transport(error.to_string()))?;
    }
}

fn finish_proxy_child(
    child: &mut Child,
    stderr_reader: Option<std::thread::JoinHandle<Vec<u8>>>,
) -> String {
    let _ = child.kill();
    let _ = child.wait();
    stderr_reader
        .and_then(|reader| reader.join().ok())
        .map(|stderr| String::from_utf8_lossy(&stderr).trim().to_owned())
        .unwrap_or_default()
}

fn abort_proxy_child(child: &mut Child) {
    let stderr_reader = child.stderr.take().map(|stderr| {
        thread::spawn(move || {
            let mut output = Vec::new();
            let _ = BufReader::new(stderr).read_to_end(&mut output);
            output
        })
    });
    let _ = finish_proxy_child(child, stderr_reader);
}

fn relay_proxy_response(
    stream: &mut TcpStream,
    child: &mut Child,
    method: &str,
) -> Result<(), ProxyRelayFailure> {
    let stdout = child.stdout.take().ok_or_else(|| {
        ProxyRelayFailure::BeforeResponse("ssh proxy stdout pipe unavailable".into())
    })?;
    let stderr_reader = child.stderr.take().map(|stderr| {
        thread::spawn(move || {
            let mut output = Vec::new();
            let _ = BufReader::new(stderr).read_to_end(&mut output);
            output
        })
    });
    let mut reader = BufReader::new(stdout);
    let response = match parse_proxy_response_head(&mut reader) {
        Ok(response) => response,
        Err(error) => {
            let stderr = finish_proxy_child(child, stderr_reader);
            let detail = if stderr.is_empty() {
                error
            } else {
                format!("{error}: {stderr}")
            };
            return Err(ProxyRelayFailure::BeforeResponse(detail));
        }
    };
    let body = match proxy_response_body(&response, method) {
        Ok(body) => body,
        Err(error) => {
            let detail = finish_proxy_child(child, stderr_reader);
            return Err(ProxyRelayFailure::BeforeResponse(if detail.is_empty() {
                error
            } else {
                format!("{error}: {detail}")
            }));
        }
    };
    if let Err(error) = write_proxy_response_head(stream, &response, &body) {
        let _ = finish_proxy_child(child, stderr_reader);
        return Err(ProxyRelayFailure::Transport(error.to_string()));
    }
    let result = match body {
        ProxyBody::None => Ok(()),
        ProxyBody::Length(length) => relay_proxy_length(&mut reader, stream, length),
        ProxyBody::Chunked => relay_proxy_chunked(&mut reader, stream),
        ProxyBody::Close => relay_proxy_close(&mut reader, stream),
    };
    if let Err(error) = result {
        let _ = finish_proxy_child(child, stderr_reader);
        return Err(error);
    }
    if !matches!(body, ProxyBody::Close) {
        let _ = child.kill();
    }
    let _ = child.wait();
    if let Some(stderr_reader) = stderr_reader {
        let _ = stderr_reader.join();
    }
    Ok(())
}

fn proxy_bridge_error(space: &str, port: u16, failure: ProxyRelayFailure) -> shinu::Error {
    let (kind, detail) = match failure {
        ProxyRelayFailure::BeforeResponse(detail) => ("before response", detail),
        ProxyRelayFailure::GuestClosed(detail) => ("after the response started", detail),
        ProxyRelayFailure::Transport(detail) => ("while writing the response", detail),
    };
    let lower = detail.to_ascii_lowercase();
    if lower.contains("connection refused") || lower.contains("connect_to") {
        return shinu::Error::Invalid(format!(
            "guest port {port} in space {space} has nothing listening; start a service on port {port}: {detail}"
        ));
    }
    if kind == "after the response started" {
        return shinu::Error::Invalid(format!(
            "guest in space {space} closed port {port} before completing its response: {detail}"
        ));
    }
    shinu::Error::Invalid(format!(
        "proxy to guest port {port} in space {space} failed {kind}: {detail}"
    ))
}

#[derive(Debug)]
enum Caller {
    Api { project: String },
    Console { user_id: String, project: String },
}

fn caller_project(caller: &Caller) -> &str {
    match caller {
        Caller::Api { project } | Caller::Console { project, .. } => project,
    }
}

fn is_state_changing(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "DELETE" | "PATCH")
}

/// The admin bearer is separate from project tokens so a tenant cannot grant
/// itself a larger quota. Hash both values first, then compare fixed-size
/// digests without an early return; an unset admin token never authorizes.
fn admin_token_matches(ctx: &Ctx<'_>, request: &http::Request) -> bool {
    let Some(expected) = ctx.admin_token else {
        return false;
    };
    let Some(candidate) = request.token.as_deref() else {
        return false;
    };
    let expected = shinu::sha256_hex(expected.as_bytes());
    let candidate = shinu::sha256_hex(candidate.as_bytes());
    let mut difference = 0_u8;
    for index in 0..64 {
        difference |= expected.as_bytes()[index] ^ candidate.as_bytes()[index];
    }
    difference == 0
}

fn require_admin_token(ctx: &Ctx<'_>, request: &http::Request) -> shinu::Result<()> {
    if request.authorization_present && request.token.is_none() {
        return Err(shinu::Error::Auth("invalid token".into()));
    }
    if admin_token_matches(ctx, request) {
        Ok(())
    } else {
        Err(shinu::Error::Auth("administrative token required".into()))
    }
}

fn authorize_project_limits_read(
    ctx: &Ctx<'_>,
    request: &http::Request,
    project: &str,
) -> shinu::Result<()> {
    if admin_token_matches(ctx, request) {
        return Ok(());
    }
    let caller = authenticate(ctx, request)?;
    if caller_project(&caller) == project {
        Ok(())
    } else {
        Err(shinu::Error::Auth(
            "project token may only read its own limits".into(),
        ))
    }
}

fn authenticate(ctx: &Ctx<'_>, request: &http::Request) -> shinu::Result<Caller> {
    // A bearer token is deliberately authoritative when present. Falling back
    // to a cookie after an invalid bearer would let a malformed proxy header
    // silently change which project receives a request.
    if request.authorization_present || request.token.is_some() {
        let plain = request
            .token
            .as_deref()
            .ok_or_else(|| shinu::Error::Auth("invalid token".into()))?;
        let tokens = shinu::token::load(ctx.root)?;
        let project = shinu::token::authenticate(&tokens, plain)?;
        return Ok(Caller::Api { project });
    }
    let token = request
        .cookies
        .get(SESSION_COOKIE)
        .ok_or_else(|| shinu::Error::Auth("missing authentication".into()))?;
    let token_hash = shinu::sha256_hex(token.as_bytes());
    let connection = lock_db(ctx.db);
    let user_id = state::lookup_session(&connection, &token_hash)?
        .ok_or_else(|| shinu::Error::Auth("invalid or expired session".into()))?;
    let project = state::user_project(&connection, &user_id)?
        .ok_or_else(|| shinu::Error::Auth("session user has no project".into()))?;
    Ok(Caller::Console { user_id, project })
}

fn authenticate_optional(ctx: &Ctx<'_>, request: &http::Request) -> Option<Caller> {
    if !request.authorization_present
        && request.token.is_none()
        && !request.cookies.contains_key(SESSION_COOKIE)
    {
        return None;
    }
    authenticate(ctx, request).ok()
}

fn origin_host(origin: &str) -> Option<&str> {
    let (_, authority) = origin.split_once("://")?;
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let authority = &authority[..end];
    if authority.is_empty()
        || authority.contains('@')
        || authority
            .chars()
            .any(|character| character.is_ascii_whitespace())
    {
        return None;
    }
    Some(authority)
}

fn check_console_csrf(request: &http::Request) -> shinu::Result<()> {
    if !is_state_changing(&request.method) {
        return Ok(());
    }
    let origin = request.origin.as_deref().ok_or_else(|| {
        shinu::Error::Invalid("origin header is required for this console request".into())
    })?;
    let origin_host = origin_host(origin)
        .ok_or_else(|| shinu::Error::Invalid("origin header is not a valid URL".into()))?;
    let host = request
        .host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| shinu::Error::Invalid("host header is required".into()))?;
    if !origin_host.eq_ignore_ascii_case(host) {
        return Err(shinu::Error::Invalid(
            "origin does not match the host header".into(),
        ));
    }
    Ok(())
}

fn normalize_email(raw: &str) -> shinu::Result<String> {
    let email = raw.trim();
    let valid_shape = !email.is_empty()
        && email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && !email
                    .chars()
                    .any(|character| character.is_ascii_whitespace() || character.is_control())
        });
    if !valid_shape {
        return Err(shinu::Error::Invalid(
            "please enter a valid email address".into(),
        ));
    }
    Ok(email.to_lowercase())
}
fn request_is_secure(request: &http::Request) -> bool {
    // Caddy terminates TLS and marks the original scheme here. Do not set
    // Secure for local HTTP, or browsers will silently discard the cookie.
    request
        .forwarded_proto
        .as_deref()
        .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"))
}

fn parse_credentials(body: &[u8], require_long_password: bool) -> shinu::Result<(String, String)> {
    let value = parse_body(body)?;
    let email = value
        .get("email")
        .and_then(Value::as_str)
        .ok_or_else(|| shinu::Error::Invalid("email must be a string".into()))?;
    let password = value
        .get("password")
        .and_then(Value::as_str)
        .ok_or_else(|| shinu::Error::Invalid("password must be a string".into()))?;
    let email = normalize_email(email)?;
    if require_long_password && password.chars().count() < 12 {
        return Err(shinu::Error::Invalid(
            "password must be at least 12 characters".into(),
        ));
    }
    Ok((email, password.to_owned()))
}

fn session_days() -> i64 {
    std::env::var("SHINU_SESSION_DAYS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(SESSION_DEFAULT_DAYS)
}

fn session_max_age(days: i64) -> u64 {
    if days == SESSION_DEFAULT_DAYS {
        SESSION_MAX_AGE_SECONDS
    } else {
        u64::try_from(days)
            .unwrap_or(SESSION_DEFAULT_DAYS as u64)
            .saturating_mul(24 * 60 * 60)
    }
}

fn issue_session(ctx: &Ctx<'_>, user_id: &str, secure: bool) -> shinu::Result<String> {
    let plain = shinu::auth::new_session_token()?;
    let token_hash = shinu::sha256_hex(plain.as_bytes());
    let days = session_days();
    state::create_session(&lock_db(ctx.db), &token_hash, user_id, days)?;
    Ok(http::set_cookie(
        SESSION_COOKIE,
        &plain,
        secure,
        session_max_age(days),
    ))
}

fn register_console(
    ctx: &Ctx<'_>,
    body: &[u8],
    ip: &str,
    secure: bool,
) -> shinu::Result<(Value, String)> {
    // Registration uses a dedicated one-hour per-IP limiter; the project API
    // limiter has different minute-window semantics and must not be reused.
    ctx.register_rate.check(ip)?;
    let (email, password) = parse_credentials(body, true)?;
    {
        let connection = lock_db(ctx.db);
        if state::find_user_by_email(&connection, &email)?.is_some() {
            return Err(shinu::Error::Invalid("email is already registered".into()));
        }
    }
    let password_hash = shinu::auth::hash_password(&password)?;
    let (user_id, project) = state::create_user(&lock_db(ctx.db), &email, &password_hash)?;
    let cookie = issue_session(ctx, &user_id, secure)?;
    Ok((json!({ "user_id": user_id, "project": project }), cookie))
}

fn login_console(ctx: &Ctx<'_>, body: &[u8], secure: bool) -> shinu::Result<(Value, String)> {
    let (email, password) = parse_credentials(body, false)?;
    let user = state::find_user_by_email(&lock_db(ctx.db), &email)?;
    let (user_id, password_hash) = user
        .as_ref()
        .map(|(user_id, password_hash)| (Some(user_id.as_str()), password_hash.as_str()))
        .unwrap_or((None, DUMMY_PASSWORD_HASH));
    // The dummy record has the real PBKDF2 shape so an unknown email still
    // performs the expensive password derivation before returning 401.
    let valid = shinu::auth::verify_password(&password, password_hash);
    if !valid {
        return Err(shinu::Error::Auth(LOGIN_FAILURE_MESSAGE.into()));
    }
    let user_id = user_id.ok_or_else(|| shinu::Error::Auth(LOGIN_FAILURE_MESSAGE.into()))?;
    let project = state::user_project(&lock_db(ctx.db), user_id)?
        .ok_or_else(|| shinu::Error::Auth(LOGIN_FAILURE_MESSAGE.into()))?;
    let cookie = issue_session(ctx, user_id, secure)?;
    Ok((json!({ "user_id": user_id, "project": project }), cookie))
}

fn logout_console(ctx: &Ctx<'_>, request: &http::Request) -> shinu::Result<String> {
    let token = request
        .cookies
        .get(SESSION_COOKIE)
        .ok_or_else(|| shinu::Error::Auth("missing session cookie".into()))?;
    let token_hash = shinu::sha256_hex(token.as_bytes());
    state::delete_session(&lock_db(ctx.db), &token_hash)?;
    Ok(http::clear_cookie(SESSION_COOKIE))
}

fn me_console(ctx: &Ctx<'_>, caller: &Caller) -> shinu::Result<Value> {
    let Caller::Console { user_id, project } = caller else {
        return Err(shinu::Error::Auth("console session required".into()));
    };
    let email = state::user_email(&lock_db(ctx.db), user_id)?
        .ok_or_else(|| shinu::Error::Auth("session user no longer exists".into()))?;
    Ok(json!({ "user_id": user_id, "email": email, "project": project }))
}

fn token_hash_prefix(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

fn list_console_tokens(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let _state_guard = lock_state(ctx.registry);
    let tokens = shinu::token::load(ctx.root)?;
    let tokens = tokens
        .iter()
        .filter(|token| token.project == project)
        .map(|token| {
            json!({
                "hash_prefix": token_hash_prefix(&token.hash),
                "created_at": token.created_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "tokens": tokens }))
}

fn create_console_token(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let _state_guard = lock_state(ctx.registry);
    let plain = shinu::token::mint()?;
    let mut tokens = shinu::token::load(ctx.root)?;
    tokens.push(shinu::token::Token {
        hash: shinu::token::hash(&plain),
        project: project.to_owned(),
        created_at: Utc::now(),
    });
    shinu::token::store(ctx.root, &tokens)?;
    Ok(json!({ "token": plain }))
}

fn delete_console_token(ctx: &Ctx<'_>, project: &str, prefix: &str) -> shinu::Result<Value> {
    if prefix.is_empty()
        || prefix.len() > 64
        || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(shinu::Error::NotFound("token not found".into()));
    }
    let _state_guard = lock_state(ctx.registry);
    let mut tokens = shinu::token::load(ctx.root)?;
    let matches = tokens
        .iter()
        .filter(|token| token.project == project && token.hash.starts_with(prefix))
        .count();
    if matches == 0 {
        return Err(shinu::Error::NotFound("token not found".into()));
    }
    if matches > 1 {
        return Err(shinu::Error::Invalid("token prefix is ambiguous".into()));
    }
    tokens.retain(|token| !(token.project == project && token.hash.starts_with(prefix)));
    shinu::token::store(ctx.root, &tokens)?;
    Ok(json!({}))
}

fn respond_error(stream: &mut impl Write, status: u16, error: &shinu::Error) -> shinu::Result<()> {
    let body = if status >= 500 {
        eprintln!("{error}");
        json!({ "error": "internal server error" })
    } else {
        json!({ "error": error.to_string() })
    };
    http::respond(stream, status, &body)?;
    Ok(())
}

fn is_console_path(path: &str) -> bool {
    path.split_once('?')
        .map_or(path, |(path, _)| path)
        .starts_with("/console/")
}
fn is_socket_timeout(error: &shinu::Error) -> bool {
    matches!(
        error,
        shinu::Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
    )
}

fn respond_request_timeout(stream: &mut TcpStream) {
    // A request timeout is transport policy, not a domain error; avoid the
    // diagnostic path and close with the standard status for an incomplete request.
    let _ = stream
        .write_all(
            b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .and_then(|()| stream.flush());
}

fn clear_stream_timeouts(stream: &TcpStream) -> shinu::Result<()> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(())
}
fn serve_connection(mut stream: TcpStream, ctx: &Ctx<'_>) -> shinu::Result<()> {
    let client_ip = stream
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    let mut reader = Some(RequestReader::new(&mut stream));
    let head = match http::parse_head(reader.as_mut().expect("request reader present")) {
        Ok(head) => head,
        Err(error) => {
            let _ = reader.take();
            if is_socket_timeout(&error) {
                respond_request_timeout(&mut stream);
            } else {
                respond_error(&mut stream, http::status_for(&error), &error)?;
            }
            return Ok(());
        }
    };
    let endpoint = match route(&head.path) {
        Some(endpoint) => endpoint,
        None => {
            let error = shinu::Error::NotFound(head.path.clone());
            let _ = reader.take();
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };
    if !method_allowed(&endpoint, &head.method) {
        let error = shinu::Error::Invalid("method not allowed".into());
        let _ = reader.take();
        respond_error(&mut stream, 405, &error)?;
        return Ok(());
    }
    let content_length = head.content_length;
    let metadata = head.clone().into_request(Vec::new());
    // Register and login have no Caller yet, so the console path itself is the
    // trust boundary for CSRF. This also covers logout and token mutations.
    if is_console_path(&head.path)
        && is_state_changing(&head.method)
        && let Err(error) = check_console_csrf(&metadata)
    {
        let _ = reader.take();
        respond_error(&mut stream, 403, &error)?;
        return Ok(());
    }

    let is_transfer = matches!(
        &endpoint,
        Endpoint::Push(_) | Endpoint::Pull(_) | Endpoint::Vnc(_) | Endpoint::Proxy { .. }
    );
    if is_transfer {
        // Transfer bodies and tunnel payloads are unbounded; only the request
        // head gets the admission deadline, so clear it before any body read.
        reader
            .as_mut()
            .expect("request reader present")
            .clear_socket_timeouts()?;
    }
    let request = if is_transfer {
        metadata
    } else {
        reader
            .as_mut()
            .expect("request reader present")
            .stop_capture();
        let body = match http::read_body(
            reader.as_mut().expect("request reader present"),
            content_length,
        ) {
            Ok(body) => body,
            Err(error) => {
                let _ = reader.take();
                if is_socket_timeout(&error) {
                    respond_request_timeout(&mut stream);
                } else {
                    respond_error(&mut stream, http::status_for(&error), &error)?;
                }
                return Ok(());
            }
        };
        let _ = reader.take();
        head.into_request(body)
    };

    match &endpoint {
        Endpoint::Root => {
            if authenticate_optional(ctx, &request).is_some() {
                http::respond_redirect(&mut stream, "/app")?;
            } else {
                http::respond_redirect(&mut stream, "/login")?;
            }
            return Ok(());
        }
        Endpoint::LoginPage | Endpoint::RegisterPage => {
            http::respond_html(&mut stream, 200, AUTH_HTML)?;
            return Ok(());
        }
        Endpoint::AppPage => {
            if authenticate_optional(ctx, &request).is_some() {
                http::respond_html(&mut stream, 200, APP_HTML)?;
            } else {
                http::respond_redirect(&mut stream, "/login")?;
            }
            return Ok(());
        }
        Endpoint::Asset(path) => {
            let body = match *path {
                "/assets/app.css" => APP_CSS.as_bytes(),
                "/assets/app.js" => APP_JS.as_bytes(),
                _ => unreachable!("route only returns known embedded assets"),
            };
            http::respond_asset(&mut stream, path, body)?;
            return Ok(());
        }
        Endpoint::ConsoleRegister => {
            let secure = request_is_secure(&request);
            match register_console(ctx, &request.body, &client_ip, secure) {
                Ok((body, cookie)) => {
                    http::respond_with_cookie(&mut stream, 201, &body, &cookie)?;
                }
                Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
            }
            return Ok(());
        }
        Endpoint::ConsoleLogin => {
            let secure = request_is_secure(&request);
            match login_console(ctx, &request.body, secure) {
                Ok((body, cookie)) => {
                    http::respond_with_cookie(&mut stream, 200, &body, &cookie)?;
                }
                Err(shinu::Error::Auth(_)) => {
                    // Keep every login failure byte-for-byte equivalent so an
                    // observer cannot distinguish an unknown email.
                    http::respond(&mut stream, 401, &json!({ "error": LOGIN_FAILURE_MESSAGE }))?;
                }
                Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
            }
            return Ok(());
        }
        Endpoint::ConsoleLogout
        | Endpoint::ConsoleMe
        | Endpoint::ConsoleTokens
        | Endpoint::ConsoleToken(_) => {}
        _ => {}
    }

    if let Endpoint::ProjectLimits(project) = &endpoint {
        let authorization = if request.method == "GET" {
            authorize_project_limits_read(ctx, &request, project)
        } else {
            require_admin_token(ctx, &request)
        };
        if let Err(error) = authorization {
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
        let result = match request.method.as_str() {
            "GET" => limits_value(ctx, project),
            "PATCH" => patch_project_limits(ctx, project, &request.body),
            "DELETE" => clear_project_limits(ctx, project),
            _ => unreachable!("project limits method was checked above"),
        };
        match result {
            Ok(value) => http::respond(&mut stream, 200, &value)?,
            Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
        }
        return Ok(());
    }

    let caller = match authenticate(ctx, &request) {
        Ok(caller) => caller,
        Err(error) => {
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };

    match &endpoint {
        Endpoint::ConsoleLogout
        | Endpoint::ConsoleMe
        | Endpoint::ConsoleTokens
        | Endpoint::ConsoleToken(_) => {
            let Caller::Console { .. } = &caller else {
                let error = shinu::Error::Auth("console session required".into());
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            };
            let project = caller_project(&caller);
            match &endpoint {
                Endpoint::ConsoleLogout => match logout_console(ctx, &request) {
                    Ok(cookie) => {
                        http::respond_with_cookie(&mut stream, 200, &json!({}), &cookie)?;
                    }
                    Err(error) => {
                        respond_error(&mut stream, http::status_for(&error), &error)?;
                    }
                },
                Endpoint::ConsoleMe => match me_console(ctx, &caller) {
                    Ok(body) => http::respond(&mut stream, 200, &body)?,
                    Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
                },
                Endpoint::ConsoleTokens if request.method == "GET" => {
                    match list_console_tokens(ctx, project) {
                        Ok(body) => http::respond(&mut stream, 200, &body)?,
                        Err(error) => {
                            respond_error(&mut stream, http::status_for(&error), &error)?;
                        }
                    }
                }
                Endpoint::ConsoleTokens => match create_console_token(ctx, project) {
                    Ok(body) => http::respond(&mut stream, 201, &body)?,
                    Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
                },
                Endpoint::ConsoleToken(prefix) => {
                    match delete_console_token(ctx, project, prefix) {
                        Ok(body) => http::respond(&mut stream, 200, &body)?,
                        Err(error) => {
                            respond_error(&mut stream, http::status_for(&error), &error)?;
                        }
                    }
                }
                _ => unreachable!("console endpoint was checked above"),
            }
            return Ok(());
        }
        _ => {}
    }

    // API routes accept either bearer callers or console sessions. Only the
    // latter are subject to the browser-origin check; SDKs must remain usable
    // without manufacturing an Origin header.
    if let Caller::Console { .. } = &caller
        && is_state_changing(&request.method)
        && let Err(error) = check_console_csrf(&request)
    {
        respond_error(&mut stream, 403, &error)?;
        return Ok(());
    }
    let project = caller_project(&caller);
    let effective = match effective_limits(ctx, project) {
        Ok(limits) => limits,
        Err(error) => {
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };
    if let Err(error) = ctx.rate.check(project, effective.api_per_min) {
        respond_error(&mut stream, http::status_for(&error), &error)?;
        return Ok(());
    }

    let (from, to) = if matches!(&endpoint, Endpoint::Usage) {
        match usage_query(&request.path) {
            Ok(range) => range,
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        }
    } else {
        (None, None)
    };
    if let Endpoint::Diff(space) = &endpoint {
        let req = match diff_request(&request.path, space.clone()) {
            Ok(req) => req,
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        match handle(ctx, req, project) {
            Ok(value) => {
                record_usage(ctx.db, project, "api_call", None, 1)?;
                http::respond(&mut stream, 200, &value)?;
            }
            Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
        }
        return Ok(());
    }
    if let Endpoint::Exec(space) = &endpoint {
        let req = match request_for(
            Endpoint::Exec(space.clone()),
            &request.method,
            &request.body,
            None,
            None,
        ) {
            Ok((req, _)) => req,
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let Req::Exec {
            cmd: command,
            stdin,
            session,
            ..
        } = req
        else {
            unreachable!("exec route must produce an Exec request");
        };
        clear_stream_timeouts(&stream)?;
        match execute_streaming(
            &mut stream,
            ctx,
            project,
            space.clone(),
            command,
            stdin,
            session,
        ) {
            Ok(()) => {
                record_usage(ctx.db, project, "api_call", None, 1)?;
            }
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
            }
        }
        return Ok(());
    }
    if let Endpoint::Push(space) = &endpoint {
        let path = match transfer_path(&request.path) {
            Ok(path) => path,
            Err(error) => {
                let _ = reader.take();
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let length = match upload_length(content_length) {
            Ok(length) => length,
            Err(error) => {
                let _ = reader.take();
                respond_error(&mut stream, 400, &error)?;
                return Ok(());
            }
        };
        let target = match prepare_ssh(ctx, project, space) {
            Ok(target) => target,
            Err(error) => {
                let _ = reader.take();
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let result = push_file(
            reader.as_mut().expect("request reader present"),
            &target,
            &path,
            length,
        );
        let _ = reader.take();
        match result {
            Ok(bytes) => {
                record_usage(ctx.db, project, "api_call", None, 1)?;
                http::respond(&mut stream, 200, &json!({ "path": path, "bytes": bytes }))?;
            }
            Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
        }
        return Ok(());
    }
    if let Endpoint::Pull(space) = &endpoint {
        let path = match transfer_path(&request.path) {
            Ok(path) => path,
            Err(error) => {
                let _ = reader.take();
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let _ = reader.take();
        let target = match prepare_ssh(ctx, project, space) {
            Ok(target) => target,
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        match pull_file(&mut stream, &target, &path) {
            Ok(()) => {
                record_usage(ctx.db, project, "api_call", None, 1)?;
            }
            Err(PullFailure::BeforeResponse(error)) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
            }
            Err(PullFailure::AfterResponse) => {}
        }
        return Ok(());
    }
    if let Endpoint::Vnc(space) = &endpoint {
        let target = match prepare_ssh(ctx, project, space) {
            Ok(target) => target,
            Err(error) => {
                let _ = reader.take();
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let vsock = match shinu::vsock_connect(
            &shinu::vm::vsock_path(&target.vm_dir),
            shinu::VSOCK_VNC_PORT,
        ) {
            Ok(vsock) => vsock,
            Err(error) => {
                let _ = reader.take();
                let error = vnc_bridge_error(space, &error);
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let _ = reader.take();
        respond_vnc_start(&mut stream)?;
        stream_vnc(&mut stream, vsock)?;
        record_usage(ctx.db, project, "api_call", None, 1)?;
        return Ok(());
    }
    if let Endpoint::Proxy { space, port, path } = &endpoint {
        let raw_headers = reader
            .as_mut()
            .expect("request reader present")
            .take_headers();
        let proxy_head = match parse_proxy_request_head(&raw_headers, &request.method, path) {
            Ok(head) => head,
            Err(error) => {
                let _ = reader.take();
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let target = match prepare_ssh(ctx, project, space) {
            Ok(target) => target,
            Err(error) => {
                let _ = reader.take();
                let error = if matches!(error, shinu::Error::NotFound(_)) {
                    error
                } else {
                    shinu::Error::Invalid(format!(
                        "could not start VM for proxy space {space}: {error}"
                    ))
                };
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let mut child = match spawn_proxy_forward(&target, *port) {
            Ok(child) => child,
            Err(error) => {
                let _ = reader.take();
                let error = shinu::Error::Invalid(format!(
                    "could not open SSH proxy to guest port {port} in space {space}: {error}"
                ));
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        let request_result = send_proxy_request(
            reader.as_mut().expect("request reader present"),
            &mut child,
            &proxy_head,
            *port,
        );
        let _ = reader.take();
        if let Err(error) = request_result {
            abort_proxy_child(&mut child);
            let error = shinu::Error::Invalid(format!(
                "proxy request to guest port {port} in space {space} failed: {error}"
            ));
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
        match relay_proxy_response(&mut stream, &mut child, &request.method) {
            Ok(()) => record_usage(ctx.db, project, "api_call", None, 1)?,
            Err(failure) => {
                let before_response = matches!(&failure, ProxyRelayFailure::BeforeResponse(_));
                let error = proxy_bridge_error(space, *port, failure);
                if before_response {
                    respond_error(&mut stream, http::status_for(&error), &error)?;
                } else {
                    // Once guest headers are emitted, appending a JSON error would
                    // turn a diagnosable truncated response into invalid bytes.
                    eprintln!("{error}");
                }
            }
        }
        return Ok(());
    }

    let (req, status) = match request_for(endpoint, &request.method, &request.body, from, to) {
        Ok(request) => request,
        Err(error) => {
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };
    match handle(ctx, req, project) {
        Ok(value) => {
            record_usage(ctx.db, project, "api_call", None, 1)?;
            http::respond(&mut stream, status, &value)?;
        }
        Err(error) => respond_error(&mut stream, http::status_for(&error), &error)?,
    }
    Ok(())
}

struct StreamLine {
    stream: &'static str,
    data: String,
}

/// Reads one output stream of the child, framing on newlines.
///
/// Deliberately byte-oriented. `read_line` requires valid UTF-8 and returns
/// an error on the first stray byte, and treating that error as end-of-stream
/// silently discarded everything the command printed afterwards: a single
/// non-UTF-8 byte anywhere in the output truncated the response while the
/// exit status still said success, so callers could not tell. Guest output is
/// arbitrary bytes (compiler diagnostics, binary dumps, any non-UTF-8 locale),
/// so the transport must carry them. Invalid sequences become replacement
/// characters because the wire format is JSON, which cannot express them.
fn read_stream<R: Read + Send + 'static>(
    stream: &'static str,
    reader: R,
    sender: mpsc::Sender<StreamLine>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let data = String::from_utf8_lossy(&line).into_owned();
                    if sender.send(StreamLine { stream, data }).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

fn write_stream_line(stream: &mut impl Write, line: StreamLine) -> shinu::Result<()> {
    http::respond_chunk(stream, &json!({ "stream": line.stream, "data": line.data }))?;
    Ok(())
}
struct StreamingChildCleanup {
    child: Child,
    stdout_reader: Option<thread::JoinHandle<()>>,
    stderr_reader: Option<thread::JoinHandle<()>>,
    kill_on_drop: bool,
}

impl StreamingChildCleanup {
    fn new(child: Child) -> Self {
        Self {
            child,
            stdout_reader: None,
            stderr_reader: None,
            kill_on_drop: true,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn set_readers(
        &mut self,
        stdout_reader: thread::JoinHandle<()>,
        stderr_reader: thread::JoinHandle<()>,
    ) {
        self.stdout_reader = Some(stdout_reader);
        self.stderr_reader = Some(stderr_reader);
    }

    fn disarm(&mut self) {
        // `try_wait` has reaped the child; avoid signaling a PID that may be
        // reused before this guard is dropped.
        self.kill_on_drop = false;
    }
}
impl Drop for StreamingChildCleanup {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

fn execute_streaming(
    stream: &mut TcpStream,
    ctx: &Ctx<'_>,
    project: &str,
    space: String,
    command: Vec<String>,
    stdin_data: Option<String>,
    session: Option<String>,
) -> shinu::Result<()> {
    // A VM with an exec in flight is not idle, but nothing else refreshes
    // `last_used` while a command runs: `touch` fires only inside vm::start,
    // so a single long-running agent command would cross the idle window and
    // get reaped mid-command by sweep_idle, killing the SSH channel from under
    // the guest. Refresh it here for the lifetime of the child; the warm-VM
    // case (start already running, no touch at all) is covered by the first
    // refresh below.
    const TOUCH_EVERY: Duration = Duration::from_secs(30);
    let target = prepare_ssh(ctx, project, &space)?;
    let session_command = session
        .as_deref()
        .map(|session| session_remote_command(session, &command, stdin_data.is_some()));
    let remote = session_command.as_deref().unwrap_or(command.as_slice());
    let stdin_mode = if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    let mut cleanup = StreamingChildCleanup::new(spawn_ssh(
        &target,
        remote,
        stdin_mode,
        Stdio::piped(),
        Stdio::piped(),
    )?);
    let stdout = cleanup
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| shinu::Error::Invalid("ssh stdout pipe unavailable".into()))?;
    let stderr = cleanup
        .child_mut()
        .stderr
        .take()
        .ok_or_else(|| shinu::Error::Invalid("ssh stderr pipe unavailable".into()))?;
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = read_stream("stdout", stdout, sender.clone());
    let stderr_reader = read_stream("stderr", stderr, sender);
    cleanup.set_readers(stdout_reader, stderr_reader);
    if let Some(stdin_data) = stdin_data {
        let mut child_stdin = cleanup
            .child_mut()
            .stdin
            .take()
            .ok_or_else(|| shinu::Error::Invalid("ssh stdin pipe unavailable".into()))?;
        // Exec JSON is capped at 1 MiB, so this write can block only for a
        // bounded amount of input while the reader threads drain SSH output.
        if let Err(error) = child_stdin.write_all(stdin_data.as_bytes()) {
            return Err(error.into());
        }
        // EOF tells commands such as `cat` that the complete stdin payload has
        // arrived; retaining this handle would leave them waiting forever.
        drop(child_stdin);
    }
    http::respond_chunked_start(stream)?;

    let mut readers = 2;
    let mut child_status = None;
    let mut stream_broken = false;
    let mut last_touch = Instant::now();
    let _ = shinu::vm::touch(&target.vm_dir);

    while readers > 0 || child_status.is_none() {
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => {
                if write_stream_line(stream, line).is_err() {
                    stream_broken = true;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => readers = 0,
        }
        if last_touch.elapsed() >= TOUCH_EVERY {
            let _ = shinu::vm::touch(&target.vm_dir);
            last_touch = Instant::now();
        }

        if child_status.is_none() {
            match cleanup.child_mut().try_wait() {
                Ok(status) => {
                    if status.is_some() {
                        cleanup.disarm();
                    }
                    child_status = status;
                }
                Err(_) => {
                    stream_broken = true;
                    break;
                }
            }
        }
    }
    if !stream_broken {
        while let Ok(line) = receiver.try_recv() {
            if write_stream_line(stream, line).is_err() {
                stream_broken = true;
                break;
            }
        }
    }
    if stream_broken {
        return Ok(());
    }
    let exit = child_status.and_then(|status| status.code()).unwrap_or(255);
    let _ = http::respond_chunk(stream, &json!({ "exit": exit }));
    let _ = http::respond_chunked_end(stream);
    cleanup.disarm();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CkptFlags, append_checkpoint, handle, read_stream, set_head};
    use chrono::Utc;
    use rusqlite::Connection;
    use shinu::{
        Image, NetConfig, VmConfig,
        proto::{Req, SnapshotMode},
        quota::{Limits, RateLimiter},
        state::{self, Ckpt, Space, State},
        vm,
    };
    use std::collections::HashMap;
    use std::io::{Read as IoRead, Write as IoWrite};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, LazyLock, Mutex};
    use std::thread;
    use std::time::Duration;
    use uuid::Uuid;

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("shinu-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[test]
    fn startup_purges_diff_temp_and_allocates_unique_paths() {
        let root = test_root("diff-temp-cleanup");
        let temp_dir = super::diff_temp_dir(&root);
        std::fs::create_dir_all(&temp_dir).expect("create diff temp directory");
        std::fs::write(temp_dir.join("stale.ext4"), b"stale").expect("write stale diff input");
        let first = super::diff_temp_path(&root);
        let second = super::diff_temp_path(&root);
        assert_eq!(first.parent(), Some(temp_dir.as_path()));
        assert_eq!(second.parent(), Some(temp_dir.as_path()));
        assert_ne!(first, second, "diff inputs need per-operation paths");
        super::purge_diff_temp(&root).expect("purge stale diff inputs");
        assert!(
            !temp_dir.exists(),
            "startup purge must remove derived inputs"
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn read_only_checkpoint_probes_do_not_wait_for_checkpoint_lock() {
        let root = test_root("checkpoint-read-lock-scope");
        let project = "project-a";
        let checkpoint_id = Uuid::new_v4();
        store_state(
            &root,
            &State {
                spaces: Vec::new(),
                ckpts: vec![Ckpt {
                    id: checkpoint_id,
                    space: Uuid::new_v4(),
                    project: project.into(),
                    parent: None,
                    auto: true,
                    full: false,
                    base: None,
                    note: "old auto checkpoint".into(),
                    created_at: Utc::now() - chrono::Duration::days(30),
                    snapshot_version: None,
                }],
                templates: Vec::new(),
            },
        );
        let db = test_db(&root);
        let registry = registry();
        let (vm_cfg, net_cfg) = test_configs();
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let checkpoint_guard = registry.checkpoint_lock(checkpoint_id);
        let _checkpoint_guard = checkpoint_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let listing = super::list_spaces(&ctx, project).expect("list checkpoint while locked");
        assert_eq!(listing["ckpts"][0]["exclusive"], 0);
        let dry_run = super::gc(&ctx, project, u64::MAX, true).expect("GC dry run while locked");
        assert_eq!(dry_run["dry_run"], true);
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    fn test_configs() -> (VmConfig, NetConfig) {
        (
            VmConfig {
                vcpus: 1,
                mem_mib: 1,
                idle_secs: 1,
                jail_uid: 30000,
                jail_gid: 30000,
            },
            NetConfig {
                enabled: false,
                base: [172, 31],
                allow: Vec::new(),
                host_allow: Vec::new(),
                uplink: String::new(),
            },
        )
    }

    fn registry() -> shinu::registry::Registry {
        shinu::registry::Registry::new()
    }

    fn test_db(root: &std::path::Path) -> Mutex<Connection> {
        Mutex::new(state::open(root).expect("open test database"))
    }
    #[test]
    fn network_members_are_scoped_by_project_and_name() {
        fn space(id: Uuid, name: &str, project: &str, network: Option<&str>) -> Space {
            Space {
                id,
                name: name.to_owned(),
                project: project.to_owned(),
                image: Image::Void,
                parent: None,
                head: None,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: network.map(str::to_owned),
                expires_at: None,

                created_at: Utc::now(),
            }
        }
        let state = State {
            spaces: vec![
                space(Uuid::new_v4(), "web", "project-a", Some("blue")),
                space(Uuid::new_v4(), "db", "project-a", Some("blue")),
                space(Uuid::new_v4(), "other-network", "project-a", Some("green")),
                space(Uuid::new_v4(), "other-project", "project-b", Some("blue")),
                space(Uuid::new_v4(), "isolated", "project-a", None),
            ],
            ckpts: Vec::new(),
            templates: Vec::new(),
        };
        let members = super::network_members(&state, "project-a", Some("blue"));
        assert_eq!(
            members
                .iter()
                .map(|space| space.name.as_str())
                .collect::<Vec<_>>(),
            vec!["web", "db"]
        );
        assert!(
            super::network_members(&state, "project-b", Some("blue"))
                .iter()
                .all(|space| space.name == "other-project")
        );
        assert!(super::network_members(&state, "project-a", None).is_empty());
    }

    fn test_limits() -> &'static Limits {
        static LIMITS: LazyLock<Limits> = LazyLock::new(|| Limits {
            max_spaces: 5,
            max_disk_mib: 10240,
            max_vcpus: 16,
            max_mem_mib: 262_144,
            max_running: 2,
            api_per_min: 120,
        });
        &LIMITS
    }

    fn test_rate() -> &'static RateLimiter {
        static RATE: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);
        &RATE
    }
    fn test_register_rate() -> &'static super::RegistrationLimiter {
        static RATE: LazyLock<super::RegistrationLimiter> =
            LazyLock::new(super::RegistrationLimiter::new);
        &RATE
    }

    fn store_state(root: &std::path::Path, value: &State) {
        let connection = state::open(root).expect("open test database");
        state::store(&connection, value).expect("write test state");
    }

    fn daemon_ctx<'a>(
        root: &'a std::path::Path,
        db: &'a Mutex<Connection>,
        vm_cfg: &'a VmConfig,
        net_cfg: &'a NetConfig,
        registry: &'a shinu::registry::Registry,
    ) -> super::Ctx<'a> {
        super::Ctx {
            root,
            db,
            vm_cfg,
            net_cfg,
            limits: test_limits(),
            rate: test_rate(),
            register_rate: test_register_rate(),
            registry,
            admin_token: None,
        }
    }
    fn snapshot_test_space(id: Uuid, head: Option<Uuid>) -> Space {
        Space {
            id,
            name: "snapshot-space".into(),
            project: "project-a".into(),
            image: Image::Void,
            parent: None,
            head,
            vcpus: None,
            mem_mib: None,
            disk_mib: None,
            network: None,
            expires_at: None,

            created_at: Utc::now(),
        }
    }

    fn snapshot_test_checkpoint(
        id: Uuid,
        space: Uuid,
        parent: Option<Uuid>,
        base: Option<Uuid>,
        snapshot_version: Option<&str>,
    ) -> Ckpt {
        Ckpt {
            id,
            space,
            project: "project-a".into(),
            parent,
            auto: false,
            full: true,
            base,
            note: "snapshot test".into(),
            created_at: Utc::now(),
            snapshot_version: snapshot_version.map(str::to_owned),
        }
    }

    fn write_snapshot_test_files(root: &std::path::Path, id: Uuid) {
        std::fs::create_dir_all(root.join("ckpts")).expect("create checkpoint directory");
        std::fs::write(shinu::ckpt_mem(root, id), b"memory").expect("write memory snapshot");
        std::fs::write(shinu::ckpt_state(root, id), b"state").expect("write snapshot state");
    }

    fn snapshot_test_chain(root: &std::path::Path, diff_count: usize) -> (State, Uuid) {
        let space_id = Uuid::new_v4();
        let base_id = Uuid::new_v4();
        let mut space = snapshot_test_space(space_id, Some(base_id));
        let base = snapshot_test_checkpoint(
            base_id,
            space_id,
            None,
            None,
            Some(shinu::FC_SNAPSHOT_VERSION),
        );
        write_snapshot_test_files(root, base_id);
        let mut checkpoints = vec![base];
        let mut parent = base_id;
        for _ in 0..diff_count {
            let id = Uuid::new_v4();
            checkpoints.push(snapshot_test_checkpoint(
                id,
                space_id,
                Some(parent),
                Some(base_id),
                Some(shinu::FC_SNAPSHOT_VERSION),
            ));
            parent = id;
        }
        space.head = Some(parent);
        (
            State {
                spaces: vec![space],
                ckpts: checkpoints,
                templates: Vec::new(),
            },
            base_id,
        )
    }

    #[test]
    fn first_full_snapshot_request_stays_full_without_an_ancestor() {
        let root = test_root("full-first");
        let space = snapshot_test_space(Uuid::new_v4(), None);
        let state = State {
            spaces: vec![space.clone()],
            ckpts: Vec::new(),
            templates: Vec::new(),
        };

        let (mode, base) =
            super::resolve_snapshot_mode(&root, &state, &space, SnapshotMode::Full, 8)
                .expect("resolve first full snapshot");
        assert_eq!(mode, SnapshotMode::Full);
        assert!(base.is_none());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn second_full_snapshot_request_degrades_to_diff_against_the_base() {
        let root = test_root("full-second");
        let space_id = Uuid::new_v4();
        let base_id = Uuid::new_v4();
        let space = snapshot_test_space(space_id, Some(base_id));
        let base = snapshot_test_checkpoint(
            base_id,
            space_id,
            None,
            None,
            Some(shinu::FC_SNAPSHOT_VERSION),
        );
        write_snapshot_test_files(&root, base_id);
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![base],
            templates: Vec::new(),
        };

        let (mode, selected) =
            super::resolve_snapshot_mode(&root, &state, &space, SnapshotMode::Full, 8)
                .expect("resolve second full snapshot");
        assert_eq!(mode, SnapshotMode::Diff);
        assert_eq!(
            selected.as_ref().map(|checkpoint| checkpoint.id),
            Some(base_id)
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn full_snapshot_frequency_bounds_diffs_on_one_base() {
        for (diff_count, expected_mode) in [(7, SnapshotMode::Diff), (8, SnapshotMode::Full)] {
            let root = test_root("full-frequency");
            let (state, base_id) = snapshot_test_chain(&root, diff_count);
            let space = &state.spaces[0];
            let (mode, selected) =
                super::resolve_snapshot_mode(&root, &state, space, SnapshotMode::Full, 8)
                    .expect("resolve frequency-bounded full snapshot");
            assert_eq!(mode, expected_mode);
            if expected_mode == SnapshotMode::Diff {
                assert_eq!(
                    selected.as_ref().map(|checkpoint| checkpoint.id),
                    Some(base_id)
                );
            } else {
                assert!(selected.is_none());
            }
            std::fs::remove_dir_all(root).expect("remove test root");
        }
    }

    #[test]
    fn mismatched_snapshot_version_forces_a_new_full_snapshot() {
        let root = test_root("full-stale-version");
        let space_id = Uuid::new_v4();
        let base_id = Uuid::new_v4();
        let space = snapshot_test_space(space_id, Some(base_id));
        let base = snapshot_test_checkpoint(base_id, space_id, None, None, Some("8.0.0"));
        write_snapshot_test_files(&root, base_id);
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![base],
            templates: Vec::new(),
        };

        let (mode, selected) =
            super::resolve_snapshot_mode(&root, &state, &space, SnapshotMode::Full, 8)
                .expect("resolve stale full snapshot");
        assert_eq!(mode, SnapshotMode::Full);
        assert!(selected.is_none());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn missing_base_snapshot_file_forces_a_new_full_snapshot() {
        let root = test_root("full-missing-file");
        let space_id = Uuid::new_v4();
        let base_id = Uuid::new_v4();
        let space = snapshot_test_space(space_id, Some(base_id));
        let base = snapshot_test_checkpoint(
            base_id,
            space_id,
            None,
            None,
            Some(shinu::FC_SNAPSHOT_VERSION),
        );
        write_snapshot_test_files(&root, base_id);
        std::fs::remove_file(shinu::ckpt_mem(&root, base_id)).expect("remove base memory snapshot");
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![base],
            templates: Vec::new(),
        };

        let (mode, selected) =
            super::resolve_snapshot_mode(&root, &state, &space, SnapshotMode::Full, 8)
                .expect("resolve missing base snapshot");
        assert_eq!(mode, SnapshotMode::Full);
        assert!(selected.is_none());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn zero_full_frequency_disables_automatic_degradation() {
        let root = test_root("full-frequency-zero");
        assert_eq!(super::full_every_from(Some("0")), 0);
        let (state, _) = snapshot_test_chain(&root, 0);
        let space = &state.spaces[0];

        let (mode, selected) =
            super::resolve_snapshot_mode(&root, &state, space, SnapshotMode::Full, 0)
                .expect("resolve zero frequency full snapshot");
        assert_eq!(mode, SnapshotMode::Full);
        assert!(selected.is_none());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn explicit_diff_without_a_valid_base_remains_an_error() {
        let root = test_root("diff-no-base");
        let space = snapshot_test_space(Uuid::new_v4(), None);
        let state = State {
            spaces: vec![space.clone()],
            ckpts: Vec::new(),
            templates: Vec::new(),
        };

        let result = super::resolve_snapshot_mode(&root, &state, &space, SnapshotMode::Diff, 8);
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("existing full checkpoint")
        ));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn full_resolution_skips_invalid_newer_full_ancestors() {
        let root = test_root("full-skip-invalid");
        let space_id = Uuid::new_v4();
        let old_base_id = Uuid::new_v4();
        let stale_base_id = Uuid::new_v4();
        let space = snapshot_test_space(space_id, Some(stale_base_id));
        let old_base = snapshot_test_checkpoint(
            old_base_id,
            space_id,
            None,
            None,
            Some(shinu::FC_SNAPSHOT_VERSION),
        );
        let stale_base = snapshot_test_checkpoint(
            stale_base_id,
            space_id,
            Some(old_base_id),
            None,
            Some("8.0.0"),
        );
        write_snapshot_test_files(&root, old_base_id);
        write_snapshot_test_files(&root, stale_base_id);
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![old_base, stale_base],
            templates: Vec::new(),
        };

        let (mode, selected) =
            super::resolve_snapshot_mode(&root, &state, &space, SnapshotMode::Full, 8)
                .expect("resolve full snapshot past stale ancestor");
        assert_eq!(mode, SnapshotMode::Diff);
        assert_eq!(
            selected.as_ref().map(|checkpoint| checkpoint.id),
            Some(old_base_id)
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn log_reports_the_recorded_diff_snapshot_mode() {
        let root = test_root("log-diff-mode");
        let space_id = Uuid::new_v4();
        let base_id = Uuid::new_v4();
        let diff_id = Uuid::new_v4();
        let space = snapshot_test_space(space_id, Some(diff_id));
        let base = snapshot_test_checkpoint(
            base_id,
            space_id,
            None,
            None,
            Some(shinu::FC_SNAPSHOT_VERSION),
        );
        let diff = snapshot_test_checkpoint(
            diff_id,
            space_id,
            Some(base_id),
            Some(base_id),
            Some(shinu::FC_SNAPSHOT_VERSION),
        );
        store_state(
            &root,
            &State {
                spaces: vec![space],
                ckpts: vec![base, diff],
                templates: Vec::new(),
            },
        );
        let db = test_db(&root);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);

        let log = handle(
            &ctx,
            Req::Log {
                space: "snapshot-space".into(),
            },
            "project-a",
        )
        .expect("read snapshot log");
        assert_eq!(log["commits"][0]["snapshot"], "diff");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn checkpoint_responses_report_the_actual_snapshot_mode() {
        let base_id = Uuid::new_v4();
        let space_id = Uuid::new_v4();
        let diff = super::Ckpt {
            id: Uuid::new_v4(),
            space: space_id,
            project: "project-a".into(),
            parent: Some(base_id),
            auto: false,
            full: true,
            base: Some(base_id),
            note: "diff".into(),
            created_at: Utc::now(),
            snapshot_version: Some(shinu::FC_SNAPSHOT_VERSION.into()),
        };
        let full = super::Ckpt {
            base: None,
            full: true,
            note: "full".into(),
            ..diff.clone()
        };
        let disk = super::Ckpt {
            base: None,
            full: false,
            note: "disk".into(),
            snapshot_version: None,
            ..diff.clone()
        };
        assert_eq!(
            super::checkpoint_json(&diff).expect("diff response")["snapshot"],
            "diff"
        );
        assert_eq!(
            super::checkpoint_json(&full).expect("full response")["snapshot"],
            "full"
        );
        assert_eq!(
            super::checkpoint_json(&disk).expect("disk response")["snapshot"],
            "none"
        );
    }

    fn checkpoint_for_snapshot_gate(full: bool, snapshot_version: Option<&str>) -> Ckpt {
        Ckpt {
            id: Uuid::new_v4(),
            space: Uuid::new_v4(),
            project: "project-a".into(),
            parent: None,
            auto: false,
            full,
            base: None,
            note: "snapshot gate test".into(),
            created_at: Utc::now(),
            snapshot_version: snapshot_version.map(str::to_owned),
        }
    }

    #[test]
    fn snapshot_load_gate_accepts_disk_only_checkpoint() {
        let checkpoint = checkpoint_for_snapshot_gate(false, None);
        assert!(super::ensure_snapshot_loadable(&checkpoint).is_ok());
    }

    #[test]
    fn snapshot_load_gate_accepts_matching_version() {
        let checkpoint = checkpoint_for_snapshot_gate(true, Some(shinu::FC_SNAPSHOT_VERSION));
        assert!(super::ensure_snapshot_loadable(&checkpoint).is_ok());
    }

    #[test]
    fn snapshot_load_gate_rejects_unrecorded_memory_state() {
        let checkpoint = checkpoint_for_snapshot_gate(true, None);
        let id = checkpoint.id.to_string();
        let result = super::ensure_snapshot_loadable(&checkpoint);
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message))
                if message.contains(&id)
                    && message.contains("unrecorded")
                    && message.contains(shinu::FC_SNAPSHOT_VERSION)
                    && message.contains("disk image is still usable")
        ));
    }

    #[test]
    fn snapshot_load_gate_rejects_stale_memory_state_as_invalid() {
        let checkpoint = checkpoint_for_snapshot_gate(true, Some("8.0.0"));
        let id = checkpoint.id.to_string();
        let result = super::ensure_snapshot_loadable(&checkpoint);
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message))
                if message.contains(&id)
                    && message.contains("8.0.0")
                    && message.contains(shinu::FC_SNAPSHOT_VERSION)
                    && message.contains("disk image is still usable")
        ));
    }

    #[test]
    fn exec_command_accepts_absent_and_present_stdin() {
        let value =
            super::parse_body(br#"{"cmd":["sh","-c","cat"]}"#).expect("parse exec without stdin");
        let (command, stdin) = super::exec_command_value(&value).expect("exec without stdin");
        assert_eq!(command, vec!["sh", "-c", "cat"]);
        assert_eq!(stdin, None);
        let value = super::parse_body(br#"{"cmd":["cat"],"stdin":"payload"}"#)
            .expect("parse exec with stdin");
        let (_, stdin) = super::exec_command_value(&value).expect("exec with stdin");
        assert_eq!(stdin.as_deref(), Some("payload"));
        let value = super::parse_body(br#"{"cmd":["cat"],"stdin":null}"#)
            .expect("parse exec with null stdin");
        let (_, stdin) = super::exec_command_value(&value).expect("exec with null stdin");
        assert_eq!(stdin, None);
    }

    #[test]
    fn exec_command_rejects_non_string_stdin() {
        let value = super::parse_body(br#"{"cmd":["cat"],"stdin":7}"#).expect("parse exec body");
        assert!(matches!(
            super::exec_command_value(&value),
            Err(shinu::Error::Invalid(message)) if message == "stdin must be a string"
        ));
    }

    #[test]
    fn exec_request_defaults_session_and_rejects_unsafe_ids() {
        let (request, status) = super::request_for(
            super::Endpoint::Exec("demo".into()),
            "POST",
            br#"{"cmd":["pwd"]}"#,
            None,
            None,
        )
        .expect("parse stateless exec request");
        assert_eq!(status, 200);
        assert!(matches!(
            request,
            Req::Exec {
                space,
                session: None,
                ..
            } if space == "demo"
        ));

        let (request, _) = super::request_for(
            super::Endpoint::Exec("demo".into()),
            "POST",
            br#"{"cmd":["pwd"],"session":"agent_1"}"#,
            None,
            None,
        )
        .expect("parse persistent exec request");
        assert!(matches!(
            request,
            Req::Exec {
                session: Some(session),
                ..
            } if session == "agent_1"
        ));

        for session in ["agent;rm", "agent/name"] {
            let body = format!(r#"{{"session":"{session}"}}"#);
            let value = super::parse_body(body.as_bytes()).expect("parse session body");
            let error = super::exec_session_value(&value)
                .expect_err("unsafe session id should be rejected");
            assert!(
                error.to_string().contains("session id"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn persistent_exec_session_preserves_state_and_output_markers() {
        fn run(session: &str, command: &[&str]) -> std::process::Output {
            let command = command
                .iter()
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>();
            let remote = super::session_remote_command(session, &command, false);
            Command::new(&remote[0])
                .args(&remote[1..])
                .output()
                .expect("run guest session wrapper")
        }
        fn run_with_stdin(session: &str, command: &[&str], input: &[u8]) -> std::process::Output {
            let command = command
                .iter()
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>();
            let remote = super::session_remote_command(session, &command, true);
            let mut child = Command::new(&remote[0])
                .args(&remote[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn guest session wrapper");
            child
                .stdin
                .take()
                .expect("session wrapper stdin")
                .write_all(input)
                .expect("write session wrapper stdin");
            child
                .wait_with_output()
                .expect("wait for guest session wrapper")
        }
        let session = format!("test-{}", Uuid::new_v4());
        let session_dir = PathBuf::from(format!("/tmp/shinu-session-{session}"));
        let cleanup = || {
            if let Some(pid) = std::fs::read_to_string(session_dir.join("pid"))
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok())
            {
                let pid = pid.to_string();
                let alive = Command::new("kill")
                    .args(["-0", &pid])
                    .stderr(Stdio::null())
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false);
                if alive {
                    let _ = Command::new("kill").arg(pid).stderr(Stdio::null()).status();
                }
            }
            let _ = std::fs::remove_dir_all(&session_dir);
        };

        let changed = run(&session, &["cd", "/tmp"]);
        assert!(changed.status.success(), "stderr: {:?}", changed.stderr);
        let exported = run(&session, &["export", "SHINU_SESSION_TEST=ok"]);
        assert!(exported.status.success(), "stderr: {:?}", exported.stderr);
        let pwd = run(&session, &["pwd"]);
        assert_eq!(pwd.status.code(), Some(0));
        assert_eq!(pwd.stdout, b"/tmp\n");
        let env = run(
            &session,
            &["sh", "-c", "printf '%s\\n' \"$SHINU_SESSION_TEST\""],
        );
        assert_eq!(env.status.code(), Some(0));
        assert_eq!(env.stdout, b"ok\n");
        let child_exported = run(&session, &["sh", "-c", "export SHINU_CHILD_TEST=child"]);
        assert_eq!(child_exported.status.code(), Some(0));
        let child_env = run(&session, &["sh", "-c", "printf '%s' \"$SHINU_CHILD_TEST\""]);
        assert_eq!(child_env.status.code(), Some(0));
        assert!(child_env.stdout.is_empty());
        let echoed = run_with_stdin(&session, &["cat"], b"session input\n");
        assert_eq!(echoed.status.code(), Some(0));
        assert_eq!(echoed.stdout, b"session input\n");
        let streams = run(&session, &["sh", "-c", "printf stdout; printf stderr >&2"]);
        assert_eq!(streams.status.code(), Some(0));
        assert_eq!(streams.stdout, b"stdout");
        assert_eq!(streams.stderr, b"stderr");

        // The wrapper has no sentinel in the command output protocol. A value
        // that looks like a framing delimiter therefore remains ordinary output.
        let marker = "__SHINU_EXEC_FRAME_MARKER__";
        let marked_output = run(&session, &["printf", "%s\\n", marker]);
        assert_eq!(marked_output.status.code(), Some(0));
        assert_eq!(marked_output.stdout, format!("{marker}\n").into_bytes());

        let failed = run(&session, &["sh", "-c", "exit 3"]);
        assert_eq!(failed.status.code(), Some(3));
        let failed_builtin = run(&session, &["exit", "3"]);
        assert_eq!(failed_builtin.status.code(), Some(3));
        cleanup();
    }
    #[test]
    fn new_request_round_trips_and_validates_network() {
        let request = super::new_request(br#"{"name":"web","network":"lan-1"}"#)
            .expect("parse network create request");
        assert!(matches!(
            request,
            Req::New {
                network: Some(network),
                ..
            } if network == "lan-1"
        ));
        assert!(matches!(
            super::new_request(br#"{"name":"web","network":"LAN"}"#),
            Err(shinu::Error::Invalid(message))
                if message.contains("network name must be non-empty")
        ));
    }

    #[test]
    fn transfer_routes_and_methods_are_explicit() {
        let push = super::route("/v1/spaces/demo/push?path=%2Ftmp%2Ffile").expect("push route");
        let pull = super::route("/v1/spaces/demo/pull?path=%2Ftmp%2Ffile").expect("pull route");
        let vnc = super::route("/v1/spaces/demo/vnc").expect("vnc route");
        let diff = super::route("/v1/spaces/demo/diff").expect("diff route");
        let exec = super::route("/v1/spaces/demo/exec").expect("exec route");
        assert!(matches!(&exec, super::Endpoint::Exec(name) if name == "demo"));
        assert!(super::method_allowed(&exec, "POST"));
        assert!(!super::method_allowed(&exec, "GET"));
        assert!(matches!(&vnc, super::Endpoint::Vnc(name) if name == "demo"));
        assert!(super::method_allowed(&vnc, "GET"));
        assert!(!super::method_allowed(&vnc, "POST"));
        assert!(matches!(&diff, super::Endpoint::Diff(name) if name == "demo"));
        assert!(super::method_allowed(&diff, "GET"));
        assert!(!super::method_allowed(&diff, "POST"));
        assert!(matches!(&push, super::Endpoint::Push(name) if name == "demo"));
        assert!(matches!(&pull, super::Endpoint::Pull(name) if name == "demo"));
        assert!(super::method_allowed(&push, "POST"));
        assert!(!super::method_allowed(&push, "GET"));
        assert!(super::method_allowed(&pull, "GET"));
        assert!(!super::method_allowed(&pull, "POST"));
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let request = super::diff_request(
            &format!("/v1/spaces/demo/diff?from={first}&to={second}&all=1&limit=12"),
            "demo".to_owned(),
        )
        .expect("diff query");
        assert!(matches!(
            request,
            Req::Diff {
                space,
                from: Some(actual_first),
                to: Some(actual_second),
                all: true,
                limit: 12,
            } if space == "demo" && actual_first == first && actual_second == second
        ));
    }

    #[test]
    fn project_limit_route_requires_admin_for_mutation() {
        let root = test_root("project-limit-auth");
        let db = test_db(&root);
        let registry = registry();
        let (vm_cfg, net_cfg) = test_configs();
        let mut ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        ctx.admin_token = Some("admin-secret");

        let project_token = shinu::token::mint().expect("mint project token");
        shinu::token::store(
            &root,
            &[shinu::token::Token {
                hash: shinu::token::hash(&project_token),
                project: "project-a".into(),
                created_at: Utc::now(),
            }],
        )
        .expect("store project token");

        let endpoint = super::route("/v1/projects/project-a/limits").expect("limits route");
        assert!(
            matches!(&endpoint, super::Endpoint::ProjectLimits(project) if project == "project-a")
        );
        assert!(super::method_allowed(&endpoint, "GET"));
        assert!(super::method_allowed(&endpoint, "PATCH"));
        assert!(super::method_allowed(&endpoint, "DELETE"));

        let body = r#"{"max_spaces":0}"#;
        let denied = serve_raw(
            &ctx,
            &format!(
                "PATCH /v1/projects/project-a/limits HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {project_token}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(denied.starts_with("HTTP/1.1 401"), "response: {denied}");
        assert!(
            state::project_limits(&super::lock_db(&db), "project-a")
                .expect("read denied limits")
                .is_none()
        );

        let granted = serve_raw(
            &ctx,
            &format!(
                "PATCH /v1/projects/project-a/limits HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(granted.starts_with("HTTP/1.1 200"), "response: {granted}");
        assert_eq!(
            state::project_limit_overrides(&super::lock_db(&db), "project-a")
                .expect("read granted limits"),
            Some((Some(0), None, None, None))
        );

        let cleared = serve_raw(
            &ctx,
            "DELETE /v1/projects/project-a/limits HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer admin-secret\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(cleared.starts_with("HTTP/1.1 200"), "response: {cleared}");
        assert!(
            state::project_limits(&super::lock_db(&db), "project-a")
                .expect("read cleared limits")
                .is_none()
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn proxy_routes_preserve_guest_path_and_allow_http_methods() {
        let endpoint = super::route("/v1/spaces/demo/proxy/8080/api%2Fv1/items?q=one%20two")
            .expect("proxy route");
        assert!(matches!(
            &endpoint,
            super::Endpoint::Proxy { space, port, path }
                if space == "demo" && *port == 8080 && path == "/api%2Fv1/items?q=one%20two"
        ));
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"] {
            assert!(super::method_allowed(&endpoint, method), "{method}");
        }
        assert!(!super::method_allowed(&endpoint, "OPTIONS"));
    }

    #[test]
    fn proxy_header_filter_rewrites_host_and_framing() {
        let raw = b"POST /v1/spaces/demo/proxy/8080/ HTTP/1.1\r\nHost: control\r\nConnection: X-Trace\r\nX-Trace: hidden\r\nX-Request: kept\r\nContent-Length: 4\r\n\r\n";
        let request =
            super::parse_proxy_request_head(raw, "POST", "/").expect("parse proxy request");
        let headers = super::proxy_request_headers(&request, 8080);
        assert!(headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Host") && header.value == "127.0.0.1:8080"
        }));
        assert!(headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("X-Request") && header.value == "kept"
        }));
        assert!(!headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("X-Trace")
                || header.name.eq_ignore_ascii_case("Transfer-Encoding")
        }));
        assert!(headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Content-Length") && header.value == "4"
        }));
        assert!(headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("Connection") && header.value == "close"
        }));
    }

    #[test]
    fn proxy_request_headers_strip_control_credentials_and_reserved_cookie() {
        let raw = b"GET /v1/spaces/demo/proxy/8080/ HTTP/1.1\r\nAuthorization: Bearer secret\r\nCookie: shinu_session=secret\r\nCookie: guest=kept; shinu_session=other; preference=dark\r\n\r\n";
        let request =
            super::parse_proxy_request_head(raw, "GET", "/").expect("parse proxy request");
        let headers = super::proxy_request_headers(&request, 8080);
        assert!(
            !headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("Authorization"))
        );
        let cookies = headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("Cookie"))
            .map(|header| header.value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(cookies, vec!["guest=kept; preference=dark"]);
        assert_eq!(
            super::proxy_cookie_without_session("shinu_session=secret"),
            None
        );
    }

    #[test]
    fn proxy_chunked_body_preserves_chunks_and_trailers() {
        let mut reader = std::io::Cursor::new(b"4\r\ntest\r\n0\r\nX-Trailer: yes\r\n\r\n");
        let mut output = Vec::new();
        super::copy_proxy_chunked(&mut reader, &mut output).expect("copy chunked body");
        assert_eq!(output, b"4\r\ntest\r\n0\r\nX-Trailer: yes\r\n\r\n");
    }

    #[test]
    fn proxy_failures_name_guest_port_and_phase() {
        let refused = super::proxy_bridge_error(
            "demo",
            8080,
            super::ProxyRelayFailure::BeforeResponse("Connection refused".into()),
        );
        assert!(
            refused
                .to_string()
                .contains("guest port 8080 in space demo has nothing listening")
        );
        let closed = super::proxy_bridge_error(
            "demo",
            8080,
            super::ProxyRelayFailure::GuestClosed("response ended before Content-Length".into()),
        );
        assert!(
            closed
                .to_string()
                .contains("guest in space demo closed port 8080 before completing its response")
        );
    }

    #[test]
    fn proxy_response_framing_accepts_length_and_chunked() {
        let mut length = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
        let response = super::parse_proxy_response_head(&mut length).expect("length response");
        assert!(matches!(
            super::proxy_response_body(&response, "GET"),
            Ok(super::ProxyBody::Length(4))
        ));
        let mut chunked =
            std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        let response = super::parse_proxy_response_head(&mut chunked).expect("chunked response");
        assert!(matches!(
            super::proxy_response_body(&response, "GET"),
            Ok(super::ProxyBody::Chunked)
        ));
    }

    #[test]
    fn proxy_response_headers_suppress_only_reserved_session_cookie() {
        let response = super::ProxyResponseHead {
            status_line: "HTTP/1.1 200 OK".into(),
            status: 200,
            headers: vec![
                super::ProxyHeader {
                    name: "Set-Cookie".into(),
                    value: "shinu_session=guest-secret; Path=/".into(),
                },
                super::ProxyHeader {
                    name: "Set-Cookie".into(),
                    value: "guest_preference=dark; Path=/".into(),
                },
                super::ProxyHeader {
                    name: "X-Guest".into(),
                    value: "kept".into(),
                },
            ],
        };
        let body = super::ProxyBody::Length(0);
        let connection_tokens: Vec<String> = Vec::new();
        assert!(super::proxy_response_header_is_filtered(
            &response.headers[0],
            &connection_tokens,
            &body,
        ));
        assert!(!super::proxy_response_header_is_filtered(
            &response.headers[1],
            &connection_tokens,
            &body,
        ));
        assert!(!super::proxy_response_header_is_filtered(
            &response.headers[2],
            &connection_tokens,
            &body,
        ));
    }

    #[test]
    fn resize_and_image_routes_allow_only_their_methods() {
        let resize = super::route("/v1/spaces/demo").expect("resize route");
        let images = super::route("/v1/images").expect("images route");
        assert!(matches!(&resize, super::Endpoint::Rm(name) if name == "demo"));
        assert!(super::method_allowed(&resize, "PATCH"));
        assert!(super::method_allowed(&resize, "DELETE"));
        assert!(!super::method_allowed(&resize, "GET"));
        assert!(matches!(images, super::Endpoint::Images));
        assert!(super::method_allowed(&images, "GET"));
        assert!(!super::method_allowed(&images, "POST"));
        let (request, status) = super::request_for(
            resize,
            "PATCH",
            br#"{"vcpus":4,"mem_mib":null}"#,
            None,
            None,
        )
        .expect("parse resize request");
        assert_eq!(status, 200);
        assert!(matches!(
            request,
            Req::Resize {
                vcpus: Some(Some(4)),
                mem_mib: Some(None),
                ..
            }
        ));
        assert!(matches!(
            super::resize_request(br#"{"image":"arch"}"#, "demo".into()),
            Err(shinu::Error::Invalid(message)) if message.contains("immutable")
        ));
    }

    #[test]
    fn commit_request_defaults_snapshot_to_none() {
        let (request, status) = super::request_for(
            super::Endpoint::Commit("demo".into()),
            "POST",
            br#"{"note":"disk","hot":false}"#,
            None,
            None,
        )
        .expect("parse commit request");
        assert_eq!(status, 201);
        assert!(matches!(
            request,
            Req::Commit {
                snapshot: SnapshotMode::None,
                ..
            }
        ));

        let (request, status) = super::request_for(
            super::Endpoint::Commit("demo".into()),
            "POST",
            br#"{"note":"memory","hot":false,"snapshot":"full"}"#,
            None,
            None,
        )
        .expect("parse full commit request");
        assert_eq!(status, 201);
        assert!(matches!(
            request,
            Req::Commit {
                snapshot: SnapshotMode::Full,
                ..
            }
        ));
        let (request, status) = super::request_for(
            super::Endpoint::Commit("demo".into()),
            "POST",
            br#"{"note":"delta","hot":false,"snapshot":"diff"}"#,
            None,
            None,
        )
        .expect("parse diff commit request");
        assert_eq!(status, 201);
        assert!(matches!(
            request,
            Req::Commit {
                snapshot: SnapshotMode::Diff,
                ..
            }
        ));
    }

    #[test]
    fn push_rejects_relative_paths_and_invalid_lengths() {
        assert!(matches!(
            super::transfer_path("/v1/spaces/demo/push?path=relative"),
            Err(shinu::Error::Invalid(message)) if message == "path must be absolute"
        ));
        assert!(matches!(
            super::upload_length(None),
            Err(shinu::Error::Invalid(message)) if message.contains("Content-Length")
        ));
        assert!(matches!(
            super::upload_length(Some(shinu::MAX_UPLOAD_BYTES + 1)),
            Err(shinu::Error::Invalid(message)) if message.contains("256 MiB")
        ));
    }
    #[test]
    fn rejects_empty_snapshot_note() {
        let root = test_root("empty-note");
        let (vm_cfg, net_cfg) = test_configs();
        let db = test_db(&root);
        let registry = registry();
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::Commit {
                space: "missing".into(),
                note: "  ".into(),
                hot: false,
                snapshot: SnapshotMode::None,
            },
            "project-a",
        );
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message == "checkpoint needs a note"
        ));
        std::fs::remove_dir_all(root).expect("remove test root");
    }
    #[test]
    fn space_quota_boundary_is_rejected_before_state_write() {
        let root = test_root("quota-boundary");
        let id = Uuid::new_v4();
        store_state(
            &root,
            &State {
                spaces: vec![Space {
                    id,
                    name: "one".into(),
                    project: "project-a".into(),
                    image: Image::Void,
                    vcpus: None,
                    mem_mib: None,
                    disk_mib: None,
                    network: None,
                    expires_at: None,

                    parent: None,
                    head: None,
                    created_at: Utc::now(),
                }],
                ckpts: Vec::new(),
                templates: Vec::new(),
            },
        );
        let db = test_db(&root);
        let registry = registry();
        let limits = Limits {
            max_spaces: 1,
            max_disk_mib: 10240,
            max_vcpus: 16,
            max_mem_mib: 262_144,
            max_running: 2,
            api_per_min: 120,
        };
        let result =
            super::update_state_with_quota(&root, &db, &registry, "project-a", &limits, 0, |_| {
                Ok(())
            });
        assert!(
            matches!(result, Err(shinu::Error::Quota(message)) if message.contains("space limit"))
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn rate_limit_rejects_the_request_after_the_boundary() {
        let rate = RateLimiter::new();
        assert!(rate.check("project-a", 1).is_ok());
        let result = rate.check("project-a", 1);
        assert!(
            matches!(result, Err(shinu::Error::Quota(message)) if message.contains("rate limit"))
        );
    }

    #[test]
    fn usage_query_accepts_unix_ranges_and_rejects_bad_values() {
        assert_eq!(
            super::usage_query("/v1/usage?from=10&to=20").expect("valid range"),
            (Some(10), Some(20))
        );
        assert!(super::usage_query("/v1/usage?from=nope").is_err());
    }

    #[test]
    fn effective_limits_prefers_project_override() {
        let root = test_root("project-limits");
        let db = test_db(&root);
        {
            let connection = db.lock().expect("lock test database");
            connection
                .execute(
                    "INSERT INTO projects(project,max_spaces,max_disk_mib,max_running,api_per_min) VALUES ('project-a',7,99,4,321)",
                    [],
                )
                .expect("insert project limits");
            connection
                .execute(
                    "INSERT INTO projects(project,max_spaces,max_disk_mib,max_running,api_per_min) VALUES ('project-unlimited',0,0,0,0)",
                    [],
                )
                .expect("insert unlimited project limits");
        }
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let global = Limits {
            max_spaces: 5,
            max_disk_mib: 10,
            max_vcpus: 16,
            max_mem_mib: 262_144,
            max_running: 2,
            api_per_min: 120,
        };
        let rate = RateLimiter::new();
        let ctx = super::Ctx {
            root: &root,
            db: &db,
            vm_cfg: &vm_cfg,
            net_cfg: &net_cfg,
            limits: &global,
            rate: &rate,
            register_rate: test_register_rate(),
            registry: &registry,
            admin_token: None,
        };
        let override_limits = super::effective_limits(&ctx, "project-a").expect("override");
        assert_eq!(override_limits.max_spaces, 7);
        assert_eq!(override_limits.max_disk_mib, 99);
        let default_limits = super::effective_limits(&ctx, "project-b").expect("default");
        assert_eq!(default_limits.max_spaces, 5);
        assert_eq!(default_limits.max_disk_mib, 10);
        let unlimited_limits =
            super::effective_limits(&ctx, "project-unlimited").expect("unlimited override");
        assert_eq!(unlimited_limits.max_spaces, 0);
        assert_eq!(unlimited_limits.max_disk_mib, 0);
        assert_eq!(unlimited_limits.max_running, 0);
        assert_eq!(unlimited_limits.api_per_min, 0);
        assert!(shinu::quota::check_space_limit(7, &unlimited_limits).is_ok());
        assert!(shinu::quota::check_disk_limit(u64::MAX, u64::MAX, &unlimited_limits).is_ok());
        assert!(shinu::quota::check_running_limit(3, &unlimited_limits).is_ok());
        assert!(
            RateLimiter::new()
                .check("project-unlimited", unlimited_limits.api_per_min)
                .is_ok()
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn resize_rejects_disk_shrink_as_data_loss() {
        let root = test_root("resize-shrink");
        let space_id = Uuid::new_v4();
        store_state(
            &root,
            &State {
                spaces: vec![Space {
                    id: space_id,
                    name: "resizable".into(),
                    project: "project-a".into(),
                    image: Image::Void,
                    parent: None,
                    head: None,
                    vcpus: None,
                    mem_mib: None,
                    disk_mib: Some(100),
                    network: None,
                    expires_at: None,

                    created_at: Utc::now(),
                }],
                ckpts: Vec::new(),
                templates: Vec::new(),
            },
        );
        let db = test_db(&root);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::Resize {
                space: "resizable".into(),
                vcpus: None,
                mem_mib: None,
                disk_mib: Some(Some(99)),
            },
            "project-a",
        );
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("data loss")
        ));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    fn running_state(root: &std::path::Path, project: &str) -> (Uuid, Uuid, std::process::Child) {
        let space_id = Uuid::new_v4();
        let ckpt_id = Uuid::new_v4();
        let name = "running";
        let vm_dir = shinu::vm_dir(root, space_id);
        std::fs::create_dir_all(&vm_dir).expect("create VM directory");
        let config = vm::config_path(&vm_dir);
        std::fs::create_dir_all(config.parent().expect("config parent"))
            .expect("create config directory");
        std::fs::write(&config, "{}").expect("write fake config");
        let state = State {
            spaces: vec![Space {
                id: space_id,
                name: name.into(),
                project: project.into(),
                image: Image::Void,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: None,
                expires_at: None,

                parent: None,
                head: None,
                created_at: Utc::now(),
            }],
            ckpts: vec![Ckpt {
                id: ckpt_id,
                space: space_id,
                project: project.into(),
                parent: None,
                auto: false,
                full: false,
                base: None,
                note: "before".into(),
                created_at: Utc::now(),
                snapshot_version: None,
            }],
            templates: Vec::new(),
        };
        store_state(root, &state);
        let fake_firecracker = root.join("firecracker");
        symlink("/usr/bin/yes", &fake_firecracker).expect("link fake firecracker");
        let child = Command::new(&fake_firecracker)
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start fake firecracker");
        let pid_path = vm::pid_path(&vm_dir);
        std::fs::create_dir_all(pid_path.parent().expect("pid parent"))
            .expect("create pid directory");
        std::fs::write(pid_path, child.id().to_string()).expect("write fake pid");
        let running = (0..20).any(|_| {
            if vm::is_running(&vm_dir) {
                true
            } else {
                thread::sleep(Duration::from_millis(10));
                false
            }
        });
        assert!(running, "fake firecracker was not recognized as running");
        (space_id, ckpt_id, child)
    }

    #[test]
    fn resize_rejects_running_space_with_stop_requirement() {
        let root = test_root("resize-running");
        let (_space_id, _ckpt_id, mut child) = running_state(&root, "project-a");
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::Resize {
                space: "running".into(),
                vcpus: Some(Some(2)),
                mem_mib: None,
                disk_mib: None,
            },
            "project-a",
        );
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("stop the space")
        ));
        child.kill().expect("stop fake firecracker");
        child.wait().expect("wait fake firecracker");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn locked_space_revalidation_reads_current_sizing_network_and_head() {
        let root = test_root("space-revalidation");
        let project = "project-a";
        let space_id = Uuid::new_v4();
        let head = Uuid::new_v4();
        store_state(
            &root,
            &State {
                spaces: vec![Space {
                    id: space_id,
                    name: "web".into(),
                    project: project.into(),
                    image: Image::Void,
                    parent: None,
                    head: None,
                    vcpus: Some(1),
                    mem_mib: Some(512),
                    disk_mib: Some(10),
                    network: Some("old".into()),
                    expires_at: None,

                    created_at: Utc::now(),
                }],
                ckpts: Vec::new(),
                templates: Vec::new(),
            },
        );
        let db = test_db(&root);
        let registry = registry();
        let (vm_cfg, net_cfg) = test_configs();
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let initial = super::find_space(&db, "web", project).expect("initial lookup");
        let space_guard = registry.space_lock(initial.id);
        let _space_guard = space_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        super::update_state(&db, &registry, |state| {
            let space = state
                .spaces
                .iter_mut()
                .find(|space| space.id == space_id)
                .expect("space present");
            space.head = Some(head);
            space.vcpus = Some(4);
            space.mem_mib = Some(2048);
            space.network = Some("new".into());
            Ok(())
        })
        .expect("update metadata while waiting operation owns lock");
        let fresh =
            super::revalidate_space(&ctx, project, initial.id, "web").expect("fresh locked lookup");
        assert_eq!(fresh.vcpus, Some(4));
        assert_eq!(fresh.mem_mib, Some(2048));
        assert_eq!(fresh.network.as_deref(), Some("new"));
        assert_eq!(fresh.head, Some(head));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    thread_local! {
        /// Runs inside `resize_space`, between the unguarded grow and the store,
        /// standing in for the minutes `resize2fs` leaves that window open.
        static DURING_RESIZE_GROW: std::cell::RefCell<Option<Arc<dyn Fn()>>> =
            const { std::cell::RefCell::new(None) };
        /// Runs after a sweep snapshots identities and before host probes.
        /// Tests use it to commit a removal without timing sleeps.
        static DURING_SWEEP_PROBE: std::cell::RefCell<Option<Arc<dyn Fn()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn during_sweep_probe() {
        let hook = DURING_SWEEP_PROBE.with(|slot| slot.borrow().clone());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn with_sweep_probe_hook<T>(hook: Arc<dyn Fn()>, body: impl FnOnce() -> T) -> T {
        DURING_SWEEP_PROBE.with(|slot| *slot.borrow_mut() = Some(hook));
        let value = body();
        DURING_SWEEP_PROBE.with(|slot| *slot.borrow_mut() = None);
        value
    }

    pub(super) fn during_resize_grow() {
        let hook = DURING_RESIZE_GROW.with(|slot| slot.borrow().clone());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn with_resize_grow_hook<T>(hook: Arc<dyn Fn()>, body: impl FnOnce() -> T) -> T {
        DURING_RESIZE_GROW.with(|slot| *slot.borrow_mut() = Some(hook));
        let value = body();
        DURING_RESIZE_GROW.with(|slot| *slot.borrow_mut() = None);
        value
    }

    #[test]
    fn sweep_releases_state_locks_before_probes_and_skips_removed_spaces() {
        let root = test_root("sweep-lock-scope");
        let project = "project-a";
        let space_id = Uuid::new_v4();
        store_state(
            &root,
            &State {
                spaces: vec![Space {
                    id: space_id,
                    name: "swept".into(),
                    project: project.into(),
                    image: Image::Void,
                    parent: None,
                    head: None,
                    vcpus: None,
                    mem_mib: None,
                    disk_mib: None,
                    network: None,
                    expires_at: None,

                    created_at: Utc::now(),
                }],
                ckpts: Vec::new(),
                templates: Vec::new(),
            },
        );
        let db = Arc::new(test_db(&root));
        let registry = Arc::new(registry());
        let remove = {
            let db = Arc::clone(&db);
            let registry = Arc::clone(&registry);
            Arc::new(move || {
                super::update_state(&db, &registry, |state| {
                    state.spaces.retain(|space| space.id != space_id);
                    Ok(())
                })
                .expect("remove swept space during probe");
            }) as Arc<dyn Fn()>
        };
        let result =
            with_sweep_probe_hook(remove, || super::record_sweep_usage(&root, &db, &registry));
        assert!(
            result.is_ok(),
            "sweep failed after concurrent removal: {result:?}"
        );
        let connection = db.lock().expect("lock sweep database");
        let events: i64 = connection
            .query_row("SELECT COUNT(*) FROM usage_events", [], |row| row.get(0))
            .expect("count sweep events");
        assert_eq!(events, 0, "removed space must not receive stale samples");
        drop(connection);
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    /// The pre-check clears against the state as it was before the grow, so it
    /// cannot see an allocation another request commits while `resize2fs` runs.
    /// Committing a sibling's growth inside that window leaves only the
    /// re-check under the storing lock able to reject the resize, so this fails
    /// if the authoritative check is dropped and only the pre-check remains.
    #[test]
    fn resize_rechecks_quota_against_state_committed_during_the_grow() {
        let root = test_root("resize-recheck");
        let project = "project-a";
        let target = Uuid::new_v4();
        let sibling = Uuid::new_v4();
        let space = |id: Uuid, name: &str, disk_mib: u64| Space {
            id,
            name: name.to_owned(),
            project: project.to_owned(),
            image: shinu::Image::Void,
            vcpus: None,
            mem_mib: None,
            disk_mib: Some(disk_mib),
            network: None,
            expires_at: None,

            parent: None,
            head: None,
            created_at: Utc::now(),
        };
        store_state(
            &root,
            &State {
                spaces: vec![space(target, "target", 10), space(sibling, "sibling", 10)],
                ckpts: Vec::new(),
                templates: Vec::new(),
            },
        );
        // Sized at the request already, so resize_disk_image is skipped and the
        // test needs no e2fsck or resize2fs on the host.
        for id in [target, sibling] {
            let image = shinu::space_image(&root, id);
            std::fs::create_dir_all(image.parent().expect("image parent"))
                .expect("create image directory");
            std::fs::File::create(&image)
                .expect("create image")
                .set_len(30 * 1024 * 1024)
                .expect("size image");
        }
        let (vm_cfg, net_cfg) = test_configs();
        let registry = Arc::new(registry());
        let db = Arc::new(test_db(&root));
        // 20 MiB declared, 50 MiB cap: growing target to 30 passes the pre-check
        // against 10+10, but 30+30 exceeds the cap once the sibling commits.
        let limits = Limits {
            max_spaces: 5,
            max_disk_mib: 50,
            max_vcpus: 16,
            max_mem_mib: 262_144,
            max_running: 2,
            api_per_min: 120,
        };
        let rate = RateLimiter::new();
        let register_rate = super::RegistrationLimiter::new();
        let ctx = super::Ctx {
            root: &root,
            db: &db,
            vm_cfg: &vm_cfg,
            net_cfg: &net_cfg,
            limits: &limits,
            rate: &rate,
            register_rate: &register_rate,
            registry: &registry,
            admin_token: None,
        };
        // Committed only after resize_space has already cleared its pre-check.
        let grow_sibling = {
            let db = Arc::clone(&db);
            let registry = Arc::clone(&registry);
            Arc::new(move || {
                super::update_state(&db, &registry, |state| {
                    let entry = state
                        .spaces
                        .iter_mut()
                        .find(|entry| entry.id == sibling)
                        .expect("sibling present");
                    entry.disk_mib = Some(30);
                    Ok(())
                })
                .expect("commit sibling growth inside the grow window");
            }) as Arc<dyn Fn()>
        };
        let result = with_resize_grow_hook(grow_sibling, || {
            handle(
                &ctx,
                Req::Resize {
                    space: "target".into(),
                    vcpus: None,
                    mem_mib: None,
                    disk_mib: Some(Some(30)),
                },
                project,
            )
        });
        assert!(
            matches!(result, Err(shinu::Error::Quota(_))),
            "resize must be rejected once the sibling's allocation is visible, got {result:?}"
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    /// AGENTS.md invariant 8: the record is claimed under the state lock before
    /// any file is unlinked. A failure partway through the deletes must
    /// therefore leave an orphaned file for gc, never a surviving record whose
    /// image is already gone — that state needs the user to retry `rm`, and
    /// meanwhile the space looks present but cannot boot.
    #[test]
    fn remove_space_claims_the_record_before_unlinking_files() {
        let root = test_root("rm-claim");
        let project = "project-a";
        let id = Uuid::new_v4();
        store_state(
            &root,
            &State {
                spaces: vec![Space {
                    id,
                    name: "doomed".into(),
                    project: project.to_owned(),
                    image: shinu::Image::Void,
                    vcpus: None,
                    mem_mib: None,
                    disk_mib: Some(10),
                    network: None,
                    expires_at: None,

                    parent: None,
                    head: None,
                    created_at: Utc::now(),
                }],
                ckpts: Vec::new(),
                templates: Vec::new(),
            },
        );
        let image = shinu::space_image(&root, id);
        std::fs::create_dir_all(image.parent().expect("image parent"))
            .expect("create image directory");
        std::fs::write(&image, b"disk").expect("create image");
        // The snapshot path is a non-empty directory, so remove_file returns
        // EISDIR and the delete phase fails after the record was claimed. A
        // permission trick would not do: these tests run as root.
        let blocked = super::space_snapshot_mem(&root, id);
        std::fs::create_dir_all(blocked.join("occupied")).expect("block snapshot path");

        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::Rm {
                space: "doomed".into(),
            },
            project,
        );

        assert!(
            result.is_err(),
            "the delete phase must fail, got {result:?}"
        );
        let state = super::snapshot(&db, &registry).expect("read state after failed rm");
        assert!(
            state.spaces.iter().all(|space| space.id != id),
            "the record must stay claimed after a failed delete, leaving only an orphan for gc"
        );

        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn checkout_rejects_running_space() {
        let root = test_root("checkout-running");
        let project = "project-a";
        let (_space_id, ckpt_id, mut child) = running_state(&root, project);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::Checkout {
                space: "running".into(),
                commit: ckpt_id,
            },
            project,
        );
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("running")
        ));
        child.kill().expect("stop fake firecracker");
        child.wait().expect("wait fake firecracker");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn rejects_checkpoint_deletion_while_referenced() {
        let root = test_root("rmckpt-referenced");
        let project = "project-a";
        let checkpoint_id = Uuid::new_v4();
        let child_id = Uuid::new_v4();
        let state = State {
            spaces: vec![Space {
                id: child_id,
                name: "child-space".into(),
                project: project.into(),
                image: Image::Void,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: None,
                expires_at: None,

                parent: Some(checkpoint_id),
                head: None,
                created_at: Utc::now(),
            }],
            ckpts: vec![Ckpt {
                id: checkpoint_id,
                space: child_id,
                project: project.into(),
                parent: None,
                auto: false,
                full: false,
                base: None,
                note: "base".into(),
                created_at: Utc::now(),
                snapshot_version: None,
            }],
            templates: Vec::new(),
        };
        store_state(&root, &state);
        std::fs::create_dir_all(root.join("ckpts")).expect("create checkpoint directory");
        std::fs::write(shinu::ckpt_image(&root, checkpoint_id), b"checkpoint")
            .expect("write checkpoint image");
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::RmCkpt {
                ckpt: checkpoint_id,
            },
            project,
        );
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("child-space")
        ));
        assert!(shinu::ckpt_image(&root, checkpoint_id).exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn checkpoint_deletion_hides_foreign_project() {
        let root = test_root("rmckpt-project");
        let checkpoint_id = Uuid::new_v4();
        let state = State {
            spaces: Vec::new(),
            ckpts: vec![Ckpt {
                id: checkpoint_id,
                space: Uuid::new_v4(),
                project: "project-b".into(),
                parent: None,
                auto: false,
                full: false,
                base: None,
                note: "private".into(),
                created_at: Utc::now(),
                snapshot_version: None,
            }],
            templates: Vec::new(),
        };
        store_state(&root, &state);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::RmCkpt {
                ckpt: checkpoint_id,
            },
            "project-a",
        );
        assert!(matches!(
            result,
            Err(shinu::Error::NotFound(message)) if message.contains(&checkpoint_id.to_string())
        ));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn cold_commit_rejects_running_space() {
        let root = test_root("cold-running");
        let project = "project-a";
        let (_space_id, _ckpt_id, mut child) = running_state(&root, project);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::Commit {
                space: "running".into(),
                note: "cold".into(),
                hot: false,
                snapshot: SnapshotMode::None,
            },
            project,
        );
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("stop the space")
        ));
        child.kill().expect("stop fake firecracker");
        child.wait().expect("wait fake firecracker");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn commit_parent_chain_and_head_are_dag_ordered() {
        let space_id = Uuid::new_v4();
        let project = "project-a";
        let mut state = State {
            spaces: vec![Space {
                id: space_id,
                name: "web".into(),
                project: project.into(),
                image: Image::Void,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: None,
                expires_at: None,

                parent: None,
                head: None,
                created_at: Utc::now(),
            }],
            ckpts: Vec::new(),
            templates: Vec::new(),
        };
        let first = append_checkpoint(
            &mut state,
            space_id,
            project,
            Uuid::new_v4(),
            "first".into(),
            CkptFlags {
                auto: false,
                full: false,
                base: None,
                update_head: true,
            },
        )
        .expect("first checkpoint");
        let second = append_checkpoint(
            &mut state,
            space_id,
            project,
            Uuid::new_v4(),
            "second".into(),
            CkptFlags {
                auto: false,
                full: false,
                base: None,
                update_head: true,
            },
        )
        .expect("second checkpoint");
        assert_eq!(second.parent, Some(first.id));
        assert_eq!(state.spaces[0].head, Some(second.id));
        let log = shinu::log_chain(&state, &state.spaces[0]);
        assert_eq!(
            log.iter()
                .map(|checkpoint| checkpoint.id)
                .collect::<Vec<_>>(),
            vec![second.id, first.id]
        );
    }

    #[test]
    fn checkout_records_reflog_before_moving_head() {
        let space_id = Uuid::new_v4();
        let project = "project-a";
        let target_id = Uuid::new_v4();
        let mut state = State {
            spaces: vec![Space {
                id: space_id,
                name: "web".into(),
                project: project.into(),
                image: Image::Void,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: None,
                expires_at: None,

                parent: None,
                head: Some(target_id),
                created_at: Utc::now(),
            }],
            ckpts: vec![Ckpt {
                id: target_id,
                space: space_id,
                project: project.into(),
                parent: None,
                auto: false,
                full: false,
                base: None,
                note: "target".into(),
                created_at: Utc::now(),
                snapshot_version: None,
            }],
            templates: Vec::new(),
        };
        let auto = append_checkpoint(
            &mut state,
            space_id,
            project,
            Uuid::new_v4(),
            format!("auto before checkout {}", &target_id.to_string()[..8]),
            CkptFlags {
                auto: true,
                full: false,
                base: None,
                update_head: false,
            },
        )
        .expect("automatic checkpoint");
        set_head(&mut state, space_id, project, target_id).expect("checkout head");
        assert!(auto.auto);
        assert_eq!(auto.parent, Some(target_id));
        assert_eq!(state.spaces[0].head, Some(target_id));
        assert_eq!(state.ckpts.len(), 2);
    }

    #[test]
    fn reflog_finds_auto_commit_left_behind_by_checkout() {
        let root = test_root("reflog");
        let project = "project-a";
        let space_id = Uuid::new_v4();
        let old_id = Uuid::new_v4();
        let auto_id = Uuid::new_v4();
        let state = State {
            spaces: vec![Space {
                id: space_id,
                name: "web".into(),
                project: project.into(),
                image: Image::Void,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: None,
                expires_at: None,

                parent: None,
                head: Some(old_id),
                created_at: Utc::now(),
            }],
            ckpts: vec![
                Ckpt {
                    id: old_id,
                    space: space_id,
                    project: project.into(),
                    parent: None,
                    auto: false,
                    full: false,
                    base: None,
                    note: "before checkout".into(),
                    created_at: Utc::now(),
                    snapshot_version: None,
                },
                Ckpt {
                    id: auto_id,
                    space: space_id,
                    project: project.into(),
                    parent: Some(old_id),
                    auto: true,
                    full: false,
                    base: None,
                    note: "auto before checkout".into(),
                    created_at: Utc::now(),
                    snapshot_version: None,
                },
            ],
            templates: Vec::new(),
        };
        store_state(&root, &state);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);

        let reflog = handle(
            &ctx,
            Req::Reflog {
                space: "web".into(),
            },
            project,
        )
        .expect("read reflog");
        let log = handle(
            &ctx,
            Req::Log {
                space: "web".into(),
            },
            project,
        )
        .expect("read log");
        let entries = reflog["entries"].as_array().expect("reflog entries");
        let auto_id_text = auto_id.to_string();
        assert_eq!(entries.len(), 2);
        assert_eq!(log["commits"].as_array().unwrap().len(), 1);
        assert!(entries.iter().any(|entry| {
            entry["id"].as_str() == Some(auto_id_text.as_str())
                && entry["auto"].as_bool().unwrap_or(false)
        }));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    /// `gc` computes its candidate list from a snapshot taken without the state
    /// lock, so a fork or commit can start referencing a candidate before the
    /// deletion commits. The claim step must re-check `is_referenced` against
    /// the authoritative state and skip anything that gained a reference, or a
    /// space is left pointing at a commit whose image has been unlinked.
    #[test]
    fn gc_claim_skips_a_commit_that_gained_a_reference() {
        let project = "project-a";
        let space_id = Uuid::new_v4();
        let stale_id = Uuid::new_v4();
        let raced_id = Uuid::new_v4();
        let mut state = State {
            spaces: vec![Space {
                id: space_id,
                name: "web".into(),
                project: project.into(),
                image: Image::Void,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                network: None,
                expires_at: None,

                parent: None,
                // The racing fork landed between the snapshot and the claim.
                head: Some(raced_id),
                created_at: Utc::now(),
            }],
            ckpts: vec![
                Ckpt {
                    id: stale_id,
                    space: space_id,
                    project: project.into(),
                    parent: None,
                    auto: true,
                    full: false,
                    base: None,
                    note: "auto stale".into(),
                    created_at: Utc::now(),
                    snapshot_version: None,
                },
                Ckpt {
                    id: raced_id,
                    space: space_id,
                    project: project.into(),
                    parent: None,
                    auto: true,
                    full: false,
                    base: None,
                    note: "auto raced".into(),
                    created_at: Utc::now(),
                    snapshot_version: None,
                },
            ],
            templates: Vec::new(),
        };
        // Both looked collectable when the snapshot was taken.
        let candidates = [stale_id, raced_id];
        let mut claimed = Vec::new();
        for id in candidates {
            let present = state
                .ckpts
                .iter()
                .any(|checkpoint| checkpoint.id == id && checkpoint.project == project);
            if !present || !shinu::is_referenced(&state, id).is_empty() {
                continue;
            }
            state.ckpts.retain(|checkpoint| checkpoint.id != id);
            claimed.push(id);
        }
        assert_eq!(
            claimed,
            vec![stale_id],
            "raced commit must survive the claim"
        );
        assert!(
            state
                .ckpts
                .iter()
                .any(|checkpoint| checkpoint.id == raced_id),
            "raced commit must stay in the state so its image is never unlinked"
        );
        assert_eq!(state.spaces[0].head, Some(raced_id));
    }
    fn console_db() -> Mutex<Connection> {
        let connection = Connection::open_in_memory().expect("open in-memory console database");
        connection
            .execute_batch(
                "
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE memberships (
                    user_id TEXT NOT NULL,
                    project TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, project)
                );
                CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE projects (
                    project TEXT PRIMARY KEY,
                    max_spaces INTEGER,
                    max_disk_mib INTEGER,
                    max_running INTEGER,
                    api_per_min INTEGER
                );
                ",
            )
            .expect("create console schema");
        Mutex::new(connection)
    }

    fn console_ctx<'a>(
        root: &'a std::path::Path,
        db: &'a Mutex<Connection>,
        registry: &'a shinu::registry::Registry,
    ) -> super::Ctx<'a> {
        static VM_CONFIG: LazyLock<VmConfig> = LazyLock::new(|| VmConfig {
            vcpus: 1,
            mem_mib: 1,
            idle_secs: 1,
            jail_uid: 30000,
            jail_gid: 30000,
        });
        static NET_CONFIG: LazyLock<NetConfig> = LazyLock::new(|| NetConfig {
            enabled: false,
            base: [172, 31],
            allow: Vec::new(),
            host_allow: Vec::new(),
            uplink: String::new(),
        });
        super::Ctx {
            root,
            db,
            vm_cfg: &VM_CONFIG,
            net_cfg: &NET_CONFIG,
            limits: test_limits(),
            rate: test_rate(),
            register_rate: test_register_rate(),
            registry,
            admin_token: None,
        }
    }

    fn console_request(origin: Option<&str>, host: Option<&str>) -> shinu::http::Request {
        shinu::http::Request {
            method: "POST".into(),
            path: "/v1/spaces".into(),
            token: None,
            authorization_present: false,
            body: br"{}".to_vec(),
            cookies: HashMap::new(),
            origin: origin.map(str::to_owned),
            forwarded_proto: None,
            host: host.map(str::to_owned),
        }
    }
    fn serve_raw(ctx: &super::Ctx<'_>, raw_request: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind route test listener");
        let address = listener.local_addr().expect("route test address");
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accept route test request");
                super::serve_connection(stream, ctx).expect("serve route test request");
            });
            let mut client = TcpStream::connect(address).expect("connect route test listener");
            client
                .write_all(raw_request.as_bytes())
                .expect("write route test request");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("read route test response");
            server.join().expect("join route test server");
            response
        })
    }
    #[test]
    fn error_responses_hide_server_details_but_preserve_client_details() {
        let infrastructure =
            shinu::Error::Internal("sql: no such column host_cidr in /srv/shinu/shinu.db".into());
        let mut server_response = Vec::new();
        super::respond_error(&mut server_response, 500, &infrastructure)
            .expect("write server error response");
        let server_response = String::from_utf8(server_response).expect("UTF-8 server response");
        assert!(server_response.starts_with("HTTP/1.1 500"));
        assert!(!server_response.contains("host_cidr"));
        assert!(server_response.contains("\"error\":\"internal server error\""));

        let client_error = shinu::Error::NotFound("missing-space".into());
        let mut client_response = Vec::new();
        super::respond_error(&mut client_response, 404, &client_error)
            .expect("write client error response");
        let client_response = String::from_utf8(client_response).expect("UTF-8 client response");
        assert!(client_response.starts_with("HTTP/1.1 404"));
        assert!(client_response.contains("missing-space"));
    }

    #[test]
    fn console_register_then_login_creates_sessions() {
        let root = test_root("console-register-login");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let email = format!("user-{}@example.com", Uuid::new_v4());
        let body = format!("{{\"email\":\"{email}\",\"password\":\"correct horse\"}}");
        let (registered, register_cookie) =
            super::register_console(&ctx, body.as_bytes(), &Uuid::new_v4().to_string(), false)
                .expect("register user");
        assert!(registered["project"].as_str().is_some());
        assert!(register_cookie.contains("shinu_session="));

        let (logged_in, login_cookie) =
            super::login_console(&ctx, body.as_bytes(), false).expect("login user");
        assert_eq!(logged_in["user_id"], registered["user_id"]);
        assert!(login_cookie.contains("shinu_session="));
        assert!(
            state::find_user_by_email(&super::lock_db(&db), &email)
                .expect("find registered user")
                .is_some()
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn console_login_hides_unknown_email_and_wrong_password() {
        let root = test_root("console-login-errors");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let email = format!("user-{}@example.com", Uuid::new_v4());
        let registered = format!("{{\"email\":\"{email}\",\"password\":\"correct horse\"}}");
        super::register_console(
            &ctx,
            registered.as_bytes(),
            &Uuid::new_v4().to_string(),
            false,
        )
        .expect("register user");
        let wrong = format!("{{\"email\":\"{email}\",\"password\":\"wrong secret\"}}");
        let unknown = format!(
            "{{\"email\":\"unknown-{}@example.com\",\"password\":\"wrong secret\"}}",
            Uuid::new_v4()
        );
        let wrong_message = match super::login_console(&ctx, wrong.as_bytes(), false) {
            Err(shinu::Error::Auth(message)) => message,
            result => panic!("wrong password unexpectedly succeeded: {result:?}"),
        };
        let unknown_message = match super::login_console(&ctx, unknown.as_bytes(), false) {
            Err(shinu::Error::Auth(message)) => message,
            result => panic!("unknown email unexpectedly succeeded: {result:?}"),
        };
        assert_eq!(wrong_message, unknown_message);
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn console_registration_rejects_short_password() {
        let root = test_root("console-short-password");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let body = format!(
            "{{\"email\":\"short-{}@example.com\",\"password\":\"too short\"}}",
            Uuid::new_v4()
        );
        let result =
            super::register_console(&ctx, body.as_bytes(), &Uuid::new_v4().to_string(), false);
        assert!(matches!(
            result,
            Err(shinu::Error::Invalid(message)) if message.contains("12 characters")
        ));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn csrf_rejects_console_origin_mismatch_but_api_has_no_check() {
        let request = console_request(Some("https://evil.example"), Some("console.example"));
        assert!(super::check_console_csrf(&request).is_err());
        let api = super::Caller::Api {
            project: "project-a".into(),
        };
        let api_result = match api {
            super::Caller::Api { .. } => Ok::<(), shinu::Error>(()),
            super::Caller::Console { .. } => super::check_console_csrf(&request),
        };
        assert!(api_result.is_ok());
    }

    #[test]
    fn malformed_authorization_never_falls_back_to_session_cookie() {
        let root = test_root("mixed-auth");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let email = format!("mixed-auth-{}@example.com", Uuid::new_v4());
        let (user_id, _) =
            state::create_user(&super::lock_db(&db), &email, super::DUMMY_PASSWORD_HASH)
                .expect("create mixed-auth user");
        let session = format!("session-{}", Uuid::new_v4());
        let session_hash = shinu::sha256_hex(session.as_bytes());
        state::create_session(&super::lock_db(&db), &session_hash, &user_id, 7)
            .expect("create mixed-auth session");

        let mut request = console_request(None, Some("console.example"));
        request
            .cookies
            .insert(super::SESSION_COOKIE.into(), session);
        assert!(matches!(
            super::authenticate(&ctx, &request),
            Ok(super::Caller::Console { .. })
        ));
        request.authorization_present = true;
        assert!(matches!(
            super::authenticate(&ctx, &request),
            Err(shinu::Error::Auth(message)) if message == "invalid token"
        ));
        assert!(super::authenticate_optional(&ctx, &request).is_none());
        std::fs::remove_dir_all(root).expect("remove mixed-auth root");
    }

    #[test]
    fn expired_console_session_is_rejected() {
        let root = test_root("console-expired-session");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let email = format!("expired-{}@example.com", Uuid::new_v4());
        let (user_id, _) =
            state::create_user(&super::lock_db(&db), &email, super::DUMMY_PASSWORD_HASH)
                .expect("create expired-session user");
        let token = format!("expired-{}", Uuid::new_v4());
        let token_hash = shinu::sha256_hex(token.as_bytes());
        state::create_session(&super::lock_db(&db), &token_hash, &user_id, -1)
            .expect("create expired session");
        let mut request = console_request(None, Some("console.example"));
        request.method = "GET".into();
        request.path = "/console/me".into();
        request.cookies.insert(super::SESSION_COOKIE.into(), token);
        assert!(matches!(
            super::authenticate(&ctx, &request),
            Err(shinu::Error::Auth(message)) if message.contains("expired")
        ));
        std::fs::remove_dir_all(root).expect("remove test root");
    }
    #[test]
    fn csrf_rejects_missing_origin_for_login() {
        let mut request = console_request(None, Some("console.example"));
        request.path = "/console/login".into();
        assert!(super::check_console_csrf(&request).is_err());
    }

    #[test]
    fn registration_limiter_rejects_the_sixth_request_in_an_hour() {
        let limiter = super::RegistrationLimiter::new();
        for _ in 0..5 {
            limiter.check("198.51.100.20").expect("within hourly limit");
        }
        assert!(matches!(
            limiter.check("198.51.100.20"),
            Err(shinu::Error::Quota(message)) if message.contains("5 registrations per hour")
        ));
    }
    #[test]
    fn login_route_rejects_missing_origin_before_authentication() {
        let root = test_root("console-route-csrf");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let response = serve_raw(
            &ctx,
            "POST /console/login HTTP/1.1\r\nHost: console.example\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn streaming_cleanup_joins_output_readers() {
        let mut child = Command::new("printf")
            .arg("output")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cleanup test child");
        let stdout = child.stdout.take().expect("cleanup test stdout");
        let stderr = child.stderr.take().expect("cleanup test stderr");
        let stdout_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stderr_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stdout_done_reader = Arc::clone(&stdout_done);
        let stderr_done_reader = Arc::clone(&stderr_done);
        let stdout_reader = thread::spawn(move || {
            let mut stdout = stdout;
            let mut output = Vec::new();
            let _ = stdout.read_to_end(&mut output);
            stdout_done_reader.store(true, std::sync::atomic::Ordering::Release);
        });
        let stderr_reader = thread::spawn(move || {
            let mut stderr = stderr;
            let mut output = Vec::new();
            let _ = stderr.read_to_end(&mut output);
            stderr_done_reader.store(true, std::sync::atomic::Ordering::Release);
        });
        let mut cleanup = super::StreamingChildCleanup::new(child);
        cleanup.set_readers(stdout_reader, stderr_reader);
        drop(cleanup);
        assert!(stdout_done.load(std::sync::atomic::Ordering::Acquire));
        assert!(stderr_done.load(std::sync::atomic::Ordering::Acquire));
    }

    /// Guest output is arbitrary bytes, and a line-oriented UTF-8 read used to
    /// treat the first invalid byte as end-of-stream: everything printed after
    /// it vanished while the exit status still reported success, so a caller
    /// saw a silently truncated response.
    #[test]
    fn output_after_invalid_utf8_still_reaches_the_client() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let payload: &[u8] = b"before\n\xff\xfe\nafter\n";
        read_stream("stdout", std::io::Cursor::new(payload), sender)
            .join()
            .expect("reader thread");
        let lines: Vec<String> = receiver.iter().map(|line| line.data).collect();
        assert_eq!(lines.len(), 3, "lines: {lines:?}");
        assert_eq!(lines[0], "before\n");
        assert_eq!(lines[2], "after\n");
    }
}
