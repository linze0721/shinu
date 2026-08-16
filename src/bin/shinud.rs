use chrono::Utc;
use clap::Parser;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

use rusqlite::Connection;
use shinu::{
    http,
    proto::Req,
    quota::{self, Limits, RateLimiter},
    registry::Registry,
    state::{self, Ckpt, Space, State},
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
const DUMMY_PASSWORD_HASH: &str =
    "pbkdf2$210000$0000000000000000000000000000000000000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000";



#[derive(Parser)]
#[command(name = "shinud")]
struct Cli {
    #[arg(long)]
    root: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let root = shinu::resolve_root(cli.root.as_deref());
    shinu::init_layout(&root)?;
    let connection = state::open(&root)?;
    if state::migrate_from_json(&root, &connection)? {
        eprintln!("imported state.json into shinu.db (renamed to state.json.migrated)");
    }
    // Fetch VM assets first: a host without network must fail before spending
    // minutes building an image it could never boot.
    shinu::ensure_assets(&root)?;
    shinu::ensure_base(&root, &shinu::BaseConfig::from_env()?)?;
    // A base built before egress filtering existed carries the host's private
    // resolver, which the guest firewall now blocks; that silently breaks
    // package installation inside every new VM. Repair is best effort because a
    // busy or damaged base is an operator problem, not a reason to refuse
    // service.
    match shinu::repair_base_resolv(&root) {
        Ok(true) => eprintln!("rewrote base.ext4 resolv.conf to a reachable resolver"),
        Ok(false) => {}
        Err(error) => eprintln!("base resolv repair: {error}"),
    }
    let vm_cfg = shinu::VmConfig::from_env();
    let net_cfg = shinu::NetConfig::from_env()?;
    let limits = Limits::from_env();
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
    let registry = Arc::new(Registry::new());

    let sweep_root = Arc::clone(&root);
    let sweep_vm_cfg = Arc::clone(&vm_cfg);
    let sweep_net_cfg = Arc::clone(&net_cfg);
    let sweep_db = Arc::clone(&db);
    let sweep_registry = Arc::clone(&registry);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        match shinu::vm::sweep_idle(
            sweep_root.as_path(),
            sweep_vm_cfg.idle_secs,
            sweep_net_cfg.as_ref(),
        ) {
            Ok(stopped) => {
                for dir in stopped {
                    eprintln!("idle sweep stopped {}", dir.display());
                }
            }
            Err(error) => eprintln!("idle sweep: {error}"),
        }
        if let Err(error) = record_sweep_usage(
            sweep_root.as_path(),
            &sweep_db,
            &sweep_registry,
        ) {
            eprintln!("usage sweep: {error}");
        }
        match state::purge_expired_sessions(&lock_db(&sweep_db)) {
            Ok(removed) if removed > 0 => {
                eprintln!("session sweep removed {removed} expired sessions");
            }
            Ok(_) => {}
            Err(error) => eprintln!("session sweep: {error}"),
        }
    });

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let connection_root = Arc::clone(&root);
                let connection_db = Arc::clone(&db);
                let connection_vm_cfg = Arc::clone(&vm_cfg);
                let connection_net_cfg = Arc::clone(&net_cfg);
                let connection_limits = Arc::clone(&limits);
                let connection_rate = Arc::clone(&rate);
                let connection_register_rate = Arc::clone(&register_rate);
                let connection_registry = Arc::clone(&registry);
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
        const WINDOW: Duration = Duration::from_secs(60 * 60);
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
        let mut timestamps = requests.remove(ip).unwrap_or_default();
        if timestamps.len() >= REGISTER_REQUESTS_PER_HOUR {
            requests.insert(ip.to_owned(), timestamps);
            return Err(shinu::Error::Quota(
                "registration rate limit exceeded: 5 registrations per hour".into(),
            ));
        }
        timestamps.push_back(now);
        requests.insert(ip.to_owned(), timestamps);
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

fn current_disk_mib(root: &Path, state: &State, project: &str) -> u64 {
    state
        .spaces
        .iter()
        .filter(|space| space.project == project)
        .map(|space| {
            shinu::btrfs::exclusive(&shinu::space_image(root, space.id))
                .unwrap_or(0)
                .saturating_add(1024 * 1024 - 1)
                / (1024 * 1024)
        })
        .sum()
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
    let disk_mib = current_disk_mib(root, &state, project);
    // Capacity quota is an instantaneous btrfs measurement. It is deliberately
    // separate from usage_events.disk_mib_hour, which is a billing time series.
    quota::check_disk_limit(disk_mib, adding_mib, limits)
}

fn effective_limits(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Limits> {
    let connection = lock_db(ctx.db);
    match state::project_limits(&connection, project)? {
        Some((max_spaces, max_disk_mib, max_running, api_per_min)) => Ok(Limits {
            max_spaces,
            max_disk_mib,
            max_running,
            api_per_min,
        }),
        None => Ok(Limits {
            max_spaces: ctx.limits.max_spaces,
            max_disk_mib: ctx.limits.max_disk_mib,
            max_running: ctx.limits.max_running,
            api_per_min: ctx.limits.api_per_min,
        }),
    }
}

fn count_running(root: &Path, state: &State, project: &str) -> u32 {
    state
        .spaces
        .iter()
        .filter(|space| {
            space.project == project && shinu::vm::is_running(&shinu::vm_dir(root, space.id))
        })
        .count() as u32
}

fn record_sweep_usage(
    root: &Path,
    db: &Mutex<Connection>,
    registry: &Registry,
) -> shinu::Result<()> {
    let _state_guard = lock_state(registry);
    let connection = lock_db(db);
    let state = state::load(&connection)?;
    for space in &state.spaces {
        let image = shinu::space_image(root, space.id);
        let disk_mib = shinu::btrfs::exclusive(&image)
            .unwrap_or(0)
            .saturating_add(1024 * 1024 - 1)
            / (1024 * 1024);
        // `disk_mib_hour` stores one MiB snapshot per sweep, not a duration;
        // later pricing can multiply the sum by the 30-second sample period.
        state::record_usage(
            &connection,
            &space.project,
            "disk_mib_hour",
            Some(space.id),
            i64::try_from(disk_mib).unwrap_or(i64::MAX),
        )?;
        if shinu::vm::is_running(&shinu::vm_dir(root, space.id)) {
            state::record_usage(
                &connection,
                &space.project,
                "vm_seconds",
                Some(space.id),
                30,
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

fn append_checkpoint(
    state: &mut State,
    space_id: Uuid,
    project: &str,
    id: Uuid,
    note: String,
    auto: bool,
    update_head: bool,
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
        auto,
        note,
        created_at: Utc::now(),
    };
    state.ckpts.push(checkpoint.clone());
    if update_head {
        state.spaces[space_index].head = Some(id);
    }
    Ok(checkpoint)
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

fn bytes_to_mib(bytes: u64) -> u64 {
    bytes.saturating_add(1024 * 1024 - 1) / (1024 * 1024)
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

fn find_checkpoint(db: &Mutex<Connection>, id: Uuid, project: &str) -> shinu::Result<Ckpt> {
    state::find_ckpt(&lock_db(db), id, project)?
        .ok_or_else(|| shinu::Error::NotFound(id.to_string()))
}

fn create_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
    let limits = effective_limits(ctx, project)?;
    {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        check_space_quota(ctx.root, &connection, project, &limits, 0)?;
    }
    let id = Uuid::new_v4();
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let image = shinu::space_image(ctx.root, id);
    shinu::btrfs::clone_for(&shinu::base_path(ctx.root), &image, 0, 0)?;
    let mount = ctx.root.join(format!("authorize.{id}.mnt"));
    let result = (|| -> shinu::Result<Value> {
        let public_key = shinu::vm::prepare(&shinu::vm_dir(ctx.root, id), 0, 0)?;
        // Each image gets its own key: the base is the common ancestor of every
        // space, so a key baked into it would be shared by all spaces.
        shinu::vm::authorize(&image, &public_key, &mount)?;
        let adding_mib = bytes_to_mib(shinu::btrfs::exclusive(&image).unwrap_or(0));
        let space = update_state_with_quota(
            ctx.root,
            ctx.db,
            ctx.registry,
            project,
            &limits,
            adding_mib,
            |state| {
                check_name(state, &name, project)?;
                let space = Space {
                    id,
                    name: name.clone(),
                    project: project.to_owned(),
                    parent: None,
                    head: None,
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
        let _ = std::fs::remove_file(&image);
        let _ = std::fs::remove_dir_all(shinu::vm_dir(ctx.root, id));
        let _ = std::fs::remove_dir_all(&mount);
    }
    result
}

fn fork_space(
    ctx: &Ctx<'_>,
    project: &str,
    ckpt: Uuid,
    name: String,
) -> shinu::Result<Value> {
    let limits = effective_limits(ctx, project)?;
    let source = {
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        check_space_quota(ctx.root, &connection, project, &limits, 0)?;
        state::find_ckpt(&connection, ckpt, project)?
            .ok_or_else(|| shinu::Error::NotFound(ckpt.to_string()))?
            .id
    };
    let id = Uuid::new_v4();
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let image = shinu::space_image(ctx.root, id);
    shinu::btrfs::clone_for(&shinu::ckpt_image(ctx.root, source), &image, 0, 0)?;
    let mount = ctx.root.join(format!("authorize.{id}.mnt"));
    let result = (|| -> shinu::Result<Value> {
        let public_key = shinu::vm::prepare(&shinu::vm_dir(ctx.root, id), 0, 0)?;
        // A fork gets a distinct VM key because it is an independent space even
        // though its first filesystem state is shared by reflink.
        shinu::vm::authorize(&image, &public_key, &mount)?;
        let adding_mib = bytes_to_mib(shinu::btrfs::exclusive(&image).unwrap_or(0));
        let space = update_state_with_quota(
            ctx.root,
            ctx.db,
            ctx.registry,
            project,
            &limits,
            adding_mib,
            |state| {
                check_name(state, &name, project)?;
                shinu::find_ckpt(state, source, project)?;
                let space = Space {
                    id,
                    name: name.clone(),
                    project: project.to_owned(),
                    parent: Some(source),
                    head: Some(source),
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
        let _ = std::fs::remove_file(&image);
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
    let running = shinu::vm::is_running(&vm_dir);
    if running && !hot {
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
    let image = shinu::ckpt_image(ctx.root, id);
    shinu::btrfs::clone_for(&shinu::space_image(ctx.root, space_id), &image, 0, 0)?;
    let result = update_state(ctx.db, ctx.registry, |state| {
        let checkpoint = append_checkpoint(state, space_id, project, id, note, false, true)?;
        Ok(serde_json::to_value(checkpoint)?)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(image);
    }
    result
}

fn checkout_space(
    ctx: &Ctx<'_>,
    project: &str,
    space: String,
    commit: Uuid,
) -> shinu::Result<Value> {
    let (space_id, space_name) = {
        let entry = find_space(ctx.db, &space, project)?;
        (entry.id, entry.name)
    };
    let space_guard = ctx.registry.space_lock(space_id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (target, current_head) = {
        let _state_guard = lock_state(ctx.registry);
        let entry = find_space(ctx.db, &space_name, project)?;
        let vm_dir = shinu::vm_dir(ctx.root, entry.id);
        if shinu::vm::is_running(&vm_dir) {
            return Err(shinu::Error::Invalid(format!(
                "stop the space before checking it out: {space_name}"
            )));
        }
        let target = find_checkpoint(ctx.db, commit, project)?;
        (target, entry.head)
    };

    let auto_id = Uuid::new_v4();
    let auto_image = shinu::ckpt_image(ctx.root, auto_id);
    shinu::btrfs::clone_for(
        &shinu::space_image(ctx.root, space_id),
        &auto_image,
        0,
        0,
    )?;
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
            note: auto_note.clone(),
            created_at: Utc::now(),
        };
        state.ckpts.push(checkpoint.clone());
        Ok(checkpoint)
    })?;

    // Keep the VM directory and keypair: changing that identity would invalidate
    // credentials already used by the daemon to reach this space.
    let vm_dir = shinu::vm_dir(ctx.root, space_id);
    let public_key = std::fs::read_to_string(shinu::vm::key_path(&vm_dir).with_extension("pub"))?;
    let image = shinu::space_image(ctx.root, space_id);
    shinu::btrfs::clone_for(&shinu::ckpt_image(ctx.root, target.id), &image, 0, 0)?;
    let mount = ctx.root.join(format!("authorize.checkout.{space_id}.mnt"));
    shinu::vm::authorize(&image, &public_key, &mount)?;
    update_state(ctx.db, ctx.registry, |state| {
        shinu::find_ckpt(state, target.id, project)?;
        set_head(state, space_id, project, target.id)?;
        Ok(())
    })?;
    Ok(json!({ "head": target.id, "auto_commit": auto_checkpoint.id }))
}

fn remove_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
    let (id, resolved_name) = {
        let entry = find_space(ctx.db, &name, project)?;
        (entry.id, entry.name)
    };
    let space_guard = ctx.registry.space_lock(id);
    let _space_guard = space_guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    shinu::vm::stop(&shinu::vm_dir(ctx.root, id), ctx.net_cfg)?;
    let image = shinu::space_image(ctx.root, id);
    match std::fs::remove_file(&image) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match std::fs::remove_dir_all(shinu::vm_dir(ctx.root, id)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    update_state(ctx.db, ctx.registry, |state| {
        state.spaces.retain(|space| space.id != id);
        Ok(())
    })?;
    Ok(json!({ "removed": resolved_name, "id": id }))
}
fn remove_checkpoint(ctx: &Ctx<'_>, project: &str, id: Uuid) -> shinu::Result<Value> {
    let checkpoint = find_checkpoint(ctx.db, id, project)?;
    let state = snapshot(ctx.db, ctx.registry)?;
    let referenced = shinu::is_referenced(&state, checkpoint.id);
    if !referenced.is_empty() {
        return Err(shinu::Error::Invalid(format!(
            "checkpoint {id} is still referenced by: {}",
            referenced.join(", ")
        )));
    }
    let image = shinu::ckpt_image(ctx.root, id);
    match std::fs::remove_file(&image) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    update_state(ctx.db, ctx.registry, |state| {
        let checkpoint = shinu::find_ckpt(state, id, project)?;
        if !shinu::is_referenced(state, checkpoint.id).is_empty() {
            return Err(shinu::Error::Invalid(format!(
                "checkpoint {id} is still referenced"
            )));
        }
        state.ckpts.retain(|entry| entry.id != id);
        Ok(())
    })?;
    Ok(json!({ "removed": id }))
}


fn list_spaces(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let state = snapshot(ctx.db, ctx.registry)?;
    let mut spaces = Vec::new();
    for space in state.spaces.iter().filter(|space| space.project == project) {
        let mut value = serde_json::to_value(space)?;
        if let Some(object) = value.as_object_mut() {
            let size = shinu::btrfs::exclusive(&shinu::space_image(ctx.root, space.id)).unwrap_or(0);
            object.insert("exclusive".into(), Value::from(size));
            object.insert(
                "running".into(),
                Value::from(shinu::vm::is_running(&shinu::vm_dir(ctx.root, space.id))),
            );
        }
        spaces.push(value);
    }
    let mut checkpoints = Vec::new();
    for checkpoint in state.ckpts.iter().filter(|checkpoint| checkpoint.project == project) {
        let mut value = serde_json::to_value(checkpoint)?;
        if let Some(object) = value.as_object_mut() {
            let size = shinu::btrfs::exclusive(&shinu::ckpt_image(ctx.root, checkpoint.id)).unwrap_or(0);
            object.insert("exclusive".into(), Value::from(size));
        }
        checkpoints.push(value);
    }
    Ok(json!({ "spaces": spaces, "ckpts": checkpoints }))
}

fn start_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
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
    let limits = effective_limits(ctx, project)?;
    // The registry state lock is held across the check and spawn. This closes
    // the race where two starts both observe the same running count.
    let _state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    let state = state::load(&connection)?;
    let already_running = shinu::vm::is_running(&shinu::vm_dir(ctx.root, id));
    if !already_running {
        quota::check_running_limit(count_running(ctx.root, &state, project), &limits)?;
    }
    drop(connection);
    let (_, booted) = shinu::vm::start(
        ctx.root,
        id,
        0,
        0,
        ctx.vm_cfg,
        ctx.net_cfg,
    )?;
    Ok(json!({ "booted": booted }))
}

fn stop_space(ctx: &Ctx<'_>, project: &str, name: String) -> shinu::Result<Value> {
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
    let was_running = shinu::vm::stop(&shinu::vm_dir(ctx.root, id), ctx.net_cfg)?;
    Ok(json!({ "was_running": was_running }))
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
    shinu::vm::touch(&shinu::vm_dir(ctx.root, id))?;
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
    let mut candidates = Vec::new();
    for checkpoint in state
        .ckpts
        .iter()
        .filter(|checkpoint| checkpoint.project == project && checkpoint.auto)
    {
        let age = now
            .signed_duration_since(checkpoint.created_at)
            .num_seconds();
        if age <= i64::try_from(retention_secs).unwrap_or(i64::MAX)
            || !shinu::is_referenced(&state, checkpoint.id).is_empty()
        {
            continue;
        }
        let exclusive = shinu::btrfs::exclusive(&shinu::ckpt_image(ctx.root, checkpoint.id))?;
        candidates.push((checkpoint.id, checkpoint.note.clone(), exclusive));
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
    // Claim before deleting. The candidate list was computed from a snapshot
    // taken without the state lock, so a concurrent fork or commit may have
    // started referencing one of these commits in the meantime. Removing the
    // rows inside the lock — re-checking `is_referenced` against the authoritative
    // state as we go — makes the claim atomic: once a commit is gone from the
    // state, `find_ckpt` fails for every later request, so no new reference to
    // it can appear while the images are being unlinked outside the lock.
    //
    // Deleting first and pruning afterwards was the other option and is worse:
    // it leaves a window where a space's `parent`/`head` points at a commit whose
    // image is already gone. Crashing between the claim and the unlink instead
    // leaks an unreferenced image file, which is recoverable garbage.
    let claimed = update_state(ctx.db, ctx.registry, |state| {
        let mut claimed = Vec::new();
        let mut budget = 0u64;
        for (id, note, exclusive) in &candidates {
            if budget >= need {
                break;
            }
            let still_present = state
                .ckpts
                .iter()
                .any(|checkpoint| checkpoint.id == *id && checkpoint.project == project);
            if !still_present || !shinu::is_referenced(state, *id).is_empty() {
                continue;
            }
            state.ckpts.retain(|checkpoint| checkpoint.id != *id);
            budget += exclusive;
            claimed.push((*id, note.clone(), *exclusive));
        }
        Ok(claimed)
    })?;

    let mut reclaimed = 0;
    let mut deleted = Vec::new();
    for (id, note, exclusive) in claimed {
        let image = shinu::ckpt_image(ctx.root, id);
        match std::fs::remove_file(&image) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        reclaimed += exclusive;
        deleted.push(json!({ "id": id, "note": note, "exclusive": exclusive }));
    }
    Ok(json!({ "dry_run": false, "reclaimed": reclaimed, "deleted": deleted }))
}

fn checkpoint_json(checkpoint: &Ckpt) -> shinu::Result<Value> {
    Ok(serde_json::to_value(checkpoint)?)
}

fn limits_value(ctx: &Ctx<'_>, project: &str) -> shinu::Result<Value> {
    let limits = effective_limits(ctx, project)?;
    let _state_guard = lock_state(ctx.registry);
    let connection = lock_db(ctx.db);
    let state = state::load(&connection)?;
    let used_spaces = state::count_spaces(&connection, project)?;
    let used_disk = current_disk_mib(ctx.root, &state, project);
    let used_running = count_running(ctx.root, &state, project);
    Ok(json!({
        "max_spaces": limits.max_spaces,
        "max_disk_mib": limits.max_disk_mib,
        "max_running": limits.max_running,
        "api_per_min": limits.api_per_min,
        "used": {
            "spaces": used_spaces,
            "disk_mib": used_disk,
            "running": used_running,
        },
    }))
}

fn handle(ctx: &Ctx<'_>, req: Req, project: &str) -> shinu::Result<Value> {
    match req {
        Req::New { name } => create_space(ctx, project, name),
        Req::Fork { ckpt, name } => fork_space(ctx, project, ckpt, name),
        Req::Commit { space, note, hot } => commit_space(ctx, project, space, note, hot),
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
        Req::Rm { space } => remove_space(ctx, project, space),
        Req::RmCkpt { ckpt } => remove_checkpoint(ctx, project, ckpt),
        Req::Ls => list_spaces(ctx, project),
        Req::Start { space } => start_space(ctx, project, space),
        Req::Stop { space } => stop_space(ctx, project, space),
        Req::Touch { space } => touch_space(ctx, project, space),
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
    Usage,
    Limits,
    Rm(String),
    Start(String),
    Stop(String),
    Exec(String),
    Commit(String),
    Log(String),
    Reflog(String),
    Checkout(String),
    Fork(String),
    RmCkpt(String),
    Gc,
}
fn route(path: &str) -> Option<Endpoint> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    match path {
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
    let segments = path
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
    if segments.len() == 3 && segments[2] == "usage" {
        return Some(Endpoint::Usage);
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
            "commits" => Some(Endpoint::Commit(name)),
            "log" => Some(Endpoint::Log(name)),
            "reflog" => Some(Endpoint::Reflog(name)),
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
            shinu::Error::Invalid(format!("usage query {key} must be a unix timestamp: {error}"))
        })?;
        match key {
            "from" if from.is_none() => from = Some(parsed),
            "to" if to.is_none() => to = Some(parsed),
            "from" | "to" => {
                return Err(shinu::Error::Invalid(format!("duplicate usage query key: {key}")))
            }
            _ => return Err(shinu::Error::Invalid(format!("unknown usage query key: {key}"))),
        }
    }
    Ok((from, to))
}


fn method_allowed(endpoint: &Endpoint, method: &str) -> bool {
    match endpoint {
        Endpoint::Root
        | Endpoint::LoginPage
        | Endpoint::RegisterPage
        | Endpoint::AppPage
        | Endpoint::Asset(_)
        | Endpoint::ConsoleMe => method == "GET",
        Endpoint::ConsoleRegister | Endpoint::ConsoleLogin | Endpoint::ConsoleLogout => {
            method == "POST"
        }
        Endpoint::ConsoleTokens => method == "GET" || method == "POST",
        Endpoint::ConsoleToken(_) => method == "DELETE",
        Endpoint::Spaces => method == "GET" || method == "POST",
        Endpoint::Usage | Endpoint::Limits | Endpoint::Log(_) | Endpoint::Reflog(_) => {
            method == "GET"
        }
        Endpoint::Rm(_) | Endpoint::RmCkpt(_) => method == "DELETE",
        Endpoint::Start(_)
        | Endpoint::Stop(_)
        | Endpoint::Exec(_)
        | Endpoint::Commit(_)
        | Endpoint::Checkout(_)
        | Endpoint::Fork(_)
        | Endpoint::Gc => method == "POST",
    }
}
fn parse_body(body: &[u8]) -> shinu::Result<Value> {
    if body.is_empty() {
        return Err(shinu::Error::Invalid("request body is required".into()));
    }
    serde_json::from_slice(body)
        .map_err(|error| shinu::Error::Invalid(format!("invalid JSON body: {error}")))
}

fn body_string(body: &[u8], field: &str) -> shinu::Result<String> {
    let value = parse_body(body)?;
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| shinu::Error::Invalid(format!("body field {field} must be a string")))
}

fn body_bool(body: &[u8], field: &str) -> shinu::Result<bool> {
    let value = parse_body(body)?;
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| shinu::Error::Invalid(format!("body field {field} must be a boolean")))
}

fn body_u64(body: &[u8], field: &str) -> shinu::Result<u64> {
    let value = parse_body(body)?;
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| shinu::Error::Invalid(format!("body field {field} must be an unsigned integer")))
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
        Endpoint::Spaces => Ok((Req::New { name: body_string(body, "name")? }, 201)),
        Endpoint::Usage => Ok((Req::Usage { from, to }, 200)),
        Endpoint::Limits => Ok((Req::Limits, 200)),
        Endpoint::Rm(space) => Ok((Req::Rm { space }, 200)),
        Endpoint::Start(space) => Ok((Req::Start { space }, 200)),
        Endpoint::Stop(space) => Ok((Req::Stop { space }, 200)),
        Endpoint::Commit(space) => Ok((
            Req::Commit {
                space,
                note: body_string(body, "note")?,
                hot: body_bool(body, "hot")?,
            },
            201,
        )),
        Endpoint::Log(space) => Ok((Req::Log { space }, 200)),
        Endpoint::Reflog(space) => Ok((Req::Reflog { space }, 200)),
        Endpoint::Checkout(space) => Ok((
            Req::Checkout {
                space,
                commit: Uuid::parse_str(&body_string(body, "commit")?)
                    .map_err(|error| shinu::Error::Invalid(format!("invalid commit id: {error}")))?,
            },
            200,
        )),
        Endpoint::Fork(commit) => Ok((
            Req::Fork {
                ckpt: Uuid::parse_str(&commit)
                    .map_err(|error| shinu::Error::Invalid(format!("invalid commit id: {error}")))?,
                name: body_string(body, "name")?,
            },
            201,
        )),
        Endpoint::RmCkpt(commit) => Ok((
            Req::RmCkpt {
                ckpt: Uuid::parse_str(&commit)
                    .map_err(|error| shinu::Error::Invalid(format!("invalid commit id: {error}")))?,
            },
            200,
        )),
        Endpoint::Gc => Ok((
            Req::Gc {
                free_below: body_u64(body, "free_below")?,
                dry_run: body_bool(body, "dry_run")?,
            },
            200,
        )),
        Endpoint::Exec(_) => Err(shinu::Error::Invalid("exec requires a command".into())),
        _ => Err(shinu::Error::Invalid("endpoint is not an API route".into())),
    }
}

fn exec_command(body: &[u8]) -> shinu::Result<Vec<String>> {
    let value = parse_body(body)?;
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
    Ok(command)
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
    matches!(method, "POST" | "DELETE" | "PATCH")
}

fn authenticate(ctx: &Ctx<'_>, request: &http::Request) -> shinu::Result<Caller> {
    // A bearer token is deliberately authoritative when present. Falling back
    // to a cookie after an invalid bearer would let a malformed proxy header
    // silently change which project receives a request.
    if let Some(plain) = request.token.as_deref() {
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
    if request.token.is_none() && !request.cookies.contains_key(SESSION_COOKIE) {
        return None;
    }
    authenticate(ctx, request).ok()
}

fn origin_host(origin: &str) -> Option<&str> {
    let (_, authority) = origin.split_once("://")?;
    let end = authority
        .find(['/', '?', '#'])
        .unwrap_or(authority.len());
    let authority = &authority[..end];
    if authority.is_empty()
        || authority.contains('@')
        || authority.chars().any(|character| character.is_ascii_whitespace())
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
    let origin_host = origin_host(origin).ok_or_else(|| {
        shinu::Error::Invalid("origin header is not a valid URL".into())
    })?;
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

fn login_console(
    ctx: &Ctx<'_>,
    body: &[u8],
    secure: bool,
) -> shinu::Result<(Value, String)> {
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
        .map(|token| json!({
            "hash_prefix": token_hash_prefix(&token.hash),
            "created_at": token.created_at,
        }))
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
    if prefix.is_empty() || prefix.len() > 64 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
    http::respond(stream, status, &json!({ "error": error.to_string() }))?;
    Ok(())
}

fn is_console_path(path: &str) -> bool {
    path.split_once('?')
        .map_or(path, |(path, _)| path)
        .starts_with("/console/")
}
fn serve_connection(mut stream: TcpStream, ctx: &Ctx<'_>) -> shinu::Result<()> {
    let client_ip = stream
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    let parsed_request = {
        let mut reader = BufReader::new(&mut stream);
        http::parse(&mut reader)
    };
    let request = match parsed_request {
        Ok(request) => request,
        Err(error) => {
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };
    let endpoint = match route(&request.path) {
        Some(endpoint) => endpoint,
        None => {
            let error = shinu::Error::NotFound(request.path.clone());
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };
    if !method_allowed(&endpoint, &request.method) {
        let error = shinu::Error::Invalid("method not allowed".into());
        respond_error(&mut stream, 405, &error)?;
        return Ok(());
    }
    // Register and login have no Caller yet, so the console path itself is the
    // trust boundary for CSRF. This also covers logout and token mutations.
    if is_console_path(&request.path)
        && is_state_changing(&request.method)
        && let Err(error) = check_console_csrf(&request)
    {
        respond_error(&mut stream, 403, &error)?;
        return Ok(());
    }

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
                    http::respond(
                        &mut stream,
                        401,
                        &json!({ "error": LOGIN_FAILURE_MESSAGE }),
                    )?;
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
                Endpoint::ConsoleLogout => {
                    match logout_console(ctx, &request) {
                        Ok(cookie) => {
                            http::respond_with_cookie(&mut stream, 200, &json!({}), &cookie)?;
                        }
                        Err(error) => {
                            respond_error(&mut stream, http::status_for(&error), &error)?;
                        }
                    }
                }
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

    let (from, to) = match usage_query(&request.path) {
        Ok(range) => range,
        Err(error) => {
            respond_error(&mut stream, http::status_for(&error), &error)?;
            return Ok(());
        }
    };
    if let Endpoint::Exec(space) = &endpoint {
        let command = match exec_command(&request.body) {
            Ok(command) => command,
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
                return Ok(());
            }
        };
        match execute_streaming(&mut stream, ctx, project, space.clone(), command) {
            Ok(()) => {
                record_usage(ctx.db, project, "api_call", None, 1)?;
            }
            Err(error) => {
                respond_error(&mut stream, http::status_for(&error), &error)?;
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

fn read_stream<R: Read + Send + 'static>(
    stream: &'static str,
    reader: R,
    sender: mpsc::Sender<StreamLine>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if sender
                        .send(StreamLine { stream, data: line })
                        .is_err()
                    {
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

fn execute_streaming(
    stream: &mut TcpStream,
    ctx: &Ctx<'_>,
    project: &str,
    space: String,
    command: Vec<String>,
) -> shinu::Result<()> {
    let space_id = {
        let connection = lock_db(ctx.db);
        state::find_space(&connection, &space, project)?
            .ok_or_else(|| shinu::Error::NotFound(space.clone()))?
            .id
    };
    let limits = effective_limits(ctx, project)?;
    let space_guard = ctx.registry.space_lock(space_id);
    {
        let _space_guard = space_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Hold the state lock through the check and spawn so concurrent execs
        // cannot all observe a free running-VM slot.
        let _state_guard = lock_state(ctx.registry);
        let connection = lock_db(ctx.db);
        let state = state::load(&connection)?;
        if !shinu::vm::is_running(&shinu::vm_dir(ctx.root, space_id)) {
            quota::check_running_limit(count_running(ctx.root, &state, project), &limits)?;
        }
        drop(connection);
        shinu::vm::start(ctx.root, space_id, 0, 0, ctx.vm_cfg, ctx.net_cfg)?;
    }
    let vm_dir = shinu::vm_dir(ctx.root, space_id);
    let helper = shinu::vsock_helper()?;
    let proxy = format!(
        "ProxyCommand={} {} {}",
        shinu::shell_quote_word(&helper.to_string_lossy()),
        shinu::shell_quote_word(&shinu::vm::vsock_path(&vm_dir).to_string_lossy()),
        shinu::VSOCK_SSH_PORT
    );
    let mut child = Command::new("ssh")
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
        .arg(proxy)
        .arg("-i")
        .arg(shinu::vm::key_path(&vm_dir))
        .arg("root@shinu")
        .arg("--")
        .arg(shinu::shell_quote(&command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| shinu::Error::Invalid("ssh stdout pipe unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| shinu::Error::Invalid("ssh stderr pipe unavailable".into()))?;
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = read_stream("stdout", stdout, sender.clone());
    let stderr_reader = read_stream("stderr", stderr, sender);
    http::respond_chunked_start(stream)?;

    let mut readers = 2;
    let mut child_status = None;
    let mut stream_broken = false;
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
        if child_status.is_none() {
            match child.try_wait() {
                Ok(status) => child_status = status,
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
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        return Ok(());
    }
    let exit = child_status
        .and_then(|status| status.code())
        .unwrap_or(255);
    let _ = http::respond_chunk(stream, &json!({ "exit": exit }));
    let _ = http::respond_chunked_end(stream);
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{append_checkpoint, handle, set_head};
    use chrono::Utc;
    use rusqlite::Connection;
    use shinu::{
        NetConfig, VmConfig,
        proto::Req,
        quota::{Limits, RateLimiter},
        state::{self, Ckpt, Space, State},
        vm,
    };
    use std::os::unix::fs::symlink;
    use std::collections::HashMap;
    use std::io::{Read as IoRead, Write as IoWrite};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::{LazyLock, Mutex};
    use std::thread;
    use std::time::Duration;
    use uuid::Uuid;

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("shinu-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create test root");
        root
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

    fn test_limits() -> &'static Limits {
        static LIMITS: LazyLock<Limits> = LazyLock::new(|| Limits {
            max_spaces: 5,
            max_disk_mib: 10240,
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
        }
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
                    parent: None,
                    head: None,
                    created_at: Utc::now(),
                }],
                ckpts: Vec::new(),
            },
        );
        let db = test_db(&root);
        let registry = registry();
        let limits = Limits {
            max_spaces: 1,
            max_disk_mib: 10240,
            max_running: 2,
            api_per_min: 120,
        };
        let result = super::update_state_with_quota(
            &root,
            &db,
            &registry,
            "project-a",
            &limits,
            0,
            |_| Ok(()),
        );
        assert!(matches!(result, Err(shinu::Error::Quota(message)) if message.contains("space limit")));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn rate_limit_rejects_the_request_after_the_boundary() {
        let rate = RateLimiter::new();
        assert!(rate.check("project-a", 1).is_ok());
        let result = rate.check("project-a", 1);
        assert!(matches!(result, Err(shinu::Error::Quota(message)) if message.contains("rate limit")));
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
        }
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let global = Limits {
            max_spaces: 5,
            max_disk_mib: 10,
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
        };
        let override_limits = super::effective_limits(&ctx, "project-a").expect("override");
        assert_eq!(override_limits.max_spaces, 7);
        assert_eq!(override_limits.max_disk_mib, 99);
        let default_limits = super::effective_limits(&ctx, "project-b").expect("default");
        assert_eq!(default_limits.max_spaces, 5);
        assert_eq!(default_limits.max_disk_mib, 10);
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
                note: "before".into(),
                created_at: Utc::now(),
            }],
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
                note: "base".into(),
                created_at: Utc::now(),
            }],
        };
        store_state(&root, &state);
        std::fs::create_dir_all(root.join("ckpts")).expect("create checkpoint directory");
        std::fs::write(shinu::ckpt_image(&root, checkpoint_id), b"checkpoint")
            .expect("write checkpoint image");
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(&ctx, Req::RmCkpt { ckpt: checkpoint_id }, project);
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
                note: "private".into(),
                created_at: Utc::now(),
            }],
        };
        store_state(&root, &state);
        let (vm_cfg, net_cfg) = test_configs();
        let registry = registry();
        let db = test_db(&root);
        let ctx = daemon_ctx(&root, &db, &vm_cfg, &net_cfg, &registry);
        let result = handle(
            &ctx,
            Req::RmCkpt { ckpt: checkpoint_id },
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
                parent: None,
                head: None,
                created_at: Utc::now(),
            }],
            ckpts: Vec::new(),
        };
        let first = append_checkpoint(
            &mut state,
            space_id,
            project,
            Uuid::new_v4(),
            "first".into(),
            false,
            true,
        )
        .expect("first checkpoint");
        let second = append_checkpoint(
            &mut state,
            space_id,
            project,
            Uuid::new_v4(),
            "second".into(),
            false,
            true,
        )
        .expect("second checkpoint");
        assert_eq!(second.parent, Some(first.id));
        assert_eq!(state.spaces[0].head, Some(second.id));
        let log = shinu::log_chain(&state, &state.spaces[0]);
        assert_eq!(log.iter().map(|checkpoint| checkpoint.id).collect::<Vec<_>>(),
                   vec![second.id, first.id]);
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
                note: "target".into(),
                created_at: Utc::now(),
            }],
        };
        let auto = append_checkpoint(
            &mut state,
            space_id,
            project,
            Uuid::new_v4(),
            format!("auto before checkout {}", &target_id.to_string()[..8]),
            true,
            false,
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
                    note: "before checkout".into(),
                    created_at: Utc::now(),
                },
                Ckpt {
                    id: auto_id,
                    space: space_id,
                    project: project.into(),
                    parent: Some(old_id),
                    auto: true,
                    note: "auto before checkout".into(),
                    created_at: Utc::now(),
                },
            ],
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
                    note: "auto stale".into(),
                    created_at: Utc::now(),
                },
                Ckpt {
                    id: raced_id,
                    space: space_id,
                    project: project.into(),
                    parent: None,
                    auto: true,
                    note: "auto raced".into(),
                    created_at: Utc::now(),
                },
            ],
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
        assert_eq!(claimed, vec![stale_id], "raced commit must survive the claim");
        assert!(
            state.ckpts.iter().any(|checkpoint| checkpoint.id == raced_id),
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
        }
    }

    fn console_request(origin: Option<&str>, host: Option<&str>) -> shinu::http::Request {
        shinu::http::Request {
            method: "POST".into(),
            path: "/v1/spaces".into(),
            token: None,
            body: br#"{}"#.to_vec(),
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

        let (logged_in, login_cookie) = super::login_console(
            &ctx,
            body.as_bytes(),
            false,
        )
        .expect("login user");
        assert_eq!(logged_in["user_id"], registered["user_id"]);
        assert!(login_cookie.contains("shinu_session="));
        assert!(state::find_user_by_email(&super::lock_db(&db), &email)
            .expect("find registered user")
            .is_some());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn console_login_hides_unknown_email_and_wrong_password() {
        let root = test_root("console-login-errors");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let email = format!("user-{}@example.com", Uuid::new_v4());
        let registered = format!(
            "{{\"email\":\"{email}\",\"password\":\"correct horse\"}}"
        );
        super::register_console(&ctx, registered.as_bytes(), &Uuid::new_v4().to_string(), false)
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
        let result = super::register_console(&ctx, body.as_bytes(), &Uuid::new_v4().to_string(), false);
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
    fn expired_console_session_is_rejected() {
        let root = test_root("console-expired-session");
        let db = console_db();
        let registry = registry();
        let ctx = console_ctx(&root, &db, &registry);
        let email = format!("expired-{}@example.com", Uuid::new_v4());
        let (user_id, _) = state::create_user(
            &super::lock_db(&db),
            &email,
            super::DUMMY_PASSWORD_HASH,
        )
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
}
