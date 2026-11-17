//! Public VM start/guest protocol seam. The guest and Firecracker process are
//! external adapters; the real start, identity, admission, and cleanup code runs.
use shinu_core::{Image, ReadySpec};
use shinu_vm::{NetConfig, VmConfig, vm};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Reply {
    Match,
    Wrong,
    Replay,
    Disconnect,
    Timeout,
    Hold,
    Peer,
}

struct Guest {
    root: PathBuf,
    dir: PathBuf,
    id: Uuid,
    child: Child,
    reply: Arc<Mutex<Reply>>,
    ids: Arc<Mutex<Vec<String>>>,
    permit: Arc<(Mutex<bool>, Condvar)>,
    requested: mpsc::Receiver<()>,
    peer: Arc<Mutex<Option<std::net::SocketAddr>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn configs() -> (VmConfig, NetConfig) {
    (
        VmConfig {
            vcpus: 1,
            mem_mib: 64,
            idle_secs: 3600,
            idle_reclaim: false,
            jail_uid: 30000,
            jail_gid: 30000,
        },
        NetConfig {
            enabled: false,
            base: [172, 30],
            allow: Vec::new(),
            host_allow: Vec::new(),
            uplink: "unused".into(),
        },
    )
}

fn policy() -> ReadySpec {
    ReadySpec {
        command: vec!["/bin/true".into()],
        timeout_seconds: 1,
    }
}

impl Guest {
    fn spawn_vm(root: &std::path::Path, dir: &std::path::Path) -> Child {
        let config = vm::config_path(dir);
        std::fs::write(&config, "{}").unwrap();
        let child = Command::new(root.join("firecracker"))
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::fs::write(vm::pid_path(dir), child.id().to_string()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !vm::is_running(dir) {
            assert!(
                Instant::now() < deadline,
                "fake Firecracker identity did not appear"
            );
            std::thread::yield_now();
        }
        child
    }

    fn new(reply_kind: Reply) -> Self {
        let root =
            std::env::temp_dir().join(format!("sr-{}", &Uuid::new_v4().simple().to_string()[..8]));
        let id = Uuid::new_v4();
        let dir = shinu_core::vm_dir(&root, id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(vm::jail_root(&root, id)).unwrap();
        std::os::unix::fs::symlink("/usr/bin/yes", root.join("firecracker")).unwrap();
        let child = Self::spawn_vm(&root, &dir);
        let nonce = Uuid::new_v4().to_string();
        std::fs::write(dir.join("snapshot-worker-nonce"), &nonce).unwrap();
        let listener = UnixListener::bind(vm::vsock_path(&dir)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let reply = Arc::new(Mutex::new(reply_kind));
        let peer = Arc::new(Mutex::new(None::<std::net::SocketAddr>));
        let ids = Arc::new(Mutex::new(Vec::<String>::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let permit = Arc::new((Mutex::new(false), Condvar::new()));
        let (notify, requested) = mpsc::channel();
        let worker = {
            let peer = peer.clone();
            let reply = reply.clone();
            let ids = ids.clone();
            let stopped = stopped.clone();
            let permit = permit.clone();
            std::thread::spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    if line != "CONNECT 2224\n" {
                        let _ = stream.write_all(b"FAILED\n");
                        continue;
                    }
                    if stream.write_all(b"OK 42\nSHINU-SNAPSHOT-1\n").is_err() {
                        continue;
                    }
                    line.clear();
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    if line == format!("capabilities {nonce}\n") {
                        let _ = stream.write_all(b"READY-1\n");
                        continue;
                    }
                    let mut words = line.trim_end().splitn(4, ' ');
                    assert_eq!(words.next(), Some("ready"));
                    assert_eq!(words.next(), Some(nonce.as_str()));
                    let id = words.next().unwrap().to_owned();
                    assert!(Uuid::parse_str(&id).is_ok());
                    assert_ne!(id, nonce);
                    let _: ReadySpec = serde_json::from_str(words.next().unwrap()).unwrap();
                    let previous = {
                        let mut ids = ids.lock().unwrap();
                        let previous = ids.first().cloned();
                        ids.push(id.clone());
                        previous
                    };
                    let _ = notify.send(());
                    let mode = *reply.lock().unwrap();
                    match mode {
                        Reply::Match => {
                            let _ = writeln!(stream, "READY {id}");
                        }
                        Reply::Wrong => {
                            let _ = writeln!(stream, "READY {}", Uuid::new_v4());
                        }
                        Reply::Replay => {
                            let _ = writeln!(stream, "READY {}", previous.unwrap());
                        }
                        Reply::Disconnect => {}
                        Reply::Timeout => std::thread::sleep(Duration::from_millis(1200)),
                        Reply::Hold => {
                            let (lock, wake) = &*permit;
                            let _guard = wake
                                .wait_timeout_while(
                                    lock.lock().unwrap(),
                                    Duration::from_secs(2),
                                    |permit| !*permit,
                                )
                                .unwrap();
                            let _ = writeln!(stream, "READY {id}");
                        }
                        Reply::Peer => {
                            let peer_reply = peer
                                .lock()
                                .unwrap()
                                .and_then(|address| std::net::TcpStream::connect(address).ok())
                                .and_then(|mut peer| {
                                    use std::io::Read;
                                    peer.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
                                    peer.write_all(b"ping").ok()?;
                                    let mut reply = [0; 4];
                                    peer.read_exact(&mut reply).ok()?;
                                    (reply == *b"pong").then_some(())
                                });
                            if peer_reply.is_some() {
                                let _ = writeln!(stream, "READY {id}");
                            } else {
                                let _ = writeln!(stream, "FAILED peer-unavailable");
                            }
                        }
                    }
                }
            })
        };
        Self {
            root,
            dir,
            id,
            child,
            reply,
            ids,
            permit,
            requested,
            stopped,
            peer,
            worker: Some(worker),
        }
    }

    fn start(&self, readiness: Option<&ReadySpec>) -> shinu_core::Result<(PathBuf, bool)> {
        let (cfg, net) = configs();
        vm::start(
            &self.root,
            self.id,
            Image::Void,
            vm::StartOptions {
                readiness,
                ..vm::StartOptions::default()
            },
            &cfg,
            &net,
            |_| Ok(()),
        )
    }

    fn next_generation(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.child = Self::spawn_vm(&self.root, &self.dir);
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        let (lock, wake) = &*self.permit;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        self.worker.take().unwrap().join().unwrap();
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Stop clears daemon-local admission receipts even for a dead VM.
        let (_, net) = configs();
        let _ = vm::stop(&self.dir, &net);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn start_never_returns_before_matching_ready_even_if_vm_is_already_running() {
    let guest = Guest::new(Reply::Hold);
    let (tx, rx) = mpsc::channel();
    let root = guest.root.clone();
    let id = guest.id;
    let worker = std::thread::spawn(move || {
        let (cfg, net) = configs();
        tx.send(vm::start(
            &root,
            id,
            Image::Void,
            vm::StartOptions {
                readiness: Some(&policy()),
                ..vm::StartOptions::default()
            },
            &cfg,
            &net,
            |_| Ok(()),
        ))
        .unwrap();
    });
    guest
        .requested
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let (lock, wake) = &*guest.permit;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    assert!(!rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap().1);
    worker.join().unwrap();
}

#[test]
fn same_boot_reuses_admission_but_new_generation_and_policy_require_fresh_ids() {
    let mut guest = Guest::new(Reply::Match);
    guest.start(Some(&policy())).unwrap();
    guest.start(Some(&policy())).unwrap();
    assert_eq!(guest.ids.lock().unwrap().len(), 1);
    let mut changed = policy();
    changed.command.push("different-policy".into());
    guest.start(Some(&changed)).unwrap();
    guest.next_generation();
    guest.start(Some(&changed)).unwrap();
    let ids = guest.ids.lock().unwrap();
    assert_eq!(ids.len(), 3);
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
}

#[test]
fn replayed_previous_generation_ready_cannot_admit_or_leave_the_new_vm_running() {
    let mut guest = Guest::new(Reply::Match);
    guest.start(Some(&policy())).unwrap();
    guest.next_generation();
    *guest.reply.lock().unwrap() = Reply::Replay;
    assert!(guest.start(Some(&policy())).is_err());
    assert!(!vm::is_running(&guest.dir));
    assert!(!vm::vsock_path(&guest.dir).exists());
}

#[test]
fn wrong_id_disconnect_and_host_timeout_fail_and_cleanup_the_exact_boot() {
    for reply in [Reply::Wrong, Reply::Disconnect, Reply::Timeout] {
        let guest = Guest::new(reply);
        let started = Instant::now();
        assert!(guest.start(Some(&policy())).is_err());
        assert!(!vm::is_running(&guest.dir));
        assert!(!vm::vsock_path(&guest.dir).exists());
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}

#[test]
fn nonconfigured_running_space_does_not_require_a_guest_readiness_exchange() {
    let guest = Guest::new(Reply::Disconnect);
    assert!(!guest.start(None).unwrap().1);
    assert!(guest.ids.lock().unwrap().is_empty());
}

#[test]
fn delayed_old_ready_cannot_cache_or_cleanup_a_successor_boot() {
    let mut guest = Guest::new(Reply::Hold);
    let (tx, rx) = mpsc::channel();
    let root = guest.root.clone();
    let id = guest.id;
    let worker = std::thread::spawn(move || {
        let (cfg, net) = configs();
        tx.send(vm::start(
            &root,
            id,
            Image::Void,
            vm::StartOptions {
                readiness: Some(&policy()),
                ..vm::StartOptions::default()
            },
            &cfg,
            &net,
            |_| Ok(()),
        ))
        .unwrap();
    });
    guest
        .requested
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    guest.next_generation();
    let (lock, wake) = &*guest.permit;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    worker.join().unwrap();
    assert!(
        vm::is_running(&guest.dir),
        "old transaction must not stop the successor"
    );
    *guest.reply.lock().unwrap() = Reply::Match;
    guest.start(Some(&policy())).unwrap();
    assert_eq!(
        guest.ids.lock().unwrap().len(),
        2,
        "late READY must not create a reusable receipt"
    );
}

#[test]
fn guest_can_exchange_with_a_peer_established_by_the_pre_admission_hook() {
    use std::io::Read;
    let guest = Guest::new(Reply::Peer);
    let (cfg, net) = configs();
    let mut peer_worker = None;
    let result = vm::start(
        &guest.root,
        guest.id,
        Image::Void,
        vm::StartOptions {
            readiness: Some(&policy()),
            ..vm::StartOptions::default()
        },
        &cfg,
        &net,
        |_| {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            *guest.peer.lock().unwrap() = Some(listener.local_addr()?);
            peer_worker = Some(std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 4];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").unwrap();
            }));
            Ok(())
        },
    );
    assert!(
        result.is_ok(),
        "readiness requires an actual bidirectional peer exchange"
    );
    peer_worker.unwrap().join().unwrap();
}

#[test]
fn peer_setup_failure_never_requests_ready_and_cleans_the_boot() {
    let guest = Guest::new(Reply::Match);
    let (cfg, net) = configs();
    let result = vm::start(
        &guest.root,
        guest.id,
        Image::Void,
        vm::StartOptions {
            readiness: Some(&policy()),
            ..vm::StartOptions::default()
        },
        &cfg,
        &net,
        |_| Err(shinu_core::Error::Internal("peer setup failed".into())),
    );
    assert!(result.is_err());
    assert!(guest.ids.lock().unwrap().is_empty());
    assert!(!vm::is_running(&guest.dir));
}

#[test]
fn admitted_same_boot_skips_peer_ssh_setup_and_shares_one_remaining_deadline() {
    let guest = Guest::new(Reply::Match);
    let (cfg, net) = configs();
    let mut calls = 0;
    let spec = policy();
    for _ in 0..2 {
        vm::start(
            &guest.root,
            guest.id,
            Image::Void,
            vm::StartOptions {
                readiness: Some(&spec),
                ..vm::StartOptions::default()
            },
            &cfg,
            &net,
            |deadline| {
                calls += 1;
                assert!(
                    deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(1)
                );
                Ok(())
            },
        )
        .unwrap();
    }
    assert_eq!(calls, 1);
}

#[test]
fn peer_setup_consumes_the_shared_admission_budget_instead_of_resetting_it() {
    let guest = Guest::new(Reply::Match);
    let (cfg, net) = configs();
    let started = Instant::now();
    let result = vm::start(
        &guest.root,
        guest.id,
        Image::Void,
        vm::StartOptions {
            readiness: Some(&policy()),
            ..vm::StartOptions::default()
        },
        &cfg,
        &net,
        |deadline| {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(guest.ids.lock().unwrap().is_empty());
    assert!(!vm::is_running(&guest.dir));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn load_only_requires_a_memory_generation_and_cannot_relabel_a_running_vm() {
    let guest = Guest::new(Reply::Match);
    let (cfg, net) = configs();
    let result = vm::start(
        &guest.root,
        guest.id,
        Image::Void,
        vm::StartOptions {
            load_only: true,
            ..vm::StartOptions::default()
        },
        &cfg,
        &net,
        |_| panic!("load-only must not run readiness"),
    );
    assert!(matches!(result, Err(shinu_core::Error::Invalid(_))));
    assert!(guest.ids.lock().unwrap().is_empty());
    assert!(vm::is_running(&guest.dir));
}

#[test]
fn loaded_spaces_are_not_admitted_by_start_and_are_stopped_on_daemon_recovery() {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    for phase in ["loading", "loaded", "resuming"] {
        let mut guest = Guest::new(Reply::Match);
        std::fs::write(
            guest.dir.join("loaded.json"),
            format!(
                "{{\"phase\":\"{phase}\",\"boot_id\":\"{}\"}}",
                boot_id.trim()
            ),
        )
        .unwrap();
        std::fs::create_dir_all(guest.root.join("spaces")).unwrap();
        let memory = shinu_core::space_image(&guest.root, guest.id).with_extension("mem");
        let state = memory.with_extension("state");
        std::fs::write(&memory, b"pending memory").unwrap();
        std::fs::write(&state, b"pending state").unwrap();
        assert_eq!(vm::lifecycle_state(&guest.dir).unwrap(), phase);
        assert!(guest.start(Some(&policy())).is_err());
        assert!(guest.ids.lock().unwrap().is_empty());
        let (_, net) = configs();
        vm::recover_loaded(&guest.root, &net).unwrap();
        guest.child.wait().unwrap();
        assert_eq!(vm::lifecycle_state(&guest.dir).unwrap(), "stopped");
        assert!(!vm::jail_root(&guest.root, guest.id).exists());
        // Never-run memory of this boot stays reloadable, recorded as pending.
        let kept = phase != "resuming";
        assert_eq!(memory.exists(), kept);
        assert_eq!(state.exists(), kept);
        assert_eq!(guest.dir.join("loaded.json").exists(), kept);
    }
}

#[test]
fn resume_rejects_an_already_running_generation_without_requesting_ready() {
    let guest = Guest::new(Reply::Match);
    let (_, net) = configs();
    assert!(matches!(
        vm::resume(&guest.root, guest.id, Some(&policy()), &net, |_| Ok(())),
        Err(shinu_core::Error::Invalid(_))
    ));
    assert!(guest.ids.lock().unwrap().is_empty());
    assert!(vm::is_running(&guest.dir));
}
