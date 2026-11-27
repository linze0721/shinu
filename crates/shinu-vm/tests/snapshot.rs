use shinu_vm::vm::{SnapshotKind, snapshot, thaw_snapshot};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

struct Guest {
    dir: PathBuf,
    events: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Guest {
    fn new(failure: &'static str) -> Self {
        let dir = std::env::temp_dir().join(format!("shinu-snapshot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("snapshot-worker-nonce"),
            uuid::Uuid::new_v4().to_string(),
        )
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for worker in [false, true] {
            let listener =
                UnixListener::bind(dir.join(if worker { "vsock.sock" } else { "fc.sock" }))
                    .unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = stop.clone();
            let events = events.clone();
            let mut worker_nonce =
                std::fs::read_to_string(dir.join("snapshot-worker-nonce")).unwrap();
            let mut lost_rotation = false;
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if worker {
                        if line == "CONNECT 2222\n" {
                            // Deliberately no SSH banner: failed readiness must
                            // not suppress the independent SSH cleanup adapter.
                            stream.write_all(b"OK 42\n").unwrap();
                            continue;
                        }
                        assert_eq!(line, "CONNECT 2224\n");
                        stream.write_all(b"OK 42\nSHINU-SNAPSHOT-1\n").unwrap();
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        let mut words = line.split_whitespace();
                        let action = words.next().unwrap();
                        if words.next() != Some(worker_nonce.as_str()) {
                            stream.write_all(b"FAILED\n").unwrap();
                            continue;
                        }
                        if action == "capabilities" {
                            // A current helper: capture keeps it, no SSH reinstall.
                            assert_eq!(words.next(), Some("setup"));
                            stream.write_all(b"SETUP-1\n").unwrap();
                            continue;
                        }
                        if action == "time_scale" {
                            // A pre-dilation kernel: the capture reset passes.
                            assert_eq!(line, format!("time_scale {worker_nonce} 1 1\n"));
                            events.lock().unwrap().push("reset".into());
                            stream.write_all(b"ERR time_dilation_unsupported\n").unwrap();
                            continue;
                        }
                        if line.split_whitespace().nth(2) == Some("hold") {
                            events.lock().unwrap().push("hold".into());
                            stream.write_all(b"OK\n").unwrap();
                            if failure == "hold-closed" { continue; }
                            let mut thaw = String::new();
                            reader.read_line(&mut thaw).unwrap();
                            let mut words = thaw.split_whitespace();
                            assert_eq!(words.next(), Some("thaw"));
                            assert_eq!(words.next(), Some(worker_nonce.as_str()));
                            events.lock().unwrap().push("thaw".into());
                            stream.write_all(if failure == "thaw" { b"FAILED\n" } else { b"OK\n" }).unwrap();
                            continue;
                        }
                        if let Some(next) = words.next() {
                            worker_nonce.clear();
                            worker_nonce.push_str(next);
                            if failure == "lost-rotation" && !lost_rotation {
                                lost_rotation = true;
                                continue;
                            }
                        }
                        if action == "freeze" && failure == "private-filesystem" {
                            stream.write_all(b"FAILED unsupported private writable block filesystem 254:1 (ext4)\n").unwrap();
                            continue;
                        }
                        if action != "status" {
                            events.lock().unwrap().push(action.into());
                        }
                        stream
                            .write_all(if action == failure {
                                b"FAILED\n"
                            } else {
                                b"OK\n"
                            })
                            .unwrap();
                    } else {
                        let request = line.clone();
                        let mut length = 0;
                        loop {
                            line.clear();
                            reader.read_line(&mut line).unwrap();
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(value) = line.strip_prefix("Content-Length: ") {
                                length = value.trim().parse().unwrap();
                            }
                        }
                        let mut body = vec![0; length];
                        reader.read_exact(&mut body).unwrap();
                        let body = String::from_utf8(body).unwrap();
                        let action = if request.contains("/version ") {
                            "version"
                        } else if request.contains("/balloon ") {
                            "balloon"
                        } else if request.contains("/snapshot/create ") {
                            "create"
                        } else if body.contains("Paused") {
                            "pause"
                        } else {
                            "resume"
                        };
                        if !matches!(action, "version" | "balloon") {
                            events.lock().unwrap().push(action.into());
                        }
                        let body = if action == "version" {
                            format!(
                                "{{\"firecracker_version\":\"{}\"}}",
                                shinu_core::FC_VERSION.trim_start_matches('v')
                            )
                        } else {
                            String::new()
                        };
                        write!(
                            stream,
                            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            if action == failure {
                                "500 Error"
                            } else {
                                "200 OK"
                            },
                            body.len()
                        )
                        .unwrap();
                    }
                }
            }));
        }
        Self {
            dir,
            events,
            stop,
            threads,
        }
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[test]
fn public_capture_never_cuts_before_freeze_or_returns_before_thaw() {
    let guest = Guest::new("");
    let events = guest.events.clone();
    let capture = snapshot(&guest.dir, Some(SnapshotKind::Full), || {
        events.lock().unwrap().push("cut".into());
        Ok(())
    })
    .unwrap();
    assert_eq!(
        *guest.events.lock().unwrap(),
        ["freeze", "pause", "create", "cut", "resume", "thaw"]
    );
    assert!(capture.guest_snapshot_nonce.is_some());
}

#[test]
fn lost_rotation_acknowledgement_does_not_strand_the_next_capture() {
    let guest = Guest::new("lost-rotation");
    assert!(
        snapshot(&guest.dir, Some(SnapshotKind::Full), || {
            panic!("a lost rotation acknowledgement must prevent the disk cut")
        })
        .is_err()
    );
    assert!(snapshot(&guest.dir, Some(SnapshotKind::Full), || Ok(())).is_ok());
}

#[test]
fn optional_preconnected_thaw_survives_pause_failures_and_peer_disconnect() {
    const CHILD: &str = "SHINU_SNAPSHOT_PRECONNECT_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "optional_preconnected_thaw_survives_pause_failures_and_peer_disconnect",
            ])
            .env(CHILD, "1")
            .env("SHINU_SNAPSHOT_PRECONNECT", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for failure in [
        "",
        "hold-closed",
        "pause",
        "create",
        "cut",
        "resume",
        "thaw",
    ] {
        let guest = Guest::new(failure);
        let events = guest.events.clone();
        let result = snapshot(&guest.dir, Some(SnapshotKind::Full), || {
            events.lock().unwrap().push("cut".into());
            if failure == "cut" {
                Err(shinu_core::Error::Internal("cut failed".into()))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.is_ok(),
            matches!(failure, "" | "hold-closed"),
            "{failure}"
        );
        let observed = guest.events.lock().unwrap();
        assert!(observed.iter().any(|event| event == "hold"), "{failure}");
        assert_eq!(
            observed.last().map(String::as_str),
            Some("thaw"),
            "{failure}"
        );
        if failure.is_empty() {
            assert_eq!(
                *observed,
                ["freeze", "hold", "pause", "create", "cut", "resume", "thaw"]
            );
        }
    }
}

#[test]
fn public_capture_thaws_and_refuses_success_after_every_failure() {
    for failure in ["freeze", "pause", "create", "cut", "resume", "thaw"] {
        let guest = Guest::new(failure);
        let events = guest.events.clone();
        let result = snapshot(&guest.dir, Some(SnapshotKind::Full), || {
            events.lock().unwrap().push("cut".into());
            if failure == "cut" {
                Err(shinu_core::Error::Internal("cut failed".into()))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err(), "{failure}");
        let observed = guest.events.lock().unwrap();
        assert_eq!(
            observed.last().map(String::as_str),
            Some("thaw"),
            "{failure}"
        );
        if matches!(failure, "freeze" | "pause" | "create") {
            assert!(!observed.iter().any(|event| event == "cut"));
        }
        if failure != "freeze" {
            assert!(observed.iter().any(|event| event == "resume"));
        }
    }
}

#[test]
fn missing_or_failed_worker_falls_back_to_ssh_and_requires_success() {
    const CHILD: &str = "SHINU_SNAPSHOT_FALLBACK_CHILD";
    if let Ok(path) = std::env::var(CHILD) {
        let result = thaw_snapshot(std::path::Path::new(&path));
        assert_eq!(
            result.is_ok(),
            std::env::var("EXPECT_SUCCESS").unwrap() == "yes"
        );
        return;
    }
    for failure in ["missing", "thaw"] {
        for succeeds in [true, false] {
            let guest = Guest::new(failure);
            if failure == "missing" {
                std::fs::remove_file(guest.dir.join("snapshot-worker-nonce")).unwrap();
            }
            let bin = guest.dir.join("bin");
            std::fs::create_dir(&bin).unwrap();
            let executable = bin.join("snapshot-tests");
            std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
            std::fs::write(bin.join("shinu-vsock"), "").unwrap();
            let ssh = bin.join("ssh");
            std::fs::write(
                &ssh,
                format!(
                    "#!/bin/sh\necho attempt >> \"$ATTEMPTS\"\nexit {}\n",
                    i32::from(!succeeds)
                ),
            )
            .unwrap();
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = Command::new(executable)
                .args([
                    "--exact",
                    "missing_or_failed_worker_falls_back_to_ssh_and_requires_success",
                ])
                .env(CHILD, &guest.dir)
                .env("EXPECT_SUCCESS", if succeeds { "yes" } else { "no" })
                .env("ATTEMPTS", guest.dir.join("attempts"))
                .env(
                    "PATH",
                    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                std::fs::read_to_string(guest.dir.join("attempts"))
                    .unwrap()
                    .lines()
                    .count(),
                if succeeds { 1 } else { 2 }
            );
        }
    }
}

#[test]
fn unsupported_private_filesystem_is_reported_without_publishing_a_cut() {
    let guest = Guest::new("private-filesystem");
    let error = snapshot(&guest.dir, Some(SnapshotKind::Full), || {
        panic!("an uncovered filesystem must prevent the disk cut")
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("private writable block filesystem"),
        "{error}"
    );
    assert_eq!(
        guest.events.lock().unwrap().last().map(String::as_str),
        Some("thaw")
    );
}
