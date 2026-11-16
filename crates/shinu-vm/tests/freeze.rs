use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn application_hooks_and_filesystems_thaw_in_reverse_order() {
    let root = std::env::temp_dir().join(format!("shinu-freeze-{}", uuid::Uuid::new_v4()));
    let bin = root.join("bin");
    let hooks = root.join("hooks");
    let state = root.join("state");
    let catalog = root.join("catalog");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(&catalog, "254:0 /\n254:1 /data\n").unwrap();
    executable(&bin.join("findmnt"), "#!/bin/sh\necho tmpfs\n");
    executable(
        &bin.join("fsfreeze"),
        "#!/bin/sh\nprintf '%s %s\\n' \"$1\" \"$2\" >> \"$EVENTS\"\n",
    );
    executable(
        &hooks.join("01-app"),
        "#!/bin/sh\nprintf 'app %s\\n' \"$1\" >> \"$EVENTS\"\n",
    );
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    for script in [
        include_str!("../src/freeze.sh"),
        include_str!("../src/thaw.sh"),
    ] {
        let output = Command::new("sh")
            .args(["-c", script, "snapshot-script"])
            .arg(&state)
            .arg(&hooks)
            .arg(&catalog)
            .env("PATH", &path)
            .env("EVENTS", root.join("events"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        std::fs::read_to_string(root.join("events")).unwrap(),
        "app freeze\n-f /data\n-f /\n-u /\n-u /data\napp thaw\n"
    );
    assert!(!state.exists());
    std::fs::remove_dir_all(root).unwrap();
}
