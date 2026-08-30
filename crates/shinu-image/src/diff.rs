use std::collections::BTreeMap;
use std::fs::{self, Metadata};
use std::path::Path;
use std::time::SystemTime;

use shinu_core::{Error, Result};
use uuid::Uuid;

/// The default keeps boot-generated churn out of a useful filesystem report.
pub const DEFAULT_EXCLUSIONS: &[&str] = &[
    "/dev",
    "/proc",
    "/run",
    "/sys",
    "/tmp",
    "/var/log",
    "/etc/machine-id",
    "/etc/ssh/ssh_host_*",
];

/// A report with ten thousand lines is still useful in a terminal while
/// preventing a damaged image from turning one API request into unbounded IO.
pub const DEFAULT_DIFF_LIMIT: usize = 10_000;
/// Callers may raise the default, but never beyond this bound.
pub const MAX_DIFF_LIMIT: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffStatus {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEntry {
    pub path: String,
    pub status: DiffStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffOptions {
    pub all: bool,
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffResult {
    pub entries: Vec<DiffEntry>,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    kind: NodeKind,
    size: u64,
    modified: Option<SystemTime>,
}

/// Mounts two images read-only, compares their roots, and always tears down
/// both mounts. The first image is the old tree and the second is the new tree.
pub fn diff_images(
    old_image: &Path,
    new_image: &Path,
    mount_root: &Path,
    options: DiffOptions,
) -> Result<DiffResult> {
    let old_mount = mount_root.join(format!("diff.{}.old.mnt", Uuid::new_v4()));
    let new_mount = mount_root.join(format!("diff.{}.new.mnt", Uuid::new_v4()));
    let mut old_mounted = false;
    let mut new_mounted = false;
    let result = (|| {
        super::extract::mount_image_read_only(old_image, &old_mount)?;
        old_mounted = true;
        super::extract::mount_image_read_only(new_image, &new_mount)?;
        new_mounted = true;
        compare_trees(&old_mount, &new_mount, options)
    })();
    let old_unmount = if old_mounted {
        super::extract::umount(&old_mount)
    } else {
        Ok(())
    };
    let new_unmount = if new_mounted {
        super::extract::umount(&new_mount)
    } else {
        Ok(())
    };
    let _ = fs::remove_dir(&old_mount);
    let _ = fs::remove_dir(&new_mount);
    combine_mount_results(result, old_unmount, new_unmount)
}

fn combine_mount_results(
    result: Result<DiffResult>,
    old_unmount: Result<()>,
    new_unmount: Result<()>,
) -> Result<DiffResult> {
    let mut failures = Vec::new();
    let value = match result {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(format!("comparison failed: {error}"));
            None
        }
    };
    if let Err(error) = old_unmount {
        failures.push(format!("old image unmount failed: {error}"));
    }
    if let Err(error) = new_unmount {
        failures.push(format!("new image unmount failed: {error}"));
    }
    if failures.is_empty() {
        return Ok(value.expect("successful comparison result"));
    }
    Err(Error::Invalid(failures.join("; ")))
}

/// Compares two ordinary directory trees without requiring a mounted ext4
/// image. This is the public seam used by tests and by the mounted-image path.
pub fn compare_trees(old_root: &Path, new_root: &Path, options: DiffOptions) -> Result<DiffResult> {
    let old = collect_tree(old_root, options.all)?;
    let new = collect_tree(new_root, options.all)?;
    let limit = options.limit.min(MAX_DIFF_LIMIT);
    let mut paths = old
        .keys()
        .chain(new.keys().filter(|path| !old.contains_key(*path)))
        .cloned()
        .collect::<Vec<_>>();
    paths.sort();

    let mut result = DiffResult {
        entries: Vec::new(),
        added: 0,
        removed: 0,
        modified: 0,
        truncated: false,
    };
    for path in paths {
        let status = match (old.get(&path), new.get(&path)) {
            (None, Some(_)) => Some(DiffStatus::Added),
            (Some(_), None) => Some(DiffStatus::Removed),
            (Some(left), Some(right)) if nodes_differ(left, right) => Some(DiffStatus::Modified),
            _ => None,
        };
        let Some(status) = status else {
            continue;
        };
        match status {
            DiffStatus::Added => result.added += 1,
            DiffStatus::Removed => result.removed += 1,
            DiffStatus::Modified => result.modified += 1,
        }
        if result.entries.len() < limit {
            result.entries.push(DiffEntry { path, status });
        } else {
            result.truncated = true;
        }
    }
    Ok(result)
}

fn nodes_differ(left: &Node, right: &Node) -> bool {
    if left.kind != right.kind {
        return true;
    }
    // Directory mtimes change whenever a child changes. Reporting them would
    // turn one edit into a second, unhelpful parent-directory entry.
    if left.kind == NodeKind::Directory {
        return false;
    }
    left.size != right.size || left.modified != right.modified
}

fn collect_tree(root: &Path, all: bool) -> Result<BTreeMap<String, Node>> {
    if !root.is_dir() {
        return Err(Error::Invalid(format!(
            "diff root is not a directory: {}",
            root.display()
        )));
    }
    let mut nodes = BTreeMap::new();
    collect_dir(root, Path::new(""), all, &mut nodes)?;
    Ok(nodes)
}

fn collect_dir(
    root: &Path,
    relative: &Path,
    all: bool,
    nodes: &mut BTreeMap<String, Node>,
) -> Result<()> {
    let directory = root.join(relative);
    let entries = fs::read_dir(&directory)?;
    for entry in entries {
        let entry = entry?;
        let child = relative.join(entry.file_name());
        if !all && is_excluded(&child) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        let kind = node_kind(&metadata);
        let path = display_path(&child);
        nodes.insert(
            path,
            Node {
                kind,
                size: metadata.len(),
                modified: metadata.modified().ok(),
            },
        );
        if kind == NodeKind::Directory {
            collect_dir(root, &child, all, nodes)?;
        }
    }
    Ok(())
}

fn node_kind(metadata: &Metadata) -> NodeKind {
    if metadata.is_dir() {
        NodeKind::Directory
    } else if metadata.is_file() {
        NodeKind::File
    } else if metadata.file_type().is_symlink() {
        NodeKind::Symlink
    } else {
        NodeKind::Other
    }
}

fn display_path(path: &Path) -> String {
    format!("/{}", path.to_string_lossy().trim_start_matches('/'))
}

/// Returns whether a relative image path belongs to the default noise filter.
pub fn is_excluded(path: &Path) -> bool {
    let path = display_path(path);
    path == "/dev"
        || path.starts_with("/dev/")
        || path == "/proc"
        || path.starts_with("/proc/")
        || path == "/run"
        || path.starts_with("/run/")
        || path == "/sys"
        || path.starts_with("/sys/")
        || path == "/tmp"
        || path.starts_with("/tmp/")
        || path == "/var/log"
        || path.starts_with("/var/log/")
        || path == "/etc/machine-id"
        || path.starts_with("/etc/ssh/ssh_host_")
}

#[cfg(test)]
mod tests {
    use super::{DiffOptions, DiffStatus, compare_trees, is_excluded};
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    fn temp_tree(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("shinu-diff-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[test]
    fn default_filter_covers_guest_churn_and_keeps_real_files() {
        for path in [
            "/proc/1/stat",
            "/sys/kernel/random/boot_id",
            "/dev/null",
            "/run/sshd.pid",
            "/tmp/work",
            "/var/log/auth.log",
            "/etc/machine-id",
            "/etc/ssh/ssh_host_ed25519_key",
        ] {
            assert!(is_excluded(Path::new(path)), "{path} should be excluded");
        }
        assert!(!is_excluded(Path::new("/home/user/file")));
        assert!(!is_excluded(Path::new("/etc/hostname")));
    }

    #[test]
    fn compare_reports_added_removed_and_modified_paths() {
        let old = temp_tree("old");
        let new = temp_tree("new");
        fs::create_dir_all(old.join("etc")).expect("create old directory");
        fs::create_dir_all(new.join("etc")).expect("create new directory");
        fs::write(old.join("removed"), b"gone").expect("write removed");
        fs::write(old.join("changed"), b"old").expect("write old changed");
        fs::write(old.join("touched"), b"same").expect("write old touched");
        std::thread::sleep(Duration::from_millis(20));
        fs::write(new.join("changed"), b"new content").expect("write new changed");
        fs::write(new.join("touched"), b"same").expect("write new touched");
        fs::write(new.join("added"), b"new file").expect("write added");
        fs::write(new.join("etc/machine-id"), b"boot-specific").expect("write churn");

        let result = compare_trees(
            &old,
            &new,
            DiffOptions {
                all: false,
                limit: 100,
            },
        )
        .expect("compare trees");
        assert_eq!(result.added, 1);
        assert_eq!(result.removed, 1);
        assert_eq!(result.modified, 2);
        assert!(!result.truncated);
        assert!(
            result
                .entries
                .iter()
                .any(|entry| entry.path == "/added" && entry.status == DiffStatus::Added)
        );
        assert!(
            result
                .entries
                .iter()
                .any(|entry| entry.path == "/removed" && entry.status == DiffStatus::Removed)
        );
        assert!(
            result
                .entries
                .iter()
                .any(|entry| entry.path == "/changed" && entry.status == DiffStatus::Modified)
        );
        assert!(
            !result
                .entries
                .iter()
                .any(|entry| entry.path == "/etc/machine-id")
        );
        let _ = fs::remove_dir_all(old);
        let _ = fs::remove_dir_all(new);
    }

    #[test]
    fn compare_caps_reported_entries_but_keeps_full_counts() {
        let old = temp_tree("cap-old");
        let new = temp_tree("cap-new");
        for name in ["a", "b", "c"] {
            fs::write(old.join(name), b"old").expect("write old");
        }
        let result = compare_trees(
            &old,
            &new,
            DiffOptions {
                all: false,
                limit: 2,
            },
        )
        .expect("compare trees");
        assert_eq!(result.removed, 3);
        assert_eq!(result.entries.len(), 2);
        assert!(result.truncated);
        let _ = fs::remove_dir_all(old);
        let _ = fs::remove_dir_all(new);
    }
}

#[cfg(test)]
mod mount_tests {
    #[test]
    fn read_only_mount_options_include_ro() {
        assert_eq!(super::super::extract::mount_options(true), "loop,ro,noload");
        assert_eq!(super::super::extract::mount_options(false), "loop");
    }
}
