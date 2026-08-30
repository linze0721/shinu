use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use uuid::Uuid;

pub const DEFAULT_ROOT: &str = "/var/lib/shinu";

pub const FC_VERSION: &str = "v1.16.1";
/// Firecracker snapshot data format expected by `PUT /snapshot/load`.
/// Checkpoints record it so restore rejects incompatible memory state.
pub const FC_SNAPSHOT_VERSION: &str = "10.0.0";
pub const FC_URL: &str = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz";
/// Firecracker's CI kernel: an uncompressed 6.1.155 vmlinux with virtio-blk,
/// virtio-vsock and ext4 built in (`=y`), which is what booting without an
/// initrd requires. The host kernel cannot stand in for it — this host builds
/// those as modules. No `firecracker-ci/v1.16` bucket is published, so the
/// v1.15 kernel is used with the v1.16.1 binaries.
pub const KERNEL_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155";
/// Guest vsock port the in-VM socat bridge listens on; forwarded to sshd.
pub const VSOCK_SSH_PORT: u16 = 2222;
/// GUI VNC uses a separate vsock connection because each Firecracker vsock
/// connection carries one `CONNECT <port>` request.
pub const VSOCK_VNC_PORT: u16 = 2223;
/// Maximum size for raw uploads, which bypass the 1 MiB JSON body cap.
pub const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;
/// Seconds between idle-sweep passes and usage samples.
///
/// One period for both avoids drift between metering and reclamation.
pub const USAGE_SAMPLE_SECS: u64 = 30;

#[derive(Debug)]
pub enum Error {
    Btrfs(String),
    NotFound(String),
    Invalid(String),
    Auth(String),
    Quota(String),
    /// A daemon or host fault, mapped to HTTP 500 rather than a client error.
    Internal(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Btrfs(message) => write!(f, "btrfs: {message}"),
            Self::NotFound(message) => write!(f, "not found: {message}"),
            Self::Invalid(message) => write!(f, "invalid: {message}"),
            Self::Auth(message) => write!(f, "auth: {message}"),
            Self::Quota(message) => write!(f, "quota: {message}"),
            Self::Internal(message) => write!(f, "internal: {message}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

// Keep this foreign-trait impl beside `Error` so rusqlite's `?` conversions
// remain available to the store crate.
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(format!("sql: {error}"))
    }
}

pub mod btrfs {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn run(args: &[&str]) -> crate::Result<std::process::Output> {
        let output = std::process::Command::new("btrfs").args(args).output()?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(crate::Error::Btrfs(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }

    fn s(p: &Path) -> crate::Result<&str> {
        p.to_str().ok_or_else(|| {
            crate::Error::Invalid(format!("path is not valid UTF-8: {}", p.display()))
        })
    }

    pub fn create(p: &Path) -> crate::Result<()> {
        run(&["subvolume", "create", s(p)?]).map(|_| ())
    }

    pub fn snap(src: &Path, dst: &Path) -> crate::Result<()> {
        run(&["subvolume", "snapshot", s(src)?, s(dst)?]).map(|_| ())
    }

    /// File-level `CoW` clone for the ext4 images used by spaces.
    ///
    /// `--reflink=always` is required: a plain copy would consume the full
    /// image and invalidate exclusive-byte quota accounting.
    pub fn reflink(src: &Path, dst: &Path) -> crate::Result<()> {
        let out = std::process::Command::new("cp")
            .arg("--reflink=always")
            .arg("--")
            .arg(src)
            .arg(dst)
            .output()?;
        if out.status.success() {
            return Ok(());
        }
        Err(crate::Error::Btrfs(format!(
            "cp --reflink=always {} {} failed (is the shinu root on btrfs?): {}",
            src.display(),
            dst.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    /// Clones an image, makes it private, and assigns it to one owner.
    ///
    /// The image contains the guest's keys and credentials, so permission and
    /// ownership are set together; either change alone leaves an access hole.
    pub fn clone_for(src: &Path, dst: &Path, uid: u32, gid: u32) -> crate::Result<()> {
        reflink(src, dst)?;
        // Restrict mode while the file is still owned by root.
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(dst, Some(uid), Some(gid))?;
        Ok(())
    }

    pub fn delete(p: &Path) -> crate::Result<()> {
        if !p.exists() {
            return Ok(());
        }
        run(&["subvolume", "delete", s(p)?]).map(|_| ())
    }

    /// Missing path reports 0, mirroring `delete`'s idempotence: a state row
    /// whose subvolume is already gone must not break a whole listing or gc run.
    pub fn exclusive(p: &Path) -> crate::Result<u64> {
        if !p.exists() {
            return Ok(0);
        }
        let output = run(&["filesystem", "du", "-s", "--raw", s(p)?])?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_du(&stdout)
    }

    fn parse_du(out: &str) -> crate::Result<u64> {
        let line = out
            .lines()
            .filter(|line| !line.trim().is_empty())
            .nth(1)
            .ok_or_else(|| crate::Error::Btrfs("invalid filesystem du output".to_owned()))?;
        let value = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| crate::Error::Btrfs("invalid filesystem du output".to_owned()))?;
        value
            .parse::<u64>()
            .map_err(|error| crate::Error::Btrfs(format!("invalid exclusive size: {error}")))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_du;

        #[test]
        fn parses_exclusive_column() {
            let output = "Total Exclusive \"Set shared\" Filename\nTotal 12345 0 /space\n";
            assert_eq!(parse_du(output).expect("valid du output"), 12345);
        }

        #[test]
        fn rejects_garbage_or_one_line_output() {
            assert!(parse_du("garbage\n").is_err());
            assert!(parse_du("Total Exclusive Filename\n").is_err());
        }
    }
}

/// Resolution order: explicit flag > `$SHINU_ROOT` > [`DEFAULT_ROOT`].
pub fn resolve_root(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    match std::env::var_os("SHINU_ROOT") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_ROOT),
    }
}

/// `<root>/cache` — downloaded rootfs tarballs.
pub fn cache_dir(root: &Path) -> PathBuf {
    root.join("cache")
}

/// The guest distributions supported by the image builder.
///
/// The spelling is part of the API: these ids are persisted in space rows and
/// are used in base-image filenames, so accepting aliases would create two
/// names for the same disk contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Image {
    Void,
    Ubuntu,
    Arch,
    Rocky,
}

impl Image {
    pub const fn all() -> [Self; 4] {
        [Self::Void, Self::Ubuntu, Self::Arch, Self::Rocky]
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Ubuntu => "ubuntu",
            Self::Arch => "arch",
            Self::Rocky => "rocky",
        }
    }
    pub const fn init_path(self) -> &'static str {
        match self {
            Self::Arch => "/usr/lib/systemd/systemd",
            Self::Void | Self::Ubuntu | Self::Rocky => "/sbin/init",
        }
    }
}

impl std::fmt::Display for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

impl std::str::FromStr for Image {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "void" => Ok(Self::Void),
            "ubuntu" => Ok(Self::Ubuntu),
            "arch" => Ok(Self::Arch),
            "rocky" => Ok(Self::Rocky),
            _ => Err(Error::Invalid(format!(
                "unknown image id {value:?}; valid ids: void, ubuntu, arch, rocky"
            ))),
        }
    }
}

/// `<root>/base-<image>.ext4` — the golden guest disk for one distribution.
/// A file, not a subvolume: Firecracker boots a block device.
pub fn base_path(root: &Path, image: Image) -> PathBuf {
    root.join(format!("base-{image}.ext4"))
}

/// Move the pre-multi-image Void base to its explicit image name.
///
/// `rename` is atomic on one filesystem, so a daemon restart cannot expose a
/// partially migrated image. When the destination already exists we leave
/// both files untouched rather than replacing a valid newer base.
pub fn migrate_base(root: &Path) -> Result<()> {
    let legacy = root.join("base.ext4");
    if !legacy.exists() {
        return Ok(());
    }
    let migrated = base_path(root, Image::Void);
    if migrated.exists() {
        return Ok(());
    }
    std::fs::rename(legacy, migrated)?;
    Ok(())
}

pub fn space_image(root: &Path, id: Uuid) -> PathBuf {
    root.join(format!("spaces/{id}.ext4"))
}

fn ckpt_path(root: &Path, id: Uuid, extension: &str) -> PathBuf {
    root.join(format!("ckpts/{id}.{extension}"))
}

pub fn ckpt_image(root: &Path, id: Uuid) -> PathBuf {
    ckpt_path(root, id, "ext4")
}

pub fn ckpt_mem(root: &Path, id: Uuid) -> PathBuf {
    ckpt_path(root, id, "mem")
}

pub fn ckpt_state(root: &Path, id: Uuid) -> PathBuf {
    ckpt_path(root, id, "state")
}

/// `<root>/assets` — the firecracker binary and the guest kernel.
pub fn assets_dir(root: &Path) -> PathBuf {
    root.join("assets")
}

pub fn firecracker_bin(root: &Path) -> PathBuf {
    root.join("assets/firecracker")
}

pub fn jailer_bin(root: &Path) -> PathBuf {
    root.join("assets/jailer")
}

pub fn kernel_path(root: &Path) -> PathBuf {
    root.join("assets/vmlinux")
}

/// `<root>/vm/<space-id>` — the host-side half of one VM's runtime state:
/// `last_used` and the space's own SSH key pair.
///
/// The rest lives inside the jailer chroot ([`vm::jail_root`]): `fc.json`,
/// `fc.sock`, `vsock.sock`, and `firecracker.pid` are all written by a
/// firecracker that has been chrooted and dropped to an unprivileged uid, so
/// they are reachable only through the jail paths. The daemon proxies guest
/// access, so callers never need to traverse either location.
pub fn vm_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join(format!("vm/{id}"))
}

const DAEMON_UID: u32 = 0;
const PROTECTED_LAYOUT_DIRS: [&str; 7] = [
    "spaces",
    "ckpts",
    "vm",
    "assets",
    "cache",
    "jail",
    "jail/firecracker",
];

/// Checks the ownership and permission invariant for a daemon-owned directory.
///
/// This scalar seam is deliberately independent of the host's current uid so
/// tests can exercise the production expected uid without impersonating root.
fn validate_directory_attributes(uid: u32, mode: u32, expected_uid: u32) -> bool {
    uid == expected_uid && mode & 0o022 == 0
}

/// Existing ancestors may be traversed only when an untrusted user cannot
/// replace the established root. A root-owned sticky world-writable directory
/// (for example `/tmp`) is the one intentional exception.
fn validate_ancestor_attributes(uid: u32, mode: u32) -> bool {
    uid == DAEMON_UID && ((mode & 0o022 == 0) || (mode & 0o002 != 0 && mode & 0o1000 != 0))
}

fn validate_directory(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_uid: u32,
    final_component: bool,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(Error::Invalid(format!(
            "daemon directory is a symlink: {}",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(Error::Invalid(format!(
            "daemon directory is not a directory: {}",
            path.display()
        )));
    }
    let safe = if final_component {
        validate_directory_attributes(metadata.uid(), metadata.mode(), expected_uid)
    } else {
        validate_ancestor_attributes(metadata.uid(), metadata.mode())
    };
    if !safe {
        return Err(Error::Invalid(format!(
            "unsafe daemon directory {}: uid {}, mode {:o}",
            path.display(),
            metadata.uid(),
            metadata.mode() & 0o7777
        )));
    }
    Ok(())
}

fn read_or_create_directory(path: &Path) -> Result<std::fs::Metadata> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Start every newly created component private. `init_layout`
            // applies the established public modes only after this walk has
            // proved that the whole path is daemon-owned and stable.
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => Ok(std::fs::symlink_metadata(path)?),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok(std::fs::symlink_metadata(path)?)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Walks a directory path lexically and inspects each component with
/// `symlink_metadata`, never following a link supplied by the caller. Missing
/// components are created one at a time with a private mode and re-inspected.
fn secure_directory_path(path: &Path, expected_uid: u32) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components = absolute.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Invalid(format!(
            "daemon directory contains a parent component: {}",
            path.display()
        )));
    }

    let mut current = PathBuf::from("/");
    let mut saw_normal = false;
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                saw_normal = true;
                current.push(name);
                let last = !components[index + 1..]
                    .iter()
                    .any(|component| matches!(component, Component::Normal(_)));
                let metadata = read_or_create_directory(&current)?;
                validate_directory(&current, &metadata, expected_uid, last)?;
            }
            Component::ParentDir => {
                return Err(Error::Invalid(format!(
                    "daemon directory contains a parent component: {}",
                    path.display()
                )));
            }
            Component::Prefix(_) => {}
        }
    }
    if !saw_normal {
        let metadata = read_or_create_directory(&current)?;
        validate_directory(&current, &metadata, expected_uid, true)?;
    }
    Ok(())
}

/// Establishes the daemon-owned filesystem layout before state or assets are
/// opened. Existing roots and protected directories must be real directories,
/// owned by uid 0, and free of group/other write permission. A root-owned
/// sticky world-writable ancestor such as `/tmp` is allowed; the established
/// root itself is still required to satisfy the stricter invariant.
pub fn init_daemon_layout(root: &Path) -> Result<()> {
    secure_directory_path(root, DAEMON_UID)?;
    for name in PROTECTED_LAYOUT_DIRS {
        secure_directory_path(&root.join(name), DAEMON_UID)?;
    }

    // Keep the existing mode policy in one place, but invoke it only after the
    // path and every protected child have passed the no-follow trust checks.
    init_layout(root)?;

    // Re-read after mode establishment so a future init_layout change cannot
    // silently weaken this boundary.
    secure_directory_path(root, DAEMON_UID)?;
    for name in PROTECTED_LAYOUT_DIRS {
        secure_directory_path(&root.join(name), DAEMON_UID)?;
    }
    Ok(())
}

pub fn init_layout(root: &Path) -> Result<()> {
    // Explicit modes keep host permissions deterministic. The daemon proxies
    // exec, so callers never need to traverse VM or space image directories.
    std::fs::create_dir_all(root)?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))?;
    for (dir, mode) in [
        (root.join("spaces"), 0o700),
        (root.join("ckpts"), 0o700),
        (root.join("vm"), 0o700),
        (assets_dir(root), 0o755),
        (cache_dir(root), 0o755),
        (root.join("jail"), 0o700),
        (root.join("jail/firecracker"), 0o700),
    ] {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Recursive `chown`, shelled out because `std` has no recursive form. Only
/// metadata changes, so a freshly cloned space stays 0 bytes exclusive.
pub fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let output = std::process::Command::new("chown")
        .arg("-R")
        .arg("--")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "chown -R {uid}:{gid} {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// The `shinu-vsock` helper, resolved next to this executable so a build tree
/// and an installed prefix both work without a compiled-in path.
pub fn vsock_helper() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| Error::Invalid("cannot locate own directory".to_owned()))?;
    let helper = dir.join("shinu-vsock");
    if !helper.exists() {
        return Err(Error::Invalid(format!(
            "vsock helper missing: {}",
            helper.display()
        )));
    }
    Ok(helper)
}

/// Renders an argv as a single POSIX shell word list.
///
/// SSH joins its arguments with spaces and lets the remote shell split them.
/// Single quotes have no escapes inside; embedded quotes are closed, escaped,
/// and reopened.
pub fn shell_quote(cmd: &[String]) -> String {
    let mut out = String::new();
    for (index, arg) in cmd.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        append_shell_quote(&mut out, arg);
    }
    out
}

fn append_shell_quote(out: &mut String, argument: &str) {
    out.push('\'');
    for character in argument.chars() {
        if character == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(character);
        }
    }
    out.push('\'');
}

/// Quotes one argument for the remote POSIX shell command line.
///
/// This is the single-word form used when constructing SSH options.
pub fn shell_quote_word(argument: &str) -> String {
    let mut quoted = String::with_capacity(argument.len() + 2);
    append_shell_quote(&mut quoted, argument);
    quoted
}

pub fn avail_bytes(path: &Path) -> Result<u64> {
    let output = std::process::Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(Error::Btrfs(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(1)
        .ok_or_else(|| Error::Invalid("invalid df output".to_owned()))?
        .trim();
    value
        .parse::<u64>()
        .map_err(|error| Error::Invalid(format!("invalid available byte count: {error}")))
}

#[cfg(test)]
mod layout_tests {
    use super::{init_daemon_layout, validate_ancestor_attributes, validate_directory_attributes};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("shinu-layout-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn rejects_a_symlink_root_before_following_its_target() {
        let root = test_root("symlink");
        symlink("/tmp", &root).expect("create root symlink");

        let result = init_daemon_layout(&root);

        assert!(matches!(result, Err(super::Error::Invalid(_))));
        std::fs::remove_file(root).expect("remove fixture symlink");
    }

    #[test]
    fn directory_validation_rejects_wrong_uid_and_group_write() {
        assert!(validate_directory_attributes(0, 0o755, 0));
        assert!(!validate_directory_attributes(1000, 0o755, 0));
        assert!(!validate_directory_attributes(0, 0o775, 0));
    }

    #[test]
    fn only_a_root_owned_sticky_world_writable_ancestor_is_excepted() {
        assert!(validate_ancestor_attributes(0, 0o1777));
        assert!(!validate_ancestor_attributes(0, 0o0777));
        assert!(!validate_ancestor_attributes(1000, 0o1777));
        assert!(validate_ancestor_attributes(0, 0o755));
    }
}

#[cfg(test)]
mod quote_tests {
    use super::shell_quote;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn keeps_a_multi_word_argument_as_one_word() {
        assert_eq!(
            shell_quote(&argv(&["sh", "-c", "echo a; echo b"])),
            "'sh' '-c' 'echo a; echo b'"
        );
    }

    #[test]
    fn neutralises_metacharacters_and_embedded_quotes() {
        assert_eq!(shell_quote(&argv(&["echo", "$HOME"])), "'echo' '$HOME'");
        assert_eq!(shell_quote(&argv(&["echo", "a'b"])), "'echo' 'a'\\''b'");
        assert_eq!(
            shell_quote(&argv(&["rm", "-rf", "/ ; reboot"])),
            "'rm' '-rf' '/ ; reboot'"
        );
    }

    #[test]
    fn preserves_an_empty_argument() {
        assert_eq!(shell_quote(&argv(&["test", ""])), "'test' ''");
    }
}

// Shared IPv4 parsing and guest-destination predicates. Keeping them here
// gives the image and VM crates one validation rule.
pub fn parse_net_base(value: &str) -> Option<[u8; 2]> {
    let mut octets = value.trim().split('.');
    let first = octets.next()?.parse::<u8>().ok()?;
    let second = octets.next()?.parse::<u8>().ok()?;
    octets.next().is_none().then_some([first, second])
}

pub fn parse_ipv4(value: &str) -> Option<[u8; 4]> {
    let mut octets = value.trim().split('.');
    let address = [
        octets.next()?.parse::<u8>().ok()?,
        octets.next()?.parse::<u8>().ok()?,
        octets.next()?.parse::<u8>().ok()?,
        octets.next()?.parse::<u8>().ok()?,
    ];
    octets.next().is_none().then_some(address)
}

pub fn parse_ipv4_cidr(value: &str) -> Option<([u8; 4], u8)> {
    let (address, prefix) = value.trim().split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    let address = parse_ipv4(address)?;
    (prefix <= 32).then_some((address, prefix))
}

fn is_rfc1918_octets(address: [u8; 4]) -> bool {
    match address {
        [10, ..] | [192, 168, ..] => true,
        [172, second, ..] => (16..=31).contains(&second),
        _ => false,
    }
}

/// Returns whether an IPv4 address is in one of the three RFC1918 ranges.
/// Link-local and loopback addresses are deliberately handled separately:
/// they are not RFC1918, but are blocked by the guest egress policy too.
pub fn is_rfc1918(address: &str) -> bool {
    parse_ipv4(address).is_some_and(is_rfc1918_octets)
}

pub fn is_blocked_guest_destination(address: &str) -> bool {
    parse_ipv4(address).is_some_and(|address| {
        is_rfc1918_octets(address) || matches!(address, [127, ..] | [169, 254, ..])
    })
}

pub const GUEST_BLOCKED_CIDRS: [&str; 5] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
];

/// Reads a positive `u32` environment setting, using `default` for missing,
/// blank, zero, or invalid values.
pub fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod address_tests {
    use super::is_rfc1918;

    #[test]
    fn rfc1918_boundaries_are_precise() {
        assert!(is_rfc1918("10.1.2.3"));
        assert!(is_rfc1918("172.16.0.1"));
        assert!(is_rfc1918("172.31.255.254"));
        assert!(is_rfc1918("192.168.1.1"));
        assert!(!is_rfc1918("8.8.8.8"));
        assert!(!is_rfc1918("172.15.255.255"));
        assert!(!is_rfc1918("172.32.0.1"));
    }
}
