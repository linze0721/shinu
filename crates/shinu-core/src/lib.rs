use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use uuid::Uuid;

pub const DEFAULT_ROOT: &str = "/var/lib/shinu";

pub const FC_VERSION: &str = "v1.13.1";
pub const FC_URL: &str = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.13.1/firecracker-v1.13.1-x86_64.tgz";
/// Firecracker's CI kernel: an uncompressed 6.1.141 vmlinux with virtio-blk,
/// virtio-vsock and ext4 built in (`=y`), which is what booting without an
/// initrd requires. The host kernel cannot stand in for it — this host builds
/// those as modules.
pub const KERNEL_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141";
/// Guest vsock port the in-VM socat bridge listens on; forwarded to sshd.
pub const VSOCK_SSH_PORT: u16 = 2222;
/// GUI VNC uses a separate vsock connection because each Firecracker vsock
/// connection carries one `CONNECT <port>` request.
pub const VSOCK_VNC_PORT: u16 = 2223;
/// Raw uploads use a separate cap because they stream bytes instead of the 1 MiB JSON body.
pub const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Seconds between idle-sweep passes.
///
/// The sweep both meters usage and reclaims disk, so the same period defines
/// how much time one recorded sample represents. Metering and the daemon loop
/// must not drift apart, which is why the value lives here rather than beside
/// the `thread::sleep` that consumes it.
pub const USAGE_SAMPLE_SECS: u64 = 30;

#[derive(Debug)]
pub enum Error {
    Btrfs(String),
    NotFound(String),
    Invalid(String),
    Auth(String),
    Quota(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Btrfs(message) => write!(f, "btrfs: {message}"),
            Error::NotFound(message) => write!(f, "not found: {message}"),
            Error::Invalid(message) => write!(f, "invalid: {message}"),
            Error::Auth(message) => write!(f, "auth: {message}"),
            Error::Quota(message) => write!(f, "quota: {message}"),
            Error::Io(error) => write!(f, "{error}"),
            Error::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

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

// The store crate cannot own this: `Error` is foreign to it, so the orphan
// rule rejects the impl there. Keeping it beside the error type also keeps
// every `?` on a rusqlite call working without a per-callsite adapter.
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Invalid(format!("sql: {error}"))
    }
}

pub mod btrfs {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn run(args: &[&str]) -> crate::Result<String> {
        let out = std::process::Command::new("btrfs").args(args).output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(crate::Error::Btrfs(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
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

    /// File-level CoW clone. Subvolume snapshots only apply to directories,
    /// and a space is now a single ext4 image, so `cp --reflink=always` is
    /// what keeps a clone 0 bytes exclusive.
    ///
    /// Never falls back to a plain copy: a silent full copy would make every
    /// space really occupy the whole image size and destroy the CoW premise
    /// the budget accounting in `gc` rests on. Failing loudly says the root is
    /// not on btrfs/xfs, which is a configuration error, not a slow path.
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

    /// Clones an image and hands it to one owner, private.
    ///
    /// Ownership and permission are set together on purpose. A space image is
    /// the guest's entire disk — every file, key and credential inside it —
    /// so `cp` leaving it world-readable at 0644 exposed one user's whole
    /// filesystem to every other user on the host, straight past the
    /// owner-scoped API checks (measured: an unprivileged user could read
    /// another's image byte for byte). Setting only the owner, or only the
    /// mode, still leaves that hole open, so neither is offered separately.
    pub fn clone_for(src: &Path, dst: &Path, uid: u32, gid: u32) -> crate::Result<()> {
        reflink(src, dst)?;
        // Mode before owner: while the file still belongs to root, nobody else
        // can open it, so there is no window where it is both readable and
        // owned by someone who should not have it.
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
        parse_du(&run(&["filesystem", "du", "-s", "--raw", s(p)?])?)
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
    let migrated = base_path(root, Image::Void);
    if !legacy.exists() || migrated.exists() {
        return Ok(());
    }
    std::fs::rename(legacy, migrated)?;
    Ok(())
}

pub fn space_image(root: &Path, id: Uuid) -> PathBuf {
    root.join("spaces").join(format!("{id}.ext4"))
}

pub fn ckpt_image(root: &Path, id: Uuid) -> PathBuf {
    root.join("ckpts").join(format!("{id}.ext4"))
}

pub fn ckpt_mem(root: &Path, id: Uuid) -> PathBuf {
    root.join("ckpts").join(format!("{id}.mem"))
}

pub fn ckpt_state(root: &Path, id: Uuid) -> PathBuf {
    root.join("ckpts").join(format!("{id}.state"))
}

/// `<root>/assets` — the firecracker binary and the guest kernel.
pub fn assets_dir(root: &Path) -> PathBuf {
    root.join("assets")
}

pub fn firecracker_bin(root: &Path) -> PathBuf {
    assets_dir(root).join("firecracker")
}

pub fn jailer_bin(root: &Path) -> PathBuf {
    assets_dir(root).join("jailer")
}

pub fn kernel_path(root: &Path) -> PathBuf {
    assets_dir(root).join("vmlinux")
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
    root.join("vm").join(id.to_string())
}

pub fn init_layout(root: &Path) -> Result<()> {
    // Explicit modes keep host permissions deterministic. The daemon proxies
    // exec, so callers never need to traverse VM or space image directories.
    for (dir, mode) in [
        (root.to_path_buf(), 0o755),
        (root.join("spaces"), 0o700),
        (root.join("ckpts"), 0o700),
        (root.join("vm"), 0o700),
        (assets_dir(root), 0o755),
        (cache_dir(root), 0o755),
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
/// SSH does not carry an argument vector: it joins whatever it is given with
/// spaces and hands the result to the remote user's shell, which splits it
/// again. Passing argv straight through therefore loses the boundaries —
/// `sh -c 'echo a; echo b'` arrives as four words and the guest shell runs
/// something else entirely. Quoting here restores exactly the argv the caller
/// passed, matching what the old chroot path did by never leaving the process.
///
/// Single quotes are the only POSIX construct with no escapes at all inside,
/// so an embedded `'` is emitted as `'\''`: close, escaped quote, reopen.
/// This is security-critical: SSH receives a remote command line rather than
/// an argument vector, so every argument must be quoted before it crosses that boundary.
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


// Address predicates shared by image resolver repair and VM egress rules.
// Pure string arithmetic with no VM or image dependency, so they sit below
// both crates rather than being duplicated into each.
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

/// Returns whether an IPv4 address is in one of the three RFC1918 ranges.
/// Link-local and loopback addresses are deliberately handled separately:
/// they are not RFC1918, but are blocked by the guest egress policy too.
pub fn is_rfc1918(address: &str) -> bool {
    match parse_ipv4(address) {
        Some([10, ..]) | Some([192, 168, ..]) => true,
        Some([172, second, ..]) => (16..=31).contains(&second),
        _ => false,
    }
}

pub fn is_blocked_guest_destination(address: &str) -> bool {
    if is_rfc1918(address) {
        return true;
    }
    matches!(parse_ipv4(address), Some([127, ..]) | Some([169, 254, ..]))
}

pub const GUEST_BLOCKED_CIDRS: [&str; 5] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
];

// Env parsing used by both VmConfig and the image builder's disk sizing.
// A single reader keeps one spelling of "invalid value falls back to the
// default" instead of two that can drift apart.
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
