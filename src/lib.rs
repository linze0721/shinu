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

#[derive(Debug)]
pub enum Error {
    Btrfs(String),
    NotFound(String),
    Invalid(String),
    Auth(String),
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

pub mod state {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use uuid::Uuid;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Space {
        pub id: Uuid,
        pub name: String,
        pub project: String,
        pub parent: Option<Uuid>,
        #[serde(default)]
        pub head: Option<Uuid>,
        pub created_at: DateTime<Utc>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct Ckpt {
        pub id: Uuid,
        pub space: Uuid,
        #[serde(default)]
        pub project: String,
        #[serde(default)]
        pub parent: Option<Uuid>,
        #[serde(default)]
        pub auto: bool,
        pub note: String,
        pub created_at: DateTime<Utc>,
    }

    #[derive(Serialize, Deserialize, Default, Debug)]
    pub struct State {
        pub spaces: Vec<Space>,
        pub ckpts: Vec<Ckpt>,
    }

    impl State {
        pub fn load(root: &Path) -> crate::Result<State> {
            let path = root.join("state.json");
            match std::fs::read_to_string(path) {
                Ok(contents) => Ok(serde_json::from_str(&contents)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
                Err(error) => Err(error.into()),
            }
        }

        pub fn store(&self, root: &Path) -> crate::Result<()> {
            let contents = serde_json::to_string_pretty(self)?;
            let tmp = root.join("state.json.tmp");
            std::fs::write(&tmp, contents)?;
            std::fs::rename(tmp, root.join("state.json"))?;
            Ok(())
        }
    }
}
/// Coordination locks for concurrent operations on spaces and the state file.
///
/// Long-running operations acquire the space lock first and the state lock
/// second; this fixed order prevents deadlocks between connections. The state
/// lock is held only across `State::load`, the in-memory change, and
/// `State::store`, never across a btrfs or VM operation. Poisoning is recovered
/// with `into_inner`: these locks serialize state-file access rather than guard
/// an in-memory invariant, so continuing after a panicking connection is safe.
pub mod registry {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    pub struct Registry {
        state: Mutex<()>,
        spaces: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    }

    impl Registry {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(()),
                spaces: Mutex::new(HashMap::new()),
            }
        }

        pub fn space_lock(&self, id: Uuid) -> Arc<Mutex<()>> {
            let mut spaces = self.spaces.lock().unwrap_or_else(|error| error.into_inner());
            spaces
                .entry(id)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        }

        pub fn state_lock(&self) -> &Mutex<()> {
            &self.state
        }
    }

    impl Default for Registry {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Project bearer-token persistence and authentication.
///
/// Only SHA-256 hashes are stored in `<root>/tokens.json`; the plaintext token
/// exists only in the value returned by [`mint`]. Hashes are compared in fixed
/// time so a caller cannot use response timing to learn a stored token.
pub mod token {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Token {
        pub hash: String,
        pub project: String,
        pub created_at: DateTime<Utc>,
    }

    pub fn load(root: &Path) -> crate::Result<Vec<Token>> {
        let path = root.join("tokens.json");
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn store(root: &Path, tokens: &[Token]) -> crate::Result<()> {
        let contents = serde_json::to_string_pretty(tokens)?;
        let tmp = root.join("tokens.json.tmp");
        std::fs::write(&tmp, contents)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(tmp, root.join("tokens.json"))?;
        Ok(())
    }

    pub fn mint() -> crate::Result<String> {
        let mut bytes = [0_u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let mut token = String::with_capacity(64);
        for byte in bytes {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Ok(token)
    }

    fn sha256_stdin(plain: &str) -> crate::Result<String> {
        let mut child = Command::new("sha256sum")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            crate::Error::Invalid("sha256sum stdin unavailable".to_owned())
        })?;
        stdin.write_all(plain.as_bytes())?;
        drop(stdin);

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(crate::Error::Invalid(format!(
                "sha256sum failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| crate::Error::Invalid("empty sha256sum output".to_owned()))
    }

    pub fn hash(plain: &str) -> String {
        sha256_stdin(plain).unwrap_or_else(|error| panic!("sha256sum failed: {error}"))
    }

    fn constant_time_eq(left: &str, right: &str) -> bool {
        let left = left.as_bytes();
        let right = right.as_bytes();
        let mut difference = left.len() ^ right.len();
        for index in 0..64 {
            let a = left.get(index).copied().unwrap_or(0);
            let b = right.get(index).copied().unwrap_or(0);
            difference |= usize::from(a ^ b);
        }
        difference == 0
    }

    pub fn authenticate(tokens: &[Token], plain: &str) -> crate::Result<String> {
        let digest = hash(plain);
        for token in tokens {
            // `==` can stop at the first differing byte and expose hash
            // prefixes through timing; the fixed-length XOR comparison does
            // all 64 byte comparisons before checking the accumulated result.
            if constant_time_eq(&digest, &token.hash) {
                return Ok(token.project.clone());
            }
        }
        Err(crate::Error::Auth("invalid token".into()))
    }

    #[cfg(test)]
    mod token_tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use uuid::Uuid;

        fn test_root(label: &str) -> PathBuf {
            let root = std::env::temp_dir().join(format!("shinu-token-{label}-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&root).expect("create token test root");
            root
        }

        #[test]
        fn mint_returns_distinct_lowercase_hex_tokens() {
            let first = mint().expect("mint first token");
            let second = mint().expect("mint second token");
            assert_eq!(first.len(), 64);
            assert_eq!(second.len(), 64);
            assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            assert!(second.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            assert_ne!(first, second);
        }

        #[test]
        fn hash_is_stable_and_input_sensitive() {
            assert_eq!(hash("stable"), hash("stable"));
            assert_ne!(hash("stable"), hash("different"));
        }

        #[test]
        fn authenticate_returns_matching_project() {
            let plain = "token-for-web";
            let tokens = vec![Token {
                hash: hash(plain),
                project: "web".into(),
                created_at: Utc::now(),
            }];
            assert_eq!(authenticate(&tokens, plain).expect("authenticate"), "web");
        }

        #[test]
        fn authenticate_rejects_unknown_token() {
            let tokens = vec![Token {
                hash: hash("known"),
                project: "web".into(),
                created_at: Utc::now(),
            }];
            assert!(matches!(
                authenticate(&tokens, "unknown"),
                Err(crate::Error::Auth(message)) if message == "invalid token"
            ));
        }

        #[test]
        fn store_and_load_round_trip_tokens() {
            let root = test_root("round-trip");
            let tokens = vec![Token {
                hash: hash("round-trip-token"),
                project: "project-a".into(),
                created_at: Utc::now(),
            }];
            store(&root, &tokens).expect("store tokens");
            let loaded = load(&root).expect("load tokens");
            assert_eq!(loaded, tokens);
            let mode = std::fs::metadata(root.join("tokens.json"))
                .expect("token metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            std::fs::remove_dir_all(root).expect("remove token test root");
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

/// `<root>/base.ext4` — the golden guest disk image every space is cloned
/// from. A file, not a subvolume: Firecracker boots a block device.
pub fn base_path(root: &Path) -> PathBuf {
    root.join("base.ext4")
}

pub fn space_image(root: &Path, id: Uuid) -> PathBuf {
    root.join("spaces").join(format!("{id}.ext4"))
}

pub fn ckpt_image(root: &Path, id: Uuid) -> PathBuf {
    root.join("ckpts").join(format!("{id}.ext4"))
}

/// `<root>/assets` — the firecracker binary and the guest kernel.
pub fn assets_dir(root: &Path) -> PathBuf {
    root.join("assets")
}

pub fn firecracker_bin(root: &Path) -> PathBuf {
    assets_dir(root).join("firecracker")
}

pub fn kernel_path(root: &Path) -> PathBuf {
    assets_dir(root).join("vmlinux")
}

/// `<root>/vm/<space-id>` — one VM's runtime state: `fc.json`, `fc.sock`,
/// `vsock.sock`, `fc.pid`, `last_used`, and the space's own SSH key pair.
/// The daemon proxies guest access, so callers never need to traverse this path.
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

/// Where the guest rootfs comes from. Read from the environment so no config
/// file format has to exist.
#[derive(Debug, Clone)]
pub struct BaseConfig {
    /// `SHINU_ROOTFS_TARBALL` — a local tarball, for hosts with no network.
    pub tarball: Option<PathBuf>,
    /// `SHINU_MIRROR`
    pub mirror: String,
    /// `SHINU_ARCH`, defaulting to `uname -m`.
    pub arch: String,
}

impl BaseConfig {
    pub fn from_env() -> Result<Self> {
        let arch = match std::env::var("SHINU_ARCH") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
            _ => uname_machine()?,
        };
        Ok(Self {
            tarball: std::env::var_os("SHINU_ROOTFS_TARBALL")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            mirror: match std::env::var("SHINU_MIRROR") {
                Ok(value) if !value.trim().is_empty() => {
                    value.trim().trim_end_matches('/').to_owned()
                }
                _ => "https://repo-default.voidlinux.org".to_owned(),
            },
            arch,
        })
    }

    fn index_url(&self) -> String {
        format!("{}/live/current/", self.mirror)
    }
}

fn uname_machine() -> Result<String> {
    let output = std::process::Command::new("uname").arg("-m").output()?;
    if !output.status.success() {
        return Err(Error::Invalid("uname -m failed".to_owned()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn curl_text(url: &str) -> Result<String> {
    let output = std::process::Command::new("curl")
        .args(["-sSf", "--max-time", "60", url])
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "fetch failed ({url}): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Newest `void-<arch>-ROOTFS-<date>.tar.xz` in the directory index.
///
/// The musl variants share the prefix, so they are filtered out explicitly:
/// the glibc image is what the rest of this tool assumes. Names are fixed
/// width apart from the date, so lexicographic max is date max.
fn pick_tarball_name(index: &str, arch: &str) -> Result<String> {
    let prefix = format!("void-{arch}-ROOTFS-");
    let musl = format!("void-{arch}-musl-ROOTFS-");
    let mut best: Option<&str> = None;
    for token in index.split(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c))) {
        if !token.starts_with(&prefix) || token.starts_with(&musl) || !token.ends_with(".tar.xz") {
            continue;
        }
        if best.is_none_or(|current| token > current) {
            best = Some(token);
        }
    }
    best.map(str::to_owned)
        .ok_or_else(|| Error::Invalid(format!("no {prefix}*.tar.xz in mirror index for {arch}")))
}

/// Void publishes BSD-style digests: `SHA256 (<file>) = <hex>`.
fn pick_sha256(list: &str, name: &str) -> Result<String> {
    let needle = format!("({name})");
    list.lines()
        .find(|line| line.contains(&needle))
        .and_then(|line| line.rsplit('=').next())
        .map(|hex| hex.trim().to_owned())
        .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Invalid(format!("no sha256 digest published for {name}")))
}

#[cfg(test)]
mod base_tests {
    use super::{pick_sha256, pick_tarball_name};

    /// Shape copied from the live mirror index.
    const INDEX: &str = r#"<a href="void-x86_64-ROOTFS-20240314.tar.xz">void-x86_64-ROOTFS-20240314.tar.xz</a>
<a href="void-x86_64-ROOTFS-20250202.tar.xz">void-x86_64-ROOTFS-20250202.tar.xz</a>
<a href="void-x86_64-musl-ROOTFS-20250202.tar.xz">void-x86_64-musl-ROOTFS-20250202.tar.xz</a>
<a href="void-aarch64-ROOTFS-20250202.tar.xz">void-aarch64-ROOTFS-20250202.tar.xz</a>"#;

    #[test]
    fn picks_newest_glibc_image_for_the_arch() {
        assert_eq!(
            pick_tarball_name(INDEX, "x86_64").expect("x86_64 image"),
            "void-x86_64-ROOTFS-20250202.tar.xz"
        );
        assert_eq!(
            pick_tarball_name(INDEX, "aarch64").expect("aarch64 image"),
            "void-aarch64-ROOTFS-20250202.tar.xz"
        );
    }

    #[test]
    fn rejects_arch_with_no_image() {
        assert!(pick_tarball_name(INDEX, "riscv64").is_err());
    }

    #[test]
    fn reads_bsd_style_digest_for_the_exact_file() {
        let list = "SHA256 (void-x86_64-musl-ROOTFS-20250202.tar.xz) = 8f66e05401a953d151b3e82d132437840e0b24a51edff27f13202c9010dfa27d\nSHA256 (void-x86_64-ROOTFS-20250202.tar.xz) = 3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876\n";
        assert_eq!(
            pick_sha256(list, "void-x86_64-ROOTFS-20250202.tar.xz").expect("digest"),
            "3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876"
        );
    }

    #[test]
    fn rejects_missing_or_malformed_digest() {
        let list = "SHA256 (other.tar.xz) = deadbeef\n";
        assert!(pick_sha256(list, "void-x86_64-ROOTFS-20250202.tar.xz").is_err());
        assert!(pick_sha256("SHA256 (x.tar.xz) = nothex\n", "x.tar.xz").is_err());
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let output = std::process::Command::new("sha256sum").arg(path).output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid("empty sha256sum output".to_owned()))
}

/// Returns a verified tarball path, downloading into `<root>/cache` only when
/// the cached copy is absent or fails its digest.
fn fetch_tarball(root: &Path, cfg: &BaseConfig) -> Result<PathBuf> {
    if let Some(path) = &cfg.tarball {
        if !path.exists() {
            return Err(Error::Invalid(format!(
                "SHINU_ROOTFS_TARBALL does not exist: {}",
                path.display()
            )));
        }
        return Ok(path.clone());
    }

    let index = curl_text(&cfg.index_url())?;
    let name = pick_tarball_name(&index, &cfg.arch)?;
    let digest = pick_sha256(
        &curl_text(&format!("{}sha256sum.txt", cfg.index_url()))?,
        &name,
    )?;

    let cache = cache_dir(root);
    std::fs::create_dir_all(&cache)?;
    let target = cache.join(&name);
    if target.exists() && sha256_file(&target)? == digest {
        return Ok(target);
    }

    // Download to a sibling temp name so an interrupted transfer can never be
    // mistaken for a cached image on the next run.
    let tmp = cache.join(format!("{name}.part"));
    let _ = std::fs::remove_file(&tmp);
    let status = std::process::Command::new("curl")
        .args(["-sSfL", "--max-time", "1800", "-o"])
        .arg(&tmp)
        .arg(format!("{}{name}", cfg.index_url()))
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Invalid(format!("download failed: {name}")));
    }
    let actual = sha256_file(&tmp)?;
    if actual != digest {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Invalid(format!(
            "sha256 mismatch for {name}: expected {digest}, got {actual}"
        )));
    }
    std::fs::rename(&tmp, &target)?;
    Ok(target)
}

/// Firecracker ships BSD-less `sha256sum` style digests inside the release
/// tarball: `<hex>  ./<file>`.
fn pick_sums_digest(list: &str, name: &str) -> Result<String> {
    list.lines()
        .find_map(|line| {
            let (hex, file) = line.split_once(char::is_whitespace)?;
            (file.trim().trim_start_matches("./") == name).then(|| hex.trim().to_owned())
        })
        .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Invalid(format!("no sha256 digest published for {name}")))
}

#[cfg(test)]
mod sums_tests {
    use super::pick_sums_digest;

    /// Shape copied from the v1.13.1 release tarball's SHA256SUMS.
    const SUMS: &str = "1111111111111111111111111111111111111111111111111111111111111111  ./jailer-v1.13.1-x86_64\n2222222222222222222222222222222222222222222222222222222222222222  ./firecracker-v1.13.1-x86_64\n";

    #[test]
    fn reads_digest_for_the_exact_member() {
        assert_eq!(
            pick_sums_digest(SUMS, "firecracker-v1.13.1-x86_64").expect("digest"),
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn rejects_missing_or_malformed_digest() {
        assert!(pick_sums_digest(SUMS, "seccompiler-bin").is_err());
        assert!(pick_sums_digest("nothex  ./x\n", "x").is_err());
    }
}

/// Download to `<dst>.part` and rename on success, the same anti-truncation
/// rule [`fetch_tarball`] uses: a half-transferred file must never be mistaken
/// for a finished one.
fn curl_to_file(url: &str, dst: &Path) -> Result<()> {
    let tmp = dst.with_extension("part");
    let _ = std::fs::remove_file(&tmp);
    let status = std::process::Command::new("curl")
        .args(["-sSfL", "--max-time", "1800", "-o"])
        .arg(&tmp)
        .arg(url)
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Invalid(format!("download failed: {url}")));
    }
    std::fs::rename(&tmp, dst)?;
    Ok(())
}

fn install_firecracker(root: &Path, dst: &Path) -> Result<()> {
    let cache = cache_dir(root);
    std::fs::create_dir_all(&cache)?;
    let tarball = cache.join(format!("firecracker-{FC_VERSION}-x86_64.tgz"));
    if !tarball.exists() {
        curl_to_file(FC_URL, &tarball)?;
    }

    let unpack = assets_dir(root).join(".unpack");
    let _ = std::fs::remove_dir_all(&unpack);
    std::fs::create_dir_all(&unpack)?;
    let result = (|| -> Result<()> {
        let output = std::process::Command::new("tar")
            .arg("-xzf")
            .arg(&tarball)
            .arg("-C")
            .arg(&unpack)
            .arg("--strip-components=1")
            .output()?;
        if !output.status.success() {
            return Err(Error::Invalid(format!(
                "extracting {} failed: {}",
                tarball.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        // The release carries its own SHA256SUMS, so the binary that is about
        // to be given KVM is verified against a digest shipped beside it
        // rather than trusted on transport alone.
        let member = format!("firecracker-{FC_VERSION}-x86_64");
        let digest = pick_sums_digest(
            &std::fs::read_to_string(unpack.join("SHA256SUMS"))?,
            &member,
        )?;
        let binary = unpack.join(&member);
        let actual = sha256_file(&binary)?;
        if actual != digest {
            return Err(Error::Invalid(format!(
                "sha256 mismatch for {member}: expected {digest}, got {actual}"
            )));
        }
        let staged = dst.with_extension("part");
        std::fs::copy(&binary, &staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staged, dst)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&unpack);
    result
}

/// Fetches the hypervisor and guest kernel once. Called before `ensure_base`
/// so a host with no network fails immediately rather than after building an
/// image it cannot boot.
pub fn ensure_assets(root: &Path) -> Result<()> {
    std::fs::create_dir_all(assets_dir(root))?;
    let fc = firecracker_bin(root);
    if !fc.exists() {
        install_firecracker(root, &fc)?;
    }
    let kernel = kernel_path(root);
    if !kernel.exists() {
        // No digest channel exists for this object (S3 publishes only a
        // multipart ETag, which is not the file's sha256), so HTTPS origin
        // trust is all there is — the same trade-off already made for the
        // unsigned rootfs tarball.
        curl_to_file(KERNEL_URL, &kernel)?;
    }
    Ok(())
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Per-VM sizing and lifetime, read from the environment like [`BaseConfig`].
#[derive(Debug, Clone, Copy)]
pub struct VmConfig {
    /// `SHINU_VCPUS`
    pub vcpus: u32,
    /// `SHINU_MEM_MIB`
    pub mem_mib: u32,
    /// `SHINU_IDLE_SECS` — a VM with no `Touch` for this long is shut down.
    pub idle_secs: u64,
}

impl VmConfig {
    pub fn from_env() -> Self {
        Self {
            vcpus: env_u32("SHINU_VCPUS", 2),
            mem_mib: env_u32("SHINU_MEM_MIB", 1024),
            idle_secs: u64::from(env_u32("SHINU_IDLE_SECS", 600)),
        }
    }
}
/// A private /30 network for each VM. The host owns `.1`, the guest `.2`.
///
/// The pool is intentionally part of the daemon configuration rather than a
/// per-space setting: deterministic addresses make restart idempotent, while
/// rejecting occupied host addresses keeps two VMs from sharing a subnet.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// `SHINU_NET_ENABLE` — "0" and "false" disable guest networking.
    pub enabled: bool,
    /// `SHINU_NET_BASE` — the first two octets of the /16 pool.
    pub base: [u8; 2],
    /// `SHINU_NET_UPLINK` — host interface used for NAT egress.
    pub uplink: String,
}

fn parse_net_base(value: &str) -> Option<[u8; 2]> {
    let mut octets = value.trim().split('.');
    let first = octets.next()?.parse::<u8>().ok()?;
    let second = octets.next()?.parse::<u8>().ok()?;
    octets.next().is_none().then_some([first, second])
}

fn default_uplink() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    output
        .stdout
        .split(|byte| *byte == b' ' || *byte == b'\n' || *byte == b'\t')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .windows(2)
        .find(|tokens| tokens[0] == b"dev")
        .map(|tokens| String::from_utf8_lossy(tokens[1]).into_owned())
}

impl NetConfig {
    pub fn from_env() -> Result<Self> {
        let enabled = !std::env::var("SHINU_NET_ENABLE")
            .ok()
            .is_some_and(|value| {
                let value = value.trim();
                value == "0" || value.eq_ignore_ascii_case("false")
            });
        let base = match std::env::var("SHINU_NET_BASE") {
            Ok(value) => parse_net_base(&value).ok_or_else(|| {
                Error::Invalid(format!(
                    "invalid SHINU_NET_BASE={value:?}; expected two octets such as 172.31"
                ))
            })?,
            Err(_) => [172, 31],
        };
        let uplink = match std::env::var("SHINU_NET_UPLINK") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
            _ if enabled => default_uplink().ok_or_else(|| {
                Error::Invalid(
                    "cannot determine the default uplink; set SHINU_NET_UPLINK".to_owned(),
                )
            })?,
            _ => String::new(),
        };
        Ok(Self {
            enabled,
            base,
            uplink,
        })
    }
}

/// Returns the third octet and /30-aligned fourth-octet base for a space.
/// Fourteen UUID bits provide 16,384 disjoint /30s without a mutable allocator.
pub fn net_slot(id: Uuid) -> (u8, u8) {
    let bytes = id.as_bytes();
    let index = u16::from_be_bytes([bytes[0], bytes[1]]) & 0x3fff;
    ((index >> 6) as u8, ((index & 0x3f) << 2) as u8)
}

/// Linux interface names have fifteen usable bytes; the ten hex characters
/// after `shinu` leave no room for the kernel's terminating byte.
pub fn tap_name(id: Uuid) -> String {
    format!("shinu{}", &id.simple().to_string()[..10])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSpec {
    pub tap: String,
    pub mac: String,
    pub guest_cidr: String,
    pub gateway: String,
}

/// Derives every guest-facing network value from one UUID and one pool config.
/// Keeping this as one constructor prevents a tap, MAC, and kernel address from
/// silently referring to different spaces after a restart.
pub fn net_spec(id: Uuid, cfg: &NetConfig) -> Option<NetSpec> {
    if !cfg.enabled {
        return None;
    }
    let (third, fourth_base) = net_slot(id);
    let host = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 1
    );
    let guest = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 2
    );
    let bytes = id.as_bytes();
    Some(NetSpec {
        tap: tap_name(id),
        mac: format!(
            "AA:FC:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ),
        guest_cidr: format!("{guest}/30"),
        gateway: host,
    })
}

/// Firecracker's `--config-file` body. `root=/dev/vda rw init=/sbin/init`
/// boots the ext4 image directly with no initrd, which is why the guest
/// kernel must have virtio-blk and ext4 built in.
pub fn vm_config_json(
    kernel: &Path,
    rootfs: &Path,
    vsock_uds: &Path,
    vcpus: u32,
    mem_mib: u32,
    net: Option<&NetSpec>,
) -> String {
    let mut boot_args =
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/init".to_owned();
    if let Some(net) = net {
        boot_args.push_str(" shinu.ip=");
        boot_args.push_str(&net.guest_cidr);
        boot_args.push_str(" shinu.gw=");
        boot_args.push_str(&net.gateway);
    }
    let mut config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": kernel.to_string_lossy(),
            "boot_args": boot_args
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": rootfs.to_string_lossy(),
            "is_root_device": true,
            "is_read_only": false
        }],
        // Every VM owns a private vsock UDS, so the guest CID never has to be
        // unique across VMs.
        "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": vsock_uds.to_string_lossy() },
        // Balloon starts empty and only ever inflates while the VM sits idle.
        // `deflate_on_oom` is what makes that safe: if the guest needs the
        // memory back before the daemon deflates, the balloon yields instead
        // of letting the OOM killer run.
        "balloon": { "amount_mib": 0, "deflate_on_oom": true, "stats_polling_interval_s": 1 },
        "machine-config": { "vcpu_count": vcpus, "mem_size_mib": mem_mib }
    });
    if let Some(net) = net {
        config["network-interfaces"] = serde_json::json!([{
            "iface_id": "eth0",
            "host_dev_name": net.tap,
            "guest_mac": net.mac,
        }]);
    }
    config.to_string()
}

#[cfg(test)]
mod network_tests {
    use super::{NetSpec, net_slot, tap_name, vm_config_json};
    use serde_json::Value;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn derives_disjoint_addresses_inside_one_slash_thirty() {
        let id = Uuid::from_bytes([
            0xab, 0xcd, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let (third, fourth_base) = net_slot(id);
        assert_eq!(fourth_base, 52);
        let host = fourth_base + 1;
        let guest = fourth_base + 2;
        assert_eq!(guest - host, 1);
        assert!(host > fourth_base && guest < fourth_base + 4);
        assert_eq!(third, 175);
    }

    #[test]
    fn tap_names_fit_linux_and_include_uuid_identity() {
        let first = tap_name(Uuid::from_bytes([
            0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let second = tap_name(Uuid::from_bytes([
            0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        assert_eq!(first.len(), 15);
        assert_eq!(second.len(), 15);
        assert_ne!(first, second);
    }

    #[test]
    fn vm_config_without_network_is_the_legacy_bytes() {
        let actual = vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Path::new("/vsock"),
            2,
            128,
            None,
        );
        let legacy = serde_json::json!({
            "boot-source": {
                "kernel_image_path": "/kernel",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/init"
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": "/rootfs",
                "is_root_device": true,
                "is_read_only": false
            }],
            "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": "/vsock" },
            "balloon": { "amount_mib": 0, "deflate_on_oom": true, "stats_polling_interval_s": 1 },
            "machine-config": { "vcpu_count": 2, "mem_size_mib": 128 }
        })
        .to_string();
        assert_eq!(actual, legacy);
    }

    #[test]
    fn vm_config_network_contains_interface_and_kernel_addresses() {
        let spec = NetSpec {
            tap: "shinu0123456789".to_owned(),
            mac: "AA:FC:12:34:56:78".to_owned(),
            guest_cidr: "172.31.47.54/30".to_owned(),
            gateway: "172.31.47.53".to_owned(),
        };
        let value: Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Path::new("/vsock"),
            2,
            128,
            Some(&spec),
        ))
        .expect("valid Firecracker JSON");
        assert_eq!(value["network-interfaces"][0]["iface_id"], "eth0");
        assert_eq!(value["network-interfaces"][0]["host_dev_name"], spec.tap);
        assert_eq!(value["network-interfaces"][0]["guest_mac"], spec.mac);
        let boot_args = value["boot-source"]["boot_args"]
            .as_str()
            .expect("boot args string");
        assert!(boot_args.ends_with(" shinu.ip=172.31.47.54/30 shinu.gw=172.31.47.53"));
    }
}

fn mount_image(image: &Path, mnt: &Path) -> Result<()> {
    std::fs::create_dir_all(mnt)?;
    let output = std::process::Command::new("mount")
        .arg("-o")
        .arg("loop")
        .arg(image)
        .arg(mnt)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "mounting {} failed: {}",
            image.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn umount(mnt: &Path) -> Result<()> {
    let output = std::process::Command::new("umount").arg(mnt).output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "umount {} failed: {}",
            mnt.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Runs a shell command inside the mounted image. Only ever called by the
/// root daemon while building the base: the mounts live in a private
/// namespace that dies with the child, so nothing leaks into the host.
fn chroot_run(mnt: &Path, command: &str) -> Result<()> {
    let script = r#"mount -t proc proc "$1/proc" && (mount --rbind /dev "$1/dev" || :) && (mount --rbind /sys "$1/sys" || :) && exec chroot "$1" /bin/sh -c "$2""#;
    let status = std::process::Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            "--",
            "sh",
            "-c",
            script,
            "_",
        ])
        .arg(mnt)
        .arg(command)
        .status()?;
    if !status.success() {
        return Err(Error::Invalid(format!(
            "in-image command failed ({}): {command}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Turns the extracted rootfs into a bootable cloud image: root login, serial
/// console, sshd, and the vsock bridge sshd cannot provide itself (OpenSSH
/// has no AF_VSOCK listener, so socat forwards the guest vsock port to it).
fn configure_image(mnt: &Path) -> Result<()> {
    // Passwordless root for the serial console. Key auth is what `exec` uses;
    // this only matters when a human attaches to ttyS0 to debug a boot.
    let shadow = mnt.join("etc/shadow");
    if let Ok(contents) = std::fs::read_to_string(&shadow) {
        let patched = contents
            .lines()
            .map(|line| match line.strip_prefix("root:") {
                Some(rest) => match rest.split_once(':') {
                    Some((_, tail)) => format!("root::{tail}"),
                    None => line.to_owned(),
                },
                None => line.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&shadow, format!("{patched}\n"))?;
    }

    let default = mnt.join("etc/runit/runsvdir/default");
    std::fs::create_dir_all(&default)?;
    // A microVM has one serial port and no virtual terminals; leaving the
    // tty1-6 gettys enabled just burns boot time on devices that do not exist.
    for n in 1..=6 {
        let _ = std::fs::remove_file(default.join(format!("agetty-tty{n}")));
    }

    let bridge = mnt.join("etc/sv/vsock-sshd");
    std::fs::create_dir_all(&bridge)?;
    std::fs::write(
        bridge.join("run"),
        format!(
            "#!/bin/sh\nexec 2>&1\nexec socat VSOCK-LISTEN:{VSOCK_SSH_PORT},fork,reuseaddr TCP:127.0.0.1:22\n"
        ),
    )?;
    std::fs::set_permissions(bridge.join("run"), std::fs::Permissions::from_mode(0o755))?;
    let network = mnt.join("etc/sv/shinu-net");
    std::fs::create_dir_all(&network)?;
    std::fs::write(
        network.join("run"),
        "#!/bin/sh\nexec 2>&1\nIP=$(sed -n 's/.*shinu\\.ip=\\([^ ]*\\).*/\\1/p' /proc/cmdline)\nGW=$(sed -n 's/.*shinu\\.gw=\\([^ ]*\\).*/\\1/p' /proc/cmdline)\n[ -n \"$IP\" ] || { echo \"no shinu.ip on cmdline\"; exec sleep infinity; }\nip addr add \"$IP\" dev eth0 2>/dev/null\nip link set eth0 up\n[ -n \"$GW\" ] && ip route add default via \"$GW\" 2>/dev/null\necho \"configured $IP via $GW\"\nexec sleep infinity\n",
    )?;
    std::fs::set_permissions(network.join("run"), std::fs::Permissions::from_mode(0o755))?;

    for service in ["agetty-ttyS0", "sshd", "vsock-sshd", "shinu-net"] {
        let link = default.join(service);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(format!("/etc/sv/{service}"), &link)?;
    }

    // `UseDNS no` keeps login independent of guest network readiness; the
    // bridge peer is always socat on 127.0.0.1 while eth0 is booting.
    std::fs::write(
        mnt.join("etc/ssh/sshd_config.d-shinu.conf"),
        "PermitRootLogin prohibit-password\nPubkeyAuthentication yes\nUseDNS no\nGSSAPIAuthentication no\n",
    )?;
    let sshd_config = mnt.join("etc/ssh/sshd_config");
    let mut contents = std::fs::read_to_string(&sshd_config).unwrap_or_default();
    contents.push_str(&std::fs::read_to_string(
        mnt.join("etc/ssh/sshd_config.d-shinu.conf"),
    )?);
    std::fs::write(&sshd_config, contents)?;
    std::fs::remove_file(mnt.join("etc/ssh/sshd_config.d-shinu.conf"))?;

    let hosts = mnt.join("etc/hosts");
    if !hosts.exists() {
        std::fs::write(&hosts, "127.0.0.1 localhost\n::1 localhost\n")?;
    }
    std::fs::write(mnt.join("etc/hostname"), "shinu\n")?;
    // xbps needs working DNS during the build, and the guest now uses this file
    // at runtime. A host-local resolver is unreachable through the VM tap.
    if let Ok(resolv) = std::fs::read("/etc/resolv.conf") {
        let resolv = String::from_utf8_lossy(&resolv);
        let filtered = resolv
            .lines()
            .filter(|line| {
                let mut fields = line.split_whitespace();
                !matches!(
                    (fields.next(), fields.next()),
                    (Some("nameserver"), Some(address)) if address.starts_with("127.")
                )
            })
            .collect::<Vec<_>>();
        let has_nameserver = filtered
            .iter()
            .any(|line| line.split_whitespace().next() == Some("nameserver"));
        let contents = if has_nameserver {
            format!("{}\n", filtered.join("\n"))
        } else {
            "nameserver 1.1.1.1\n".to_owned()
        };
        std::fs::write(mnt.join("etc/resolv.conf"), contents)?;
    }
    Ok(())
}

/// Bakes caller-supplied files into the base image.
///
/// The base build is the only moment shared guest files are baked into every
/// space. Runtime networking remains available for workloads that need it, but
/// preinstalling the payload keeps each clone identical and cheap to create.
///
/// Baking it into the base rather than pushing it per space also means every
/// space starts identical and pays nothing at clone time, since the payload is
/// shared CoW extents like the rest of the image.
///
/// `SHINU_PAYLOAD` is a comma-separated list of `<src>` or `<src>=<dst>`. A
/// bare `<src>` lands in `/usr/local/bin/<basename>`. `SHINU_PAYLOAD_SERVICE`
/// names a runit service to enable, whose `run` script must have arrived
/// through the payload as `/etc/sv/<name>/run`.
///
/// Nothing here knows what the payload *is* — that keeps this crate a generic
/// VM engine rather than one workload's launcher.
fn install_payload(mnt: &Path) -> Result<()> {
    let Some(spec) = std::env::var_os("SHINU_PAYLOAD") else {
        return Ok(());
    };
    let spec = spec.to_string_lossy().into_owned();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (src, dst) = match entry.split_once('=') {
            Some((src, dst)) => (Path::new(src.trim()), dst.trim().to_owned()),
            None => {
                let src = Path::new(entry);
                let name = src
                    .file_name()
                    .ok_or_else(|| Error::Invalid(format!("payload has no filename: {entry}")))?;
                (src, format!("/usr/local/bin/{}", name.to_string_lossy()))
            }
        };
        if !src.is_file() {
            return Err(Error::Invalid(format!(
                "payload is not a file: {}",
                src.display()
            )));
        }
        // Destinations are absolute guest paths; strip the leading slash so
        // they join under the mount instead of escaping to the host root.
        let target = mnt.join(dst.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, &target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
    }

    let Some(service) = std::env::var_os("SHINU_PAYLOAD_SERVICE") else {
        return Ok(());
    };
    let service = service.to_string_lossy();
    let service = service.trim();
    if service.is_empty() {
        return Ok(());
    }
    let run = mnt.join(format!("etc/sv/{service}/run"));
    if !run.exists() {
        return Err(Error::Invalid(format!(
            "SHINU_PAYLOAD_SERVICE={service} but the payload did not provide /etc/sv/{service}/run"
        )));
    }
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755))?;
    let link = mnt.join(format!("etc/runit/runsvdir/default/{service}"));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(format!("/etc/sv/{service}"), &link)?;
    Ok(())
}

fn build_base(root: &Path, base: &Path, cfg: &BaseConfig) -> Result<()> {
    let tarball = fetch_tarball(root, cfg)?;

    let disk_mib = env_u32("SHINU_DISK_MIB", 2048);
    let status = std::process::Command::new("truncate")
        .arg("-s")
        .arg(format!("{disk_mib}M"))
        .arg(base)
        .status()?;
    if !status.success() {
        return Err(Error::Invalid("truncate failed for base image".to_owned()));
    }
    let output = std::process::Command::new("mkfs.ext4")
        .args(["-q", "-F"])
        .arg(base)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "mkfs.ext4 failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mnt = root.join("build.mnt");
    mount_image(base, &mnt)?;
    // Everything past the mount runs in a closure so a failure still unmounts:
    // a leaked loop mount would pin the image and block every later rebuild.
    let result = (|| -> Result<()> {
        let output = std::process::Command::new("tar")
            .arg("-xpf")
            .arg(&tarball)
            .arg("-C")
            .arg(&mnt)
            .arg("--numeric-owner")
            .output()?;
        if !output.status.success() {
            return Err(Error::Invalid(format!(
                "extracting {} failed: {}",
                tarball.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        configure_image(&mnt)?;
        // The shipped xbps refuses to install anything until it updates itself
        // ("The 'xbps' package must be updated"). `-S` is required: without it
        // xbps compares against empty repodata and reports "up to date" while
        // changing nothing, and the next install still fails.
        //
        // The base build is where guest packages are installed before the
        // first boot; runtime networking is available after that boot too.
        chroot_run(&mnt, "xbps-install -y -S -u xbps")?;
        chroot_run(&mnt, "xbps-install -y -S socat openssh iproute2 git")?;
        chroot_run(&mnt, "ssh-keygen -A")?;
        install_payload(&mnt)?;
        Ok(())
    })();
    umount(&mnt)?;
    let _ = std::fs::remove_dir(&mnt);
    result?;

    let output = std::process::Command::new("e2fsck")
        .args(["-fp"])
        .arg(base)
        .output()?;
    // e2fsck exits 1 when it fixed something, which is expected after an
    // unmount; only 2 and above mean the image needs attention.
    if output.status.code().unwrap_or(2) >= 2 {
        return Err(Error::Invalid(format!(
            "e2fsck rejected the new base image: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        )));
    }
    Ok(())
}

pub fn ensure_base(root: &Path, cfg: &BaseConfig) -> Result<()> {
    let base = base_path(root);
    if base.exists() {
        return Ok(());
    }
    match build_base(root, &base, cfg) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&base);
            Err(error)
        }
    }
}

/// microVM lifecycle. Everything here runs in the root daemon: it spawns
/// Firecracker, owns `/dev/kvm` access, and hands the unprivileged client
/// nothing but a socket and a key it already owns.
pub mod vm {
    use super::{Error, NetConfig, Result, VmConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    pub fn config_path(dir: &Path) -> PathBuf {
        dir.join("fc.json")
    }

    pub fn vsock_path(dir: &Path) -> PathBuf {
        dir.join("vsock.sock")
    }

    /// `<vm_dir>/fc.sock` — Firecracker's control API.
    ///
    /// Deliberately *not* chowned to the space owner like the vsock socket
    /// is: this endpoint resizes the balloon and reconfigures devices, so
    /// handing it to the user would let them lift their own VM's memory
    /// ceiling. The daemon is the only client.
    pub fn api_path(dir: &Path) -> PathBuf {
        dir.join("fc.sock")
    }

    pub fn pid_path(dir: &Path) -> PathBuf {
        dir.join("fc.pid")
    }

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
        let command = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        Error::Invalid(format!(
            "{command} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
        Ok(std::process::Command::new(program).args(args).output()?)
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
        if output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("File exists")
        {
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
                return Err(Error::Invalid(format!(
                    "network address conflict for uuid {id}: {address} is already on {interface}; set SHINU_NET_BASE"
                )));
            }
        }
        Ok(())
    }

    fn ensure_iptables_rule(check: &[&str], add: &[&str]) -> Result<()> {
        let checked = run_command("iptables", check)?;
        if checked.status.success() {
            return Ok(());
        }
        require_success("iptables", add)
    }

    /// Creates one tap, address, and forwarding/NAT rule set for this VM.
    /// Every add is preceded by an existence check so retries do not grow the
    /// host firewall, while the address check preserves /30 isolation.
    pub fn tap_up(id: Uuid, cfg: &NetConfig) -> Result<()> {
        if !cfg.enabled {
            return Ok(());
        }
        let tap = crate::tap_name(id);
        let (third, fourth_base) = crate::net_slot(id);
        let network = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base
        );
        let host = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base + 1
        );
        let host_cidr = format!("{host}/30");
        let network_cidr = format!("{network}/30");

        ensure_address_free(id, &tap, &host_cidr)?;
        allow_file_exists("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])?;
        ensure_address_free(id, &tap, &host_cidr)?;
        allow_file_exists("ip", &["addr", "add", &host_cidr, "dev", &tap])?;
        ensure_address_free(id, &tap, &host_cidr)?;
        require_success("ip", &["link", "set", &tap, "up"])?;

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
        ensure_iptables_rule(&forward_in_check, &forward_in_add)
    }

    /// Removes this VM's rules and tap. Cleanup is deliberately best effort:
    /// a stopped VM with a missing tap is already in the desired state.
    pub fn tap_down(id: Uuid, cfg: &NetConfig) {
        if !cfg.enabled {
            return;
        }
        let tap = crate::tap_name(id);
        let (third, fourth_base) = crate::net_slot(id);
        let network = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base
        );
        let network_cidr = format!("{network}/30");
        let _ = std::process::Command::new("iptables")
            .args([
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
        let _ = std::process::Command::new("iptables")
            .args([
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
                return Err(Error::Invalid("ssh-keygen failed for space key".to_owned()));
            }
        }
        let public = std::fs::read_to_string(key.with_extension("pub"))?;
        crate::chown_tree(dir, uid, gid)?;
        Ok(public)
    }

    /// Writes the space's public key into its own image. Done once at clone
    /// time rather than in the base, so no two spaces trust the same key.
    pub fn authorize(image: &Path, public_key: &str, mnt: &Path) -> Result<()> {
        crate::mount_image(image, mnt)?;
        let result = (|| -> Result<()> {
            let ssh = mnt.join("root/.ssh");
            std::fs::create_dir_all(&ssh)?;
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700))?;
            let authorized = ssh.join("authorized_keys");
            std::fs::write(&authorized, public_key)?;
            std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();
        crate::umount(mnt)?;
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

    /// The pid of the Firecracker instance launched with `config`.
    ///
    /// `setsid --fork` deliberately loses the grandchild's pid, so it is
    /// recovered by matching the config path in `/proc/<pid>/cmdline`. That
    /// path contains the space uuid, so at most one VM can match.
    ///
    /// The name check is not redundant: the launching `setsid` carries the
    /// very same path in its own cmdline, and it exits immediately. Matching
    /// it recorded an already-dead pid, and the caller then reported a
    /// perfectly healthy VM as "did not come up" — intermittently, depending
    /// on whether setsid had been reaped before this scan.
    fn find_vm_pid(config: &Path) -> Option<u32> {
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if is_vm_process(pid, config) {
                return Some(pid);
            }
        }
        None
    }

    /// Whether `pid` is a live Firecracker running exactly `config`.
    ///
    /// The single definition of "this VM", shared by the scan that discovers
    /// a pid and by every later check that trusts one. Two copies of this
    /// predicate would be free to drift apart, and the lax one would decide
    /// who gets signalled.
    ///
    /// All three conditions earn their place:
    /// - the name, because a pid file outlives its process;
    /// - not a zombie, whose `/proc` entry (including `comm`) lingers until
    ///   reaped, which would report every exited VM as still alive;
    /// - the config path, because pids are recycled and every VM here is a
    ///   process called `firecracker`. The path carries the space uuid, so
    ///   no other VM can match it.
    fn is_vm_process(pid: u32, config: &Path) -> bool {
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
        // cmdline is NUL-separated; the config path is one whole argument.
        let needle = config.as_os_str().as_encoded_bytes();
        cmdline.split(|b| *b == 0).any(|arg| arg == needle)
    }

    /// The pid of this space's VM, or `None` if it is not running.
    ///
    /// Every lifecycle decision — reuse, signal, reclaim, sweep — routes
    /// through here, so the identity check is deliberately strict; see
    /// [`is_vm_process`] for why each condition is load-bearing.
    pub fn running_pid(dir: &Path) -> Option<u32> {
        let pid = read_pid(dir)?;
        is_vm_process(pid, &config_path(dir)).then_some(pid)
    }

    pub fn is_running(dir: &Path) -> bool {
        running_pid(dir).is_some()
    }

    pub fn touch(dir: &Path) -> Result<()> {
        std::fs::write(last_used_path(dir), now_secs().to_string())?;
        Ok(())
    }

    /// One request against a VM's control API. `curl` is already this crate's
    /// HTTP client (see `fetch_tarball`), and it speaks unix sockets, so no
    /// hand-rolled HTTP and no new dependency.
    fn api(dir: &Path, method: &str, path: &str, body: Option<&str>) -> Option<String> {
        let mut command = std::process::Command::new("curl");
        command
            .arg("-s")
            .arg("--max-time")
            .arg("5")
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
        let out = command.output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Pulls one unsigned field out of the balloon statistics object.
    ///
    /// A hand-rolled scan rather than a `serde_json::Value`: the reply is a
    /// flat object of numbers, and this avoids allocating a parse tree in the
    /// daemon's poll loop every 30 seconds.
    fn stat_field(stats: &str, key: &str) -> Option<u64> {
        let needle = format!("\"{key}\":");
        let rest = &stats[stats.find(&needle)? + needle.len()..];
        let digits: String = rest
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }

    /// Hands the guest's unused memory back to the host.
    ///
    /// Firecracker never reclaims on its own: a guest that once touched 500
    /// MiB keeps that resident on the host forever, even after freeing it
    /// (measured: RSS 91 MiB → 593 MiB, unchanged after the guest freed it;
    /// inflating the balloon brought it to 100 MiB). This version has no
    /// free-page reporting, so the reclaim has to be asked for explicitly.
    ///
    /// The target comes from the guest's own `available_memory` rather than a
    /// guess, less `keep_mib` so the page cache and a working margin survive.
    /// Returns the MiB actually asked for.
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

    fn signal(pid: u32, sig: &str) -> bool {
        std::process::Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// True once the guest's sshd is ready to serve on `port`.
    ///
    /// Firecracker's host vsock is not a transparent pipe: a client sends
    /// `CONNECT <port>\n` and gets `OK <assigned>` back only if something in
    /// the guest accepts.
    ///
    /// A successful handshake alone is not enough, though. The bridge inside
    /// the guest starts accepting before sshd is serving, so a VM could pass
    /// that check and still refuse the very next connection — which is how a
    /// first exec failed with 255 while two VMs were booting at once. Waiting
    /// for the SSH identification string means readiness is decided by the
    /// thing exec actually depends on.
    fn probe(uds: &Path, port: u16) -> bool {
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
        // One byte at a time: a buffered reader would swallow the banner that
        // follows the handshake line, and both lines are read here.
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
        line(&mut stream).is_some_and(|banner| banner.starts_with(b"SSH-"))
    }

    /// Boots the VM unless it is already up. Returns whether a boot happened.
    pub fn start(
        root: &Path,
        id: Uuid,
        uid: u32,
        gid: u32,
        cfg: &VmConfig,
        net_cfg: &NetConfig,
    ) -> Result<(PathBuf, bool)> {
        let dir = crate::vm_dir(root, id);
        let vsock = vsock_path(&dir);
        if is_running(&dir) {
            // The idle sweeper may have reclaimed this VM's memory; give it
            // back before the caller runs anything in it.
            release(&dir);
            touch(&dir)?;
            return Ok((vsock, false));
        }

        // Sockets left behind by a dead VM make Firecracker fail to bind —
        // measured on the API socket, which refuses to start with
        // "Check that it is not already used" — and the readiness wait would
        // then hang on a stale file.
        let _ = std::fs::remove_file(&vsock);
        let _ = std::fs::remove_file(api_path(&dir));
        std::fs::create_dir_all(&dir)?;

        let image = crate::space_image(root, id);
        if !image.exists() {
            return Err(Error::NotFound(format!("space image: {}", image.display())));
        }
        let net = crate::net_spec(id, net_cfg);
        if let Err(error) = tap_up(id, net_cfg) {
            tap_down(id, net_cfg);
            return Err(error);
        }
        let result = (|| -> Result<(PathBuf, bool)> {
            std::fs::write(
                config_path(&dir),
                crate::vm_config_json(
                    &crate::kernel_path(root),
                    &image,
                    &vsock,
                    cfg.vcpus,
                    cfg.mem_mib,
                    net.as_ref(),
                ),
            )?;

            // Launched through `setsid` so the VM is not the daemon's own child.
            //
            // The daemon is a single-threaded accept loop with nowhere to reap
            // from: a directly spawned Firecracker becomes a zombie the moment it
            // exits and stays one for the daemon's whole life (measured: three
            // stopped VMs, three zombies). Re-parenting to init makes exit
            // accounting somebody else's job, and `setsid` also detaches the VM
            // from the daemon's session so a signal to the group cannot take
            // every running VM down with it.
            //
            // `--fork` makes setsid exit immediately, so its own pid is useless
            // here; the VM's real pid is recovered from `/proc` below.
            let log = std::fs::File::create(dir.join("console.log"))?;
            let status = std::process::Command::new("setsid")
                .arg("--fork")
                .arg(crate::firecracker_bin(root))
                .arg("--api-sock")
                .arg(api_path(&dir))
                .arg("--config-file")
                .arg(config_path(&dir))
                .stdin(std::process::Stdio::null())
                .stderr(log.try_clone()?)
                .stdout(log)
                .status()?;
            if !status.success() {
                return Err(Error::Invalid("could not launch firecracker".to_owned()));
            }
            // The pid file is what every later lifecycle check reads, so it must
            // name the VM itself. Find the process holding this VM's config file:
            // the path is unique per space, so the match is unambiguous.
            let mut pid = None;
            for _ in 0..100 {
                if let Some(found) = find_vm_pid(&config_path(&dir)) {
                    pid = Some(found);
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let Some(pid) = pid else {
                let console = std::fs::read_to_string(dir.join("console.log")).unwrap_or_default();
                return Err(Error::Invalid(format!(
                    "firecracker exited immediately: {}",
                    console
                        .lines()
                        .rev()
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(" | ")
                )));
            };
            std::fs::write(pid_path(&dir), pid.to_string())?;

            // Readiness is a guest-side property, and the socket file is not it:
            // Firecracker binds the UDS at startup, long before the guest kernel
            // has run init, so waiting for the file returns while nothing inside
            // is listening yet and the first exec fails the handshake. The only
            // honest signal is completing that handshake against the guest's own
            // vsock listener.
            let mut booted = false;
            for _ in 0..600 {
                if vsock.exists() && probe(&vsock, crate::VSOCK_SSH_PORT) {
                    booted = true;
                    break;
                }
                if !is_running(&dir) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !booted {
                let console = std::fs::read_to_string(dir.join("console.log")).unwrap_or_default();
                let _ = stop(&dir, net_cfg);
                return Err(Error::Invalid(format!(
                    "vm did not come up: {}",
                    console
                        .lines()
                        .rev()
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(" | ")
                )));
            }
            // Firecracker creates both sockets as root. Only the vsock one is
            // handed to the owner — that is all `exec` needs, and it carries no
            // authority beyond talking to the guest.
            std::os::unix::fs::chown(&vsock, Some(uid), Some(gid))?;
            std::fs::set_permissions(&vsock, std::fs::Permissions::from_mode(0o600))?;
            // The control API stays root-only and is pinned explicitly rather
            // than left to umask: it can resize the balloon and reconfigure
            // devices, so an owner holding it could lift their own memory cap.
            std::fs::set_permissions(api_path(&dir), std::fs::Permissions::from_mode(0o600))?;
            touch(&dir)?;
            Ok((vsock, true))
        })();
        if result.is_err() {
            let _ = stop(&dir, net_cfg);
            tap_down(id, net_cfg);
        }
        result
    }

    fn dir_id(dir: &Path) -> Result<Uuid> {
        let name = dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Invalid(format!("VM directory has no UUID: {}", dir.display())))?;
        Uuid::parse_str(name).map_err(|error| {
            Error::Invalid(format!("VM directory is not a UUID ({}): {error}", dir.display()))
        })
    }

    /// Graceful guest shutdown first, signals only as a fallback.
    ///
    /// The API socket could send CtrlAltDel, but SIGTERM kills the VMM
    /// outright either way: the guest never runs its shutdown path, so
    /// everything still in its page cache is lost. Writes from the previous
    /// command would silently vanish (measured: a file written and read back
    /// fine within one session came back empty after a stop). So flush the
    /// guest first, and keep SIGTERM/SIGKILL for one that is wedged or gone.
    pub fn stop(dir: &Path, cfg: &NetConfig) -> Result<bool> {
        let id = dir_id(dir)?;
        let Some(pid) = running_pid(dir) else {
            let _ = std::fs::remove_file(vsock_path(dir));
            let _ = std::fs::remove_file(api_path(dir));
            let _ = std::fs::remove_file(pid_path(dir));
            tap_down(id, cfg);
            return Ok(false);
        };

        let vsock = vsock_path(dir);
        if vsock.exists() {
            // Durability needs exactly one thing: the guest's dirty pages on
            // the image before the VMM dies. `sync` plus a read-only remount
            // does that and *returns normally*, leaving the connection intact.
            //
            // Asking the guest to power itself off instead is worse on both
            // ends: an orderly `poweroff` spends ~13s tearing down services
            // for a machine about to cease existing, and `poweroff -f` halts
            // the vCPU without the VMM ever exiting, so the command never
            // returns and the SSH client hangs (both measured on this host).
            // Once the data is on disk, killing the VMM is the fast, correct
            // way to end it.
            let _ = crate::exec_in_vm(
                &vsock,
                &key_path(dir),
                crate::VSOCK_SSH_PORT,
                &[
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "sync; mount -o remount,ro / 2>/dev/null; sync".to_owned(),
                ],
            );
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
            signal(pid, "KILL");
            for _ in 0..20 {
                if running_pid(dir).is_none() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let _ = std::fs::remove_file(vsock_path(dir));
        let _ = std::fs::remove_file(api_path(dir));
        let _ = std::fs::remove_file(pid_path(dir));
        tap_down(id, cfg);
        Ok(true)
    }

    /// Idle housekeeping, in two stages.
    ///
    /// A VM that has been unused for a *tenth* of the idle window first has
    /// its unused memory handed back to the host; one that passes the full
    /// window is shut down. Reclaiming first means a VM the user comes back
    /// to is still warm — the balloon deflates in `start` — while the host
    /// stops paying for memory nobody is using. Without this stage a VM's
    /// host footprint only ever grows, because Firecracker has no free-page
    /// reporting to return pages on its own.
    ///
    /// A missing `last_used` counts as "just used" rather than "ancient": a
    /// VM that booted a moment ago must not be reaped before its first
    /// command.
    pub fn sweep_idle(root: &Path, idle_secs: u64, cfg: &NetConfig) -> Result<Vec<PathBuf>> {
        let mut stopped = Vec::new();
        let vm_root = root.join("vm");
        let entries = match std::fs::read_dir(&vm_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(stopped),
            Err(error) => return Err(error.into()),
        };
        let now = now_secs();
        // Enough headroom for the guest's page cache and a working margin;
        // reclaiming every last free page would make the next command swap
        // its own working set back in.
        const KEEP_MIB: u64 = 128;
        for entry in entries.flatten() {
            let dir = entry.path();
            if !is_running(&dir) {
                continue;
            }
            let last = std::fs::read_to_string(last_used_path(&dir))
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(now);
            let idle_for = now.saturating_sub(last);
            if idle_for >= idle_secs {
                stop(&dir, cfg)?;
                stopped.push(dir);
            } else if idle_for >= (idle_secs / 10).max(30) {
                reclaim(&dir, KEEP_MIB);
            }
        }
        Ok(stopped)
    }
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
    let helper = vsock_helper()?;
    // Host key checking is pure noise here: the key is generated once in the
    // base image and therefore shared by every clone of it, and the transport
    // is a host-kernel vsock socket that never touches a network, so there is
    // no party in the middle to authenticate against.
    let status = std::process::Command::new("ssh")
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
        .arg(shell_quote(cmd))
        .status()?;
    Ok(status.code().unwrap_or(255))
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

/// Resolves a space by name or uuid within one project's namespace.
///
/// Scoping the lookup rather than filtering afterwards keeps project names
/// private: a miss in another project is indistinguishable from a missing row.
pub fn find<'a>(
    st: &'a state::State,
    name: &str,
    project: &str,
) -> Result<&'a state::Space> {
    let mine = || st.spaces.iter().filter(|space| space.project == project);
    if let Some(space) = mine().find(|space| space.name == name) {
        return Ok(space);
    }
    if let Ok(id) = Uuid::parse_str(name)
        && let Some(space) = mine().find(|space| space.id == id)
    {
        return Ok(space);
    }
    Err(Error::NotFound(name.to_owned()))
}

/// Same project-scoped lookup rule for commits; see [`find`].
pub fn find_ckpt<'a>(
    st: &'a state::State,
    id: Uuid,
    project: &str,
) -> Result<&'a state::Ckpt> {
    st.ckpts
        .iter()
        .find(|ckpt| ckpt.id == id && ckpt.project == project)
        .ok_or_else(|| Error::NotFound(format!("checkpoint not found: {id}")))
}

/// Returns the commits reachable from a space's head, newest first.
///
/// A malformed state file may contain a missing parent or a cycle; stopping at
/// either keeps inspection safe without inventing history.
pub fn log_chain<'a>(
    st: &'a state::State,
    space: &state::Space,
) -> Vec<&'a state::Ckpt> {
    let mut chain = Vec::new();
    let mut current = space.head;
    let mut seen = std::collections::HashSet::new();
    while let Some(id) = current {
        if !seen.insert(id) {
            break;
        }
        let Some(ckpt) = st.ckpts.iter().find(|ckpt| ckpt.id == id) else {
            break;
        };
        chain.push(ckpt);
        current = ckpt.parent;
    }
    chain
}
/// Returns every checkpoint archived for a space, newest first.
///
/// Unlike [`log_chain`], which follows the space's head backwards like `git
/// log`, this is the `git reflog` view: it includes checkpoints from branches
/// discarded by checkout. This is the only way to recover a state that checkout
/// discarded.
///
/// Persisted timestamps may only have second-level resolution, so the UUID is
/// used as a deterministic secondary sort key.
pub fn reflog_entries<'a>(st: &'a state::State, space: &state::Space) -> Vec<&'a state::Ckpt> {
    let mut entries = st
        .ckpts
        .iter()
        .filter(|ckpt| ckpt.space == space.id && ckpt.project == space.project)
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    entries
}

/// Returns the names or short ids that keep a commit reachable.
pub fn is_referenced(st: &state::State, ckpt: Uuid) -> Vec<String> {
    let short_id = |id: Uuid| {
        let text = id.simple().to_string();
        text[..8].to_owned()
    };
    let mut references = Vec::new();
    for space in &st.spaces {
        // A space that both derives from a commit and still points its head at
        // it is one reason to refuse the delete, not two; naming it twice only
        // makes the error message look confused.
        if space.parent == Some(ckpt) || space.head == Some(ckpt) {
            references.push(space.name.clone());
        }
    }
    for other in &st.ckpts {
        if other.id != ckpt && other.parent == Some(ckpt) {
            references.push(short_id(other.id));
        }
    }
    references
}

#[cfg(test)]
mod chain_tests {
    use super::state::{Ckpt, Space, State};
    use super::{is_referenced, log_chain, reflog_entries};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn space(
        id: Uuid,
        name: &str,
        parent: Option<Uuid>,
        head: Option<Uuid>,
    ) -> Space {
        Space {
            id,
            name: name.to_owned(),
            project: "project".to_owned(),
            parent,
            head,
            created_at: Utc::now(),
        }
    }

    fn ckpt(id: Uuid, space: Uuid, parent: Option<Uuid>) -> Ckpt {
        Ckpt {
            id,
            space,
            project: "project".to_owned(),
            parent,
            auto: false,
            note: "note".to_owned(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn log_chain_returns_linear_history_newest_first() {
        let space_id = id(1);
        let first = id(2);
        let second = id(3);
        let third = id(4);
        let space = space(space_id, "linear", None, Some(third));
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![
                ckpt(first, space_id, None),
                ckpt(second, space_id, Some(first)),
                ckpt(third, space_id, Some(second)),
            ],
        };

        let chain = log_chain(&state, &space);
        assert_eq!(
            chain.iter().map(|commit| commit.id).collect::<Vec<_>>(),
            vec![third, second, first]
        );
    }

    #[test]
    fn log_chain_follows_each_fork_independently() {
        let source_space = id(10);
        let first = id(11);
        let left = id(12);
        let right = id(13);
        let left_space = space(id(14), "left", None, Some(left));
        let right_space = space(id(15), "right", None, Some(right));
        let state = State {
            spaces: vec![left_space.clone(), right_space.clone()],
            ckpts: vec![
                ckpt(first, source_space, None),
                ckpt(left, source_space, Some(first)),
                ckpt(right, source_space, Some(first)),
            ],
        };

        assert_eq!(
            log_chain(&state, &left_space)
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            vec![left, first]
        );
        assert_eq!(
            log_chain(&state, &right_space)
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            vec![right, first]
        );
    }

    #[test]
    fn log_chain_stops_on_a_cycle() {
        let space_id = id(20);
        let first = id(21);
        let second = id(22);
        let space = space(space_id, "cyclic", None, Some(first));
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![
                ckpt(first, space_id, Some(second)),
                ckpt(second, space_id, Some(first)),
            ],
        };

        let chain = log_chain(&state, &space);
        assert_eq!(
            chain.iter().map(|commit| commit.id).collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[test]
    fn reflog_includes_discarded_commits_scopes_and_sorts_stably() {
        let space_id = id(40);
        let other_space_id = id(41);
        let first = id(42);
        let auto = id(43);
        let same_second = id(44);
        let foreign = id(45);
        let other_space = space(other_space_id, "other", None, None);
        let space = space(space_id, "web", None, Some(first));

        let mut first_checkpoint = ckpt(first, space_id, None);
        first_checkpoint.created_at = Utc
            .timestamp_opt(10, 0)
            .single()
            .expect("valid first timestamp");
        let mut auto_checkpoint = ckpt(auto, space_id, Some(first));
        auto_checkpoint.auto = true;
        auto_checkpoint.created_at = Utc
            .timestamp_opt(20, 0)
            .single()
            .expect("valid automatic timestamp");
        let mut same_second_checkpoint = ckpt(same_second, space_id, None);
        same_second_checkpoint.created_at = Utc
            .timestamp_opt(20, 0)
            .single()
            .expect("valid tie timestamp");

        let state = State {
            spaces: vec![space.clone(), other_space],
            ckpts: vec![
                auto_checkpoint,
                first_checkpoint,
                ckpt(foreign, other_space_id, None),
                same_second_checkpoint,
            ],
        };

        assert_eq!(
            log_chain(&state, &space)
                .iter()
                .map(|checkpoint| checkpoint.id)
                .collect::<Vec<_>>(),
            vec![first]
        );
        assert_eq!(
            reflog_entries(&state, &space)
                .iter()
                .map(|checkpoint| checkpoint.id)
                .collect::<Vec<_>>(),
            vec![same_second, auto, first]
        );
        assert!(reflog_entries(&state, &space)
            .iter()
            .any(|checkpoint| checkpoint.id == auto && checkpoint.auto));
        assert!(reflog_entries(&state, &space)
            .iter()
            .all(|checkpoint| checkpoint.space == space_id));
    }

    #[test]
    fn is_referenced_reports_space_and_commit_edges() {
        let target = id(0x1000_0000_0000_0000_0000_0000_0000_0001);
        let child = id(0x2000_0000_0000_0000_0000_0000_0000_0002);
        let state = State {
            spaces: vec![
                space(id(31), "derived", Some(target), None),
                space(id(32), "checked-out", None, Some(target)),
            ],
            ckpts: vec![
                ckpt(target, id(33), None),
                ckpt(child, id(33), Some(target)),
            ],
        };

        let references = is_referenced(&state, target);
        assert_eq!(references.len(), 3);
        assert!(references.contains(&"derived".to_owned()));
        assert!(references.contains(&"checked-out".to_owned()));
        assert!(references.contains(&"20000000".to_owned()));
    }
}

pub mod http {
    use std::io::{self, BufRead, Write};

    const MAX_HEADER_BYTES: usize = 64 * 1024;
    const MAX_BODY_BYTES: usize = 1024 * 1024;
    const MAX_HEADERS: usize = 100;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Request {
        pub method: String,
        pub path: String,
        pub token: Option<String>,
        pub body: Vec<u8>,
    }

    fn invalid(message: impl Into<String>) -> crate::Error {
        crate::Error::Invalid(message.into())
    }

    fn ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }

    fn is_ows(byte: u8) -> bool {
        byte == b' ' || byte == b'\t'
    }

    fn trim_ows(value: &[u8]) -> &[u8] {
        let start = value.iter().position(|byte| !is_ows(*byte)).unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|byte| !is_ows(*byte))
            .map_or(start, |index| index + 1);
        &value[start..end]
    }

    fn read_line<R: BufRead + ?Sized>(
        stream: &mut R,
        total: &mut usize,
    ) -> crate::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        loop {
            let available = stream.fill_buf()?;
            if available.is_empty() {
                if line.is_empty() {
                    return Ok(None);
                }
                return Err(invalid("incomplete HTTP line"));
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |index| index + 1);
            // Inspect the buffered bytes before extending the line so a peer
            // cannot make the parser allocate without bound by omitting '\n'.
            if *total > MAX_HEADER_BYTES
                || take > MAX_HEADER_BYTES.saturating_sub(*total)
            {
                return Err(invalid("HTTP request line and headers exceed 64 KiB"));
            }
            line.extend_from_slice(&available[..take]);
            stream.consume(take);
            *total += take;
            if newline.is_some() {
                return Ok(Some(line));
            }
        }
    }

    fn line_content(line: &[u8]) -> crate::Result<&[u8]> {
        if line.last().copied() != Some(b'\n') {
            return Err(invalid("HTTP line is not terminated"));
        }
        let mut end = line.len() - 1;
        if end > 0 && line[end - 1] == b'\r' {
            end -= 1;
        }
        if line[..end].contains(&b'\r') {
            return Err(invalid("HTTP line contains an embedded carriage return"));
        }
        Ok(&line[..end])
    }

    fn bytes_to_string(bytes: &[u8], field: &str) -> crate::Result<String> {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| invalid(format!("HTTP {field} is not valid UTF-8")))
    }

    fn bearer_token(value: &[u8]) -> Option<String> {
        let value = trim_ows(value);
        if value.len() < 6 || !ascii_case_eq(&value[..6], b"Bearer") {
            return None;
        }
        let rest = &value[6..];
        if rest.first().copied().is_none_or(|byte| !is_ows(byte)) {
            return None;
        }
        let token = rest
            .iter()
            .position(|byte| !is_ows(*byte))
            .map_or(&[][..], |start| &rest[start..]);
        if token.is_empty()
            || token
                .iter()
                .any(|byte| *byte <= b' ' || *byte == 0x7f)
        {
            return None;
        }
        String::from_utf8(token.to_vec()).ok()
    }

    pub fn parse(stream: &mut impl BufRead) -> crate::Result<Request> {
        let mut header_bytes = 0;
        let request_line = read_line(stream, &mut header_bytes)?
            .ok_or_else(|| invalid("missing HTTP request line"))?;
        let request_line = line_content(&request_line)?;
        let mut fields = request_line.split(|byte| *byte == b' ');
        let method = fields
            .next()
            .ok_or_else(|| invalid("missing HTTP method"))?;
        let path = fields
            .next()
            .ok_or_else(|| invalid("missing HTTP path"))?;
        let version = fields
            .next()
            .ok_or_else(|| invalid("missing HTTP version"))?;
        if fields.next().is_some()
            || method.is_empty()
            || method.iter().any(|byte| *byte <= b' ' || *byte == 0x7f)
            || path.is_empty()
            || path.iter().any(|byte| *byte <= b' ' || *byte == 0x7f)
            || version != b"HTTP/1.1"
        {
            return Err(invalid("malformed HTTP request line"));
        }

        let method = bytes_to_string(method, "method")?;
        let path = bytes_to_string(path, "path")?;
        let mut token = None;
        let mut content_length = None;
        let mut header_count = 0;
        loop {
            let line = read_line(stream, &mut header_bytes)?
                .ok_or_else(|| invalid("incomplete HTTP headers"))?;
            let line = line_content(&line)?;
            if line.is_empty() {
                break;
            }
            header_count += 1;
            // Bounding the number of fields prevents a peer from forcing
            // unbounded per-header parsing work with many tiny lines.
            if header_count > MAX_HEADERS {
                return Err(invalid("HTTP request has more than 100 headers"));
            }
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .ok_or_else(|| invalid("HTTP header has no colon"))?;
            let name = &line[..colon];
            if name.is_empty()
                || name
                    .iter()
                    .any(|byte| *byte <= b' ' || *byte >= 0x7f)
            {
                return Err(invalid("invalid HTTP header name"));
            }
            let value = trim_ows(&line[colon + 1..]);
            if ascii_case_eq(name, b"Content-Length") {
                if content_length.is_some() {
                    return Err(invalid("duplicate Content-Length header"));
                }
                let value = std::str::from_utf8(value)
                    .map_err(|_| invalid("Content-Length is not valid ASCII"))?;
                let length = value
                    .parse::<usize>()
                    .map_err(|_| invalid("invalid Content-Length"))?;
                // JSON requests are deliberately bounded before allocation;
                // this also keeps a bogus length from exhausting the daemon.
                if length > MAX_BODY_BYTES {
                    return Err(invalid("Content-Length exceeds 1 MiB"));
                }
                content_length = Some(length);
            } else if ascii_case_eq(name, b"Authorization") {
                // A malformed scheme is left as no token so the auth layer
                // returns its uniform 401 rather than exposing parser detail.
                token = bearer_token(value);
            }
        }

        let mut body = vec![0; content_length.unwrap_or(0)];
        if let Err(error) = stream.read_exact(&mut body) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Err(invalid("request body is shorter than Content-Length"));
            }
            return Err(crate::Error::Io(error));
        }
        Ok(Request {
            method,
            path,
            token,
            body,
        })
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    fn json_io_error(error: serde_json::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }

    pub fn respond(
        writer: &mut impl Write,
        status: u16,
        body: &serde_json::Value,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(body).map_err(json_io_error)?;
        write!(
            writer,
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason_phrase(status),
            body.len()
        )?;
        writer.write_all(&body)
    }

    pub fn respond_chunked_start(writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )?;
        // Flush the headers before the VM command starts so clients can begin
        // consuming the stream without waiting for its first output line.
        writer.flush()
    }

    pub fn respond_chunk(
        writer: &mut impl Write,
        line: &serde_json::Value,
    ) -> io::Result<()> {
        let mut payload = serde_json::to_vec(line).map_err(json_io_error)?;
        payload.push(b'\n');
        write!(writer, "{:x}\r\n", payload.len())?;
        writer.write_all(&payload)?;
        writer.write_all(b"\r\n")?;
        // Without a flush each chunk can remain buffered until exec exits,
        // defeating NDJSON streaming for the agent.
        writer.flush()
    }

    pub fn respond_chunked_end(writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(b"0\r\n\r\n")?;
        writer.flush()
    }

    /// The single translation from domain errors to HTTP status codes.
    pub fn status_for(error: &crate::Error) -> u16 {
        match error {
            crate::Error::Auth(_) => 401,
            crate::Error::NotFound(_) => 404,
            crate::Error::Invalid(_) => 400,
            crate::Error::Btrfs(_) | crate::Error::Io(_) | crate::Error::Json(_) => 500,
        }
    }

    #[cfg(test)]
    mod http_tests {
        use super::*;
        use serde_json::json;
        use std::io::Cursor;

        #[test]
        fn parses_get_without_body() {
            let mut input = Cursor::new(
                b"GET /v1/spaces HTTP/1.1\r\nHost: localhost\r\n\r\n",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/v1/spaces");
            assert_eq!(request.token, None);
            assert!(request.body.is_empty());
        }

        #[test]
        fn reads_exact_content_length() {
            let mut input = Cursor::new(
                b"POST /v1/spaces HTTP/1.1\r\nContent-Length: 7\r\n\r\npayloadtrailing",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.body, b"payload");
        }

        #[test]
        fn recognizes_mixed_case_header_names() {
            let mut input = Cursor::new(
                b"POST /v1/spaces HTTP/1.1\r\ncontent-length: 3\r\nAUTHORIZATION: Bearer abc\r\n\r\nxyz",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.body, b"xyz");
            assert_eq!(request.token.as_deref(), Some("abc"));
        }

        #[test]
        fn extracts_case_insensitive_bearer_with_multiple_spaces() {
            let mut input = Cursor::new(
                b"GET / HTTP/1.1\r\naUtHoRiZaTiOn: bEaReR    secret\r\n\r\n",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.token.as_deref(), Some("secret"));
        }

        #[test]
        fn missing_authorization_has_no_token() {
            let mut input = Cursor::new(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert_eq!(parse(&mut input).unwrap().token, None);
        }

        #[test]
        fn rejects_headers_over_64_kib() {
            let mut input = b"GET / HTTP/1.1\r\nX-Fill: ".to_vec();
            input.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES));
            let error = parse(&mut Cursor::new(input)).unwrap_err();
            assert!(matches!(error, crate::Error::Invalid(_)));
        }

        #[test]
        fn rejects_content_length_over_1_mib() {
            let input = b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n";
            let error = parse(&mut Cursor::new(input)).unwrap_err();
            assert!(matches!(error, crate::Error::Invalid(_)));
        }

        #[test]
        fn responds_with_status_and_byte_length() {
            let body = json!({"ok": true});
            let serialized = serde_json::to_vec(&body).unwrap();
            let mut output = Vec::new();
            respond(&mut output, 201, &body).unwrap();
            assert!(output.starts_with(b"HTTP/1.1 201 Created\r\n"));
            assert!(output.windows(format!("Content-Length: {}\r\n", serialized.len()).len()).any(
                |window| window == format!("Content-Length: {}\r\n", serialized.len()).as_bytes()
            ));
            assert!(output.ends_with(&serialized));
        }

        #[test]
        fn encodes_chunk_length_and_termination() {
            let line = json!({"stream": "stdout", "data": "ok\n"});
            let mut payload = serde_json::to_vec(&line).unwrap();
            payload.push(b'\n');
            let mut output = Vec::new();
            respond_chunked_start(&mut output).unwrap();
            respond_chunk(&mut output, &line).unwrap();
            respond_chunked_end(&mut output).unwrap();
            assert!(output.windows(b"Transfer-Encoding: chunked\r\n".len()).any(
                |window| window == b"Transfer-Encoding: chunked\r\n"
            ));
            let mut expected_tail = format!("{:x}\r\n", payload.len()).into_bytes();
            expected_tail.extend_from_slice(&payload);
            expected_tail.extend_from_slice(b"\r\n0\r\n\r\n");
            assert!(output.ends_with(&expected_tail));
        }

        #[test]
        fn maps_domain_errors_to_statuses() {
            assert_eq!(status_for(&crate::Error::Auth("bad".into())), 401);
            assert_eq!(status_for(&crate::Error::NotFound("gone".into())), 404);
            assert_eq!(status_for(&crate::Error::Invalid("bad".into())), 400);
            assert_eq!(status_for(&crate::Error::Btrfs("bad".into())), 500);
            assert_eq!(
                status_for(&crate::Error::Io(std::io::Error::other("bad"))),
                500
            );
            let json_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
            assert_eq!(status_for(&crate::Error::Json(json_error)), 500);
        }
    }
}

pub mod proto {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "op", rename_all = "snake_case")]
    pub enum Req {
        New {
            name: String,
        },
        Fork {
            ckpt: Uuid,
            name: String,
        },
        /// `hot: true` syncs a running guest without remounting read-only and
        /// is not crash-consistent; `hot: false` requires the space to be stopped.
        Commit {
            space: String,
            note: String,
            hot: bool,
        },
        Checkout {
            space: String,
            commit: Uuid,
        },
        /// Lists only commits reachable from the space's head, like `git log`.
        Log {
            space: String,
        },
        /// Lists every checkpoint archived for the space, including automatic
        /// checkpoints that checkout created and then left unreachable.
        Reflog {
            space: String,
        },
        Rm {
            space: String,
        },
        /// Removes one project-scoped commit when no space or commit derives from it.
        RmCkpt {
            ckpt: Uuid,
        },
        Ls,
        /// Boots the space's VM if it is not already running and returns
        /// everything the caller needs to reach it: vsock socket, private
        /// key, port.
        Start {
            space: String,
        },
        /// Shuts the space's VM down. Idempotent.
        Stop {
            space: String,
        },
        /// Marks the VM as in use so the idle sweeper leaves it alone.
        Touch {
            space: String,
        },
        Gc {
            free_below: u64,
            dry_run: bool,
        },
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub enum Resp {
        Ok { data: serde_json::Value },
        Error { message: String },
    }
}
