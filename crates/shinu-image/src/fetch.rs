use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use shinu_core::{Error, Image, Result, cache_dir};

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Returns a private sibling name for a staged file. The process id prevents
/// ordinary cross-process collisions, while the monotonic counter and clock
/// component also cover pid reuse and repeated calls in one process.
pub(super) fn unique_staging_path(path: &Path) -> PathBuf {
    let basename = path.file_name().map_or_else(
        || "stage".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let pid = std::process::id();
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        ".{basename}.{pid}.{clock:032x}.{sequence:016x}.part"
    ))
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

    fn void_index_url(&self) -> String {
        format!("{}/live/current/", self.mirror)
    }
}

const UBUNTU_RELEASE_URL: &str = "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/";
const ARCH_BOOTSTRAP_URL: &str =
    "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-bootstrap-x86_64.tar.zst";
const ROCKY_CONTAINER_URL: &str = "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-Container-Base.latest.x86_64.tar.xz";

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

/// Newest Ubuntu 24.04 point release in the release directory listing.
fn pick_ubuntu_tarball_name(index: &str) -> Result<String> {
    let prefix = "ubuntu-base-24.04.";
    let suffix = "-base-amd64.tar.gz";
    let mut best: Option<(u32, &str)> = None;
    for token in index.split(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c))) {
        let Some(point) = token
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
        else {
            continue;
        };
        let Ok(point) = point.parse::<u32>() else {
            continue;
        };
        if best.is_none_or(|(current, _)| point > current) {
            best = Some((point, token));
        }
    }
    best.map(|(_, name)| name.to_owned()).ok_or_else(|| {
        Error::Invalid(
            "no ubuntu-base-24.04.N-base-amd64.tar.gz in the Ubuntu release index".to_owned(),
        )
    })
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
    use super::{
        oci_layer_member, oci_manifest_member, pick_sha256, pick_tarball_name,
        pick_ubuntu_tarball_name,
    };
    use shinu_core::{Error, Image, base_path, migrate_base};

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
        let list = "SHA256 (void-x86_64-musl-ROOTFS-20250202.tar.xz) = 8f66e05401a953d151b3e82d132437840e0b24a51edff27f13202c9010dfa27\nSHA256 (void-x86_64-ROOTFS-20250202.tar.xz) = 3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876\n";
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

    #[test]
    fn image_ids_round_trip_through_text_and_json() {
        for image in Image::all() {
            let id = image.to_string();
            assert_eq!(id.parse::<Image>().expect("image id"), image);
            assert_eq!(
                serde_json::to_string(&image).expect("image JSON"),
                format!("\"{id}\"")
            );
            assert_eq!(
                serde_json::from_str::<Image>(&format!("\"{id}\"")).expect("image JSON parse"),
                image
            );
        }
    }

    #[test]
    fn image_parser_names_the_valid_ids() {
        let error = "debian".parse::<Image>().expect_err("unknown image");
        assert!(
            matches!(error, Error::Invalid(message) if message.contains("void, ubuntu, arch, rocky"))
        );
    }

    #[test]
    fn base_paths_are_explicit_per_image() {
        let root = std::path::Path::new("/var/lib/shinu");
        assert_eq!(base_path(root, Image::Void), root.join("base-void.ext4"));
        assert_eq!(
            base_path(root, Image::Ubuntu),
            root.join("base-ubuntu.ext4")
        );
        assert_eq!(base_path(root, Image::Arch), root.join("base-arch.ext4"));
        assert_eq!(base_path(root, Image::Rocky), root.join("base-rocky.ext4"));
    }

    #[test]
    fn migrates_legacy_void_base_once() {
        let root = std::env::temp_dir().join(format!("shinu-base-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create test root");
        let legacy = root.join("base.ext4");
        std::fs::write(&legacy, b"void image").expect("write legacy base");
        migrate_base(&root).expect("migrate legacy base");
        assert!(!legacy.exists());
        assert_eq!(
            std::fs::read(base_path(&root, Image::Void)).expect("read migrated base"),
            b"void image"
        );
        migrate_base(&root).expect("idempotent migration");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn picks_newest_ubuntu_point_release() {
        let listing = r#"
            <a href="ubuntu-base-24.04.1-base-amd64.tar.gz">old</a>
            <a href="ubuntu-base-24.04.10-base-amd64.tar.gz">newest</a>
            <a href="ubuntu-base-24.04.9-base-amd64.tar.gz">middle</a>
            <a href="ubuntu-base-24.04.10-base-arm64.tar.gz">wrong arch</a>
        "#;
        assert_eq!(
            pick_ubuntu_tarball_name(listing).expect("Ubuntu archive"),
            "ubuntu-base-24.04.10-base-amd64.tar.gz"
        );
    }

    #[test]
    fn parses_single_layer_oci_metadata_and_rejects_multi_layer() {
        let manifest_digest = "a".repeat(64);
        let layer_digest = "b".repeat(64);
        let index = format!(r#"{{"manifests":[{{"digest":"sha256:{manifest_digest}"}}]}}"#);
        let manifest = format!(r#"{{"layers":[{{"digest":"sha256:{layer_digest}"}}]}}"#);
        assert_eq!(
            oci_manifest_member(&index).expect("manifest member"),
            format!("blobs/sha256/{manifest_digest}")
        );
        assert_eq!(
            oci_layer_member(&manifest).expect("layer member"),
            format!("blobs/sha256/{layer_digest}")
        );
        let multi = r#"{"layers":[{"digest":"sha256:a"},{"digest":"sha256:b"}]}"#;
        let error = oci_layer_member(multi).expect_err("multi-layer OCI");
        assert!(
            matches!(error, Error::Invalid(message) if message.contains("2 layers") && message.contains("single-layer"))
        );
    }
}
// Large downloaded artifacts can be gigabytes, so let `sha256sum` stream the
// file instead of buffering it through the in-memory token hashing helper.
pub(super) fn sha256_file(path: &Path) -> Result<String> {
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

/// Returns the cached rootfs archive for one image, downloading it lazily.
///
/// Void retains its signed-by-index digest flow. The remaining sources are
/// fetched from stable HTTPS URLs (Ubuntu's point release is selected from its
/// directory listing), so their archives are cached by filename.
pub(super) fn fetch_tarball(root: &Path, image: Image, cfg: &BaseConfig) -> Result<PathBuf> {
    if let Some(path) = &cfg.tarball {
        if !path.exists() {
            return Err(Error::Invalid(format!(
                "SHINU_ROOTFS_TARBALL does not exist: {}",
                path.display()
            )));
        }
        return Ok(path.clone());
    }

    let cache = cache_dir(root);
    std::fs::create_dir_all(&cache)?;
    match image {
        Image::Void => {
            let index_url = cfg.void_index_url();
            let name = pick_tarball_name(&curl_text(&index_url)?, &cfg.arch)?;
            let digest = pick_sha256(&curl_text(&format!("{index_url}sha256sum.txt"))?, &name)?;
            let target = cache.join(&name);
            if target.exists() && sha256_file(&target)? == digest {
                return Ok(target);
            }
            let tmp = unique_staging_path(&target);
            let mut owns_tmp = false;
            let result = (|| -> Result<PathBuf> {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)?;
                owns_tmp = true;
                let status = std::process::Command::new("curl")
                    .args(["-sSfL", "--max-time", "1800", "-o"])
                    .arg(&tmp)
                    .arg(format!("{index_url}{name}"))
                    .status()?;
                if !status.success() {
                    return Err(Error::Invalid(format!("download failed: {name}")));
                }
                let actual = sha256_file(&tmp)?;
                if actual != digest {
                    return Err(Error::Invalid(format!(
                        "sha256 mismatch for {name}: expected {digest}, got {actual}"
                    )));
                }
                std::fs::rename(&tmp, &target)?;
                Ok(target)
            })();
            if owns_tmp && result.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            result
        }
        Image::Ubuntu => {
            let index = curl_text(UBUNTU_RELEASE_URL)?;
            let name = pick_ubuntu_tarball_name(&index)?;
            let target = cache.join(&name);
            if !target.exists() {
                curl_to_file(&format!("{UBUNTU_RELEASE_URL}{name}"), &target)?;
            }
            Ok(target)
        }
        Image::Arch => {
            let target = cache.join("archlinux-bootstrap-x86_64.tar.zst");
            if !target.exists() {
                curl_to_file(ARCH_BOOTSTRAP_URL, &target)?;
            }
            Ok(target)
        }

        Image::Rocky => {
            let name = "Rocky-9-Container-Base.latest.x86_64.tar.xz";
            let target = cache.join(name);
            if !target.exists() {
                curl_to_file(ROCKY_CONTAINER_URL, &target)?;
            }
            Ok(target)
        }
    }
}
fn oci_descriptor_member(descriptor: &serde_json::Value, role: &str) -> Result<String> {
    let digest = descriptor
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Invalid(format!("OCI {role} descriptor has no digest")))?;
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(Error::Invalid(format!(
            "OCI {role} digest must use sha256:"
        )));
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Invalid(format!(
            "OCI {role} digest is not valid sha256"
        )));
    }
    Ok(format!("blobs/sha256/{hex}"))
}

pub(super) fn oci_manifest_member(index_json: &str) -> Result<String> {
    let index: serde_json::Value = serde_json::from_str(index_json)?;
    let manifests = index
        .get("manifests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Invalid("OCI index has no manifests array".to_owned()))?;
    if manifests.len() != 1 {
        return Err(Error::Invalid(format!(
            "OCI index has {} manifests; expected exactly one",
            manifests.len()
        )));
    }
    oci_descriptor_member(&manifests[0], "manifest")
}

pub(super) fn oci_layer_member(manifest_json: &str) -> Result<String> {
    let manifest: serde_json::Value = serde_json::from_str(manifest_json)?;
    let layers = manifest
        .get("layers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Invalid("OCI manifest has no layers array".to_owned()))?;
    if layers.len() > 1 {
        return Err(Error::Invalid(format!(
            "OCI image has {} layers; only single-layer images are supported",
            layers.len()
        )));
    }
    if layers.is_empty() {
        return Err(Error::Invalid(
            "OCI image has no layers; expected exactly one".to_owned(),
        ));
    }
    oci_descriptor_member(&layers[0], "layer")
}

pub(super) fn tar_member(archive: &Path, member: &str) -> Result<Vec<u8>> {
    let output = std::process::Command::new("tar")
        .args(["-xJOf"])
        .arg(archive)
        .arg(member)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "extracting {} from {} failed: {}",
            member,
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

/// Firecracker ships BSD-less `sha256sum` style digests inside the release
/// tarball: `<hex>  ./<file>`.
pub(super) fn pick_sums_digest(list: &str, name: &str) -> Result<String> {
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
#[cfg(test)]
mod staging_tests {
    use super::unique_staging_path;
    use std::path::Path;

    #[test]
    fn staging_paths_are_unique_private_siblings() {
        let destination = Path::new("/var/lib/shinu/assets/manifest.json");
        let first = unique_staging_path(destination);
        let second = unique_staging_path(destination);

        assert_ne!(first, second);
        assert_eq!(first.parent(), destination.parent());
        assert_eq!(second.parent(), destination.parent());
        for staged in [first, second] {
            let name = staged
                .file_name()
                .expect("staging filename")
                .to_string_lossy();
            assert!(name.starts_with(".manifest.json."));
            assert!(name.ends_with(".part"));
            assert!(name.contains(&std::process::id().to_string()));
        }
    }
}

/// Download to a unique private sibling and rename on success. A half-
/// transferred file must never be mistaken for a finished one, and a failed
/// process must only clean up its own staging path.
pub(super) fn curl_to_file(url: &str, dst: &Path) -> Result<()> {
    let tmp = unique_staging_path(dst);
    let mut owns_tmp = false;
    let result = (|| -> Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        owns_tmp = true;
        let status = std::process::Command::new("curl")
            .args(["-sSfL", "--max-time", "1800", "-o"])
            .arg(&tmp)
            .arg(url)
            .status()?;
        if !status.success() {
            return Err(Error::Invalid(format!("download failed: {url}")));
        }
        std::fs::rename(&tmp, dst)?;
        Ok(())
    })();
    if owns_tmp && result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
