use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use serde_json::{Map, Value};
use shinu_core::{
    Error, FC_SNAPSHOT_VERSION, FC_URL, FC_VERSION, KERNEL_URL, Result, assets_dir, cache_dir,
    firecracker_bin, init_daemon_layout, jailer_bin, kernel_path,
};

use super::fetch::{curl_to_file, pick_sums_digest, sha256_file, unique_staging_path};

const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_MODE: u32 = 0o600;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssetManifest {
    firecracker_version: String,
    snapshot_format_version: String,
    firecracker_sha256: String,
    jailer_sha256: String,
    kernel_sha256: String,
}

impl AssetManifest {
    fn current(firecracker_sha256: String, jailer_sha256: String, kernel_sha256: String) -> Self {
        Self {
            firecracker_version: FC_VERSION.to_owned(),
            snapshot_format_version: FC_SNAPSHOT_VERSION.to_owned(),
            firecracker_sha256,
            jailer_sha256,
            kernel_sha256,
        }
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "firecracker_version": self.firecracker_version.as_str(),
            "snapshot_format_version": self.snapshot_format_version.as_str(),
            "firecracker_sha256": self.firecracker_sha256.as_str(),
            "jailer_sha256": self.jailer_sha256.as_str(),
            "kernel_sha256": self.kernel_sha256.as_str(),
        })
    }

    fn from_json(value: Value) -> Result<Self> {
        const KEYS: [&str; 5] = [
            "firecracker_version",
            "snapshot_format_version",
            "firecracker_sha256",
            "jailer_sha256",
            "kernel_sha256",
        ];
        let object = value
            .as_object()
            .ok_or_else(|| Error::Invalid("asset manifest must be a JSON object".to_owned()))?;
        if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
            return Err(Error::Invalid(
                "asset manifest has unexpected or missing fields".to_owned(),
            ));
        }

        let manifest = Self {
            firecracker_version: manifest_string(object, "firecracker_version")?,
            snapshot_format_version: manifest_string(object, "snapshot_format_version")?,
            firecracker_sha256: manifest_string(object, "firecracker_sha256")?,
            jailer_sha256: manifest_string(object, "jailer_sha256")?,
            kernel_sha256: manifest_string(object, "kernel_sha256")?,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        if self.firecracker_version.is_empty() || self.snapshot_format_version.is_empty() {
            return Err(Error::Invalid(
                "asset manifest version fields must not be empty".to_owned(),
            ));
        }
        for (label, digest) in [
            ("firecracker", self.firecracker_sha256.as_str()),
            ("jailer", self.jailer_sha256.as_str()),
            ("kernel", self.kernel_sha256.as_str()),
        ] {
            if !valid_sha256_digest(digest) {
                return Err(Error::Invalid(format!(
                    "asset manifest has invalid {label} sha256 digest"
                )));
            }
        }
        Ok(())
    }
}

fn manifest_string(object: &Map<String, Value>, key: &str) -> Result<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid(format!("asset manifest field {key} is not a string")))
}

fn valid_sha256_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestDecision {
    Bootstrap,
    Verify,
    Reseed,
}

/// Missing provenance is a bootstrap, while a version or snapshot-format
/// change is an explicit reseed. Only an exact version match may verify files
/// against the recorded identities.
fn manifest_decision(
    manifest: Option<&AssetManifest>,
    firecracker_version: &str,
    snapshot_format_version: &str,
) -> ManifestDecision {
    match manifest {
        None => ManifestDecision::Bootstrap,
        Some(manifest)
            if manifest.firecracker_version == firecracker_version
                && manifest.snapshot_format_version == snapshot_format_version =>
        {
            ManifestDecision::Verify
        }
        Some(_) => ManifestDecision::Reseed,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestDecision {
    Match,
    Mismatch,
}

fn digest_decision(expected: &str, actual: &str) -> DigestDecision {
    if expected.eq_ignore_ascii_case(actual) {
        DigestDecision::Match
    } else {
        DigestDecision::Mismatch
    }
}

fn manifest_path(root: &Path) -> PathBuf {
    assets_dir(root).join(MANIFEST_NAME)
}

fn trusted_manifest_attributes(regular: bool, uid: u32, mode: u32, expected_uid: u32) -> bool {
    regular && uid == expected_uid && mode & 0o7777 == MANIFEST_MODE
}

fn validate_manifest_metadata(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink()
        || !trusted_manifest_attributes(
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode(),
            0,
        )
    {
        return Err(Error::Invalid(format!(
            "unsafe asset manifest: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Option<AssetManifest>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_manifest_metadata(path, &metadata)?;
    let contents = fs::read(path).map_err(|error| {
        Error::Invalid(format!(
            "cannot read asset manifest {}: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_slice(&contents).map_err(|error| {
        Error::Invalid(format!(
            "invalid asset manifest {}: {error}",
            path.display()
        ))
    })?;
    AssetManifest::from_json(value).map(Some)
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Writes provenance through a private sibling and a same-filesystem rename.
/// The file and containing directory are synced so a crash cannot expose a
/// truncated manifest or leave the old manifest half-replaced.
fn write_manifest(path: &Path, manifest: &AssetManifest) -> Result<()> {
    manifest.validate()?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_manifest_metadata(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path.parent().ok_or_else(|| {
        Error::Invalid(format!("asset manifest has no parent: {}", path.display()))
    })?;
    let staged = unique_staging_path(path);
    let mut owns_stage = false;

    let result = (|| -> Result<()> {
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(MANIFEST_MODE)
                .open(&staged)?;
            owns_stage = true;
            let encoded = serde_json::to_vec(&manifest.to_json())?;
            file.write_all(&encoded)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        fs::set_permissions(&staged, fs::Permissions::from_mode(MANIFEST_MODE))?;
        File::open(&staged)?.sync_all()?;
        fs::rename(&staged, path)?;
        File::open(parent)?.sync_all()?;
        let metadata = fs::symlink_metadata(path)?;
        validate_manifest_metadata(path, &metadata)
    })();
    let cleanup = if owns_stage {
        remove_file_if_present(&staged)
    } else {
        Ok(())
    };
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn release_tarball(root: &Path) -> Result<PathBuf> {
    let cache = cache_dir(root);
    fs::create_dir_all(&cache)?;
    let tarball = cache.join(format!("firecracker-{FC_VERSION}-x86_64.tgz"));
    match fs::symlink_metadata(&tarball) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0 =>
        {
            return Ok(tarball);
        }
        Ok(_) => {
            return Err(Error::Invalid(format!(
                "unsafe cached Firecracker release: {}",
                tarball.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    curl_to_file(FC_URL, &tarball)?;
    let metadata = fs::symlink_metadata(&tarball)?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(Error::Invalid(format!(
            "unsafe downloaded Firecracker release: {}",
            tarball.display()
        )));
    }
    Ok(tarball)
}
fn install_from_tarball(tarball: &Path, member: &str, dst: &Path) -> Result<()> {
    let unpack = unique_staging_path(dst);
    let staged = unique_staging_path(dst);
    let mut owns_unpack = false;
    let mut owns_stage = false;
    let result = (|| -> Result<()> {
        let mut unpack_builder = fs::DirBuilder::new();
        unpack_builder.mode(0o700).create(&unpack)?;
        owns_unpack = true;
        let output = std::process::Command::new("tar")
            .arg("--no-same-owner")
            .arg("--no-same-permissions")
            .arg("-xzf")
            .arg(tarball)
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
        // The release carries its own SHA256SUMS, so both binaries are
        // verified against a digest shipped beside the release artifacts.
        let digest = pick_sums_digest(&fs::read_to_string(unpack.join("SHA256SUMS"))?, member)?;
        let binary = unpack.join(member);
        let metadata = fs::symlink_metadata(&binary)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Invalid(format!(
                "release member is not a regular file: {}",
                binary.display()
            )));
        }
        // Copy into a fresh root-created inode. Publishing the archive inode
        // directly would preserve any archive uid, hardlinks, and writable
        // descriptors acquired before its ownership was normalized.
        let mut source = File::open(&binary)?;
        let mut staged_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)?;
        owns_stage = true;
        io::copy(&mut source, &mut staged_file)?;
        staged_file.sync_all()?;
        drop(staged_file);
        let actual = sha256_file(&staged)?;
        if digest_decision(&digest, &actual) == DigestDecision::Mismatch {
            return Err(Error::Invalid(format!(
                "sha256 mismatch for {member}: expected {digest}, got {actual}"
            )));
        }
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        File::open(&staged)?.sync_all()?;
        fs::rename(&staged, dst)?;
        Ok(())
    })();
    let cleanup_stage = if owns_stage {
        remove_file_if_present(&staged)
    } else {
        Ok(())
    };
    let cleanup_unpack = if owns_unpack {
        match fs::remove_dir_all(&unpack) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    } else {
        Ok(())
    };
    match (result, cleanup_stage, cleanup_unpack) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) => Err(error),
        (Ok(()), Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

fn install_firecracker(tarball: &Path, dst: &Path) -> Result<()> {
    let member = format!("firecracker-{FC_VERSION}-x86_64");
    install_from_tarball(tarball, &member, dst)
}

fn install_jailer(tarball: &Path, dst: &Path) -> Result<()> {
    let member = format!("jailer-{FC_VERSION}-x86_64");
    install_from_tarball(tarball, &member, dst)
}

/// Whether metadata describes an executable asset trusted by the daemon.
///
/// Keep the attribute check separate from filesystem access so tests can
/// exercise the expected uid without impersonating root.
fn trusted_executable_attributes(regular: bool, uid: u32, mode: u32, expected_uid: u32) -> bool {
    regular && uid == expected_uid && mode & 0o111 != 0 && mode & 0o022 == 0
}

fn trusted_kernel_attributes(regular: bool, uid: u32, mode: u32, expected_uid: u32) -> bool {
    regular && uid == expected_uid && mode & 0o444 != 0 && mode & 0o022 == 0
}

/// Returns whether an asset is absent, or rejects an unsafe existing asset.
/// `symlink_metadata` is required: following an existing link would turn a
/// user-controlled path into a root-executed program.
#[cfg(test)]
fn executable(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(Error::Invalid(format!(
            "executable asset is a symlink: {}",
            path.display()
        )));
    }
    if !trusted_executable_attributes(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.mode(),
        0,
    ) {
        return Err(Error::Invalid(format!(
            "unsafe executable asset: {}",
            path.display()
        )));
    }
    Ok(true)
}

fn asset_digest(path: &Path, label: &str, executable_asset: bool) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::Invalid(format!(
            "cannot validate {label} asset {}: {error}",
            path.display()
        ))
    })?;
    let trusted = if executable_asset {
        trusted_executable_attributes(
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode(),
            0,
        )
    } else {
        trusted_kernel_attributes(
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode(),
            0,
        )
    };
    if metadata.file_type().is_symlink() || !trusted {
        return Err(Error::Invalid(format!(
            "unsafe {label} asset: {}",
            path.display()
        )));
    }
    let digest = sha256_file(path)?;
    // Detect a replacement during hashing before accepting the identity.
    let after = fs::symlink_metadata(path).map_err(|error| {
        Error::Invalid(format!(
            "cannot revalidate {label} asset {}: {error}",
            path.display()
        ))
    })?;
    let trusted_after = if executable_asset {
        trusted_executable_attributes(after.file_type().is_file(), after.uid(), after.mode(), 0)
    } else {
        trusted_kernel_attributes(after.file_type().is_file(), after.uid(), after.mode(), 0)
    };
    if after.file_type().is_symlink()
        || !trusted_after
        || after.uid() != metadata.uid()
        || after.ino() != metadata.ino()
        || after.size() != metadata.size()
    {
        return Err(Error::Invalid(format!(
            "{label} asset changed while hashing: {}",
            path.display()
        )));
    }
    Ok(digest)
}

fn verify_asset_digest(
    path: &Path,
    label: &str,
    expected: &str,
    executable_asset: bool,
) -> Result<()> {
    let actual = asset_digest(path, label, executable_asset)?;
    if digest_decision(expected, &actual) == DigestDecision::Mismatch {
        return Err(Error::Invalid(format!(
            "{label} asset sha256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn reseed_assets(root: &Path) -> Result<AssetManifest> {
    if !KERNEL_URL.starts_with("https://") {
        return Err(Error::Invalid(format!(
            "kernel source is not HTTPS: {KERNEL_URL}"
        )));
    }
    let tarball = release_tarball(root)?;
    install_firecracker(&tarball, &firecracker_bin(root))?;
    install_jailer(&tarball, &jailer_bin(root))?;
    // A kernel without a manifest has no provenance. Always fetch it afresh
    // before recording the first baseline digest, even if a file is present.
    let kernel = kernel_path(root);
    curl_to_file(KERNEL_URL, &kernel)?;
    let firecracker_sha256 = asset_digest(&firecracker_bin(root), "firecracker", true)?;
    let jailer_sha256 = asset_digest(&jailer_bin(root), "jailer", true)?;
    let kernel_sha256 = asset_digest(&kernel, "kernel", false)?;
    Ok(AssetManifest::current(
        firecracker_sha256,
        jailer_sha256,
        kernel_sha256,
    ))
}

fn verify_assets(root: &Path, manifest: &AssetManifest) -> Result<()> {
    verify_asset_digest(
        &firecracker_bin(root),
        "firecracker",
        &manifest.firecracker_sha256,
        true,
    )?;
    verify_asset_digest(&jailer_bin(root), "jailer", &manifest.jailer_sha256, true)?;
    verify_asset_digest(&kernel_path(root), "kernel", &manifest.kernel_sha256, false)
}

/// Fetches the hypervisor, jailer, and guest kernel once. Called before
/// `ensure_base` so a host with no network fails before building an image it
/// cannot boot. Provenance is established before returning and checked on
/// every matching-version restart.
pub fn ensure_assets(root: &Path) -> Result<()> {
    static ASSET_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    let _asset_guard = ASSET_LOCK.lock().unwrap_or_else(|error| error.into_inner());

    // The asset manifest is part of the same root trust boundary as state and
    // VM executables. Re-running this check also makes direct library callers
    // safe instead of relying only on the daemon's startup ordering.
    init_daemon_layout(root)?;
    let manifest = read_manifest(&manifest_path(root))?;
    match manifest_decision(manifest.as_ref(), FC_VERSION, FC_SNAPSHOT_VERSION) {
        ManifestDecision::Verify => manifest.as_ref().map_or_else(
            || Err(Error::Invalid("asset manifest disappeared".to_owned())),
            |manifest| verify_assets(root, manifest),
        ),
        ManifestDecision::Bootstrap | ManifestDecision::Reseed => {
            let fresh = reseed_assets(root)?;
            write_manifest(&manifest_path(root), &fresh)
        }
    }
}

#[cfg(test)]
mod asset_tests {
    use super::{
        AssetManifest, DigestDecision, ManifestDecision, digest_decision, executable,
        manifest_decision, manifest_path, read_manifest, trusted_executable_attributes,
        trusted_kernel_attributes, trusted_manifest_attributes, write_manifest,
    };
    use shinu_core::{FC_SNAPSHOT_VERSION, FC_VERSION, assets_dir};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("shinu-assets-{}", Uuid::new_v4()))
    }

    fn current_manifest() -> AssetManifest {
        AssetManifest::current("a".repeat(64), "b".repeat(64), "c".repeat(64))
    }

    #[test]
    fn manifest_json_records_version_format_and_all_asset_digests() {
        let manifest = current_manifest();
        let json = manifest.to_json();

        assert_eq!(json["firecracker_version"], FC_VERSION);
        assert_eq!(json["snapshot_format_version"], FC_SNAPSHOT_VERSION);
        assert_eq!(json["firecracker_sha256"], "a".repeat(64));
        assert_eq!(json["jailer_sha256"], "b".repeat(64));
        assert_eq!(json["kernel_sha256"], "c".repeat(64));
        assert_eq!(
            AssetManifest::from_json(json).expect("parse manifest"),
            manifest
        );
    }

    #[test]
    fn manifest_decisions_distinguish_bootstrap_verify_and_reseed() {
        let manifest = current_manifest();
        assert_eq!(
            manifest_decision(None, FC_VERSION, FC_SNAPSHOT_VERSION),
            ManifestDecision::Bootstrap
        );
        assert_eq!(
            manifest_decision(Some(&manifest), FC_VERSION, FC_SNAPSHOT_VERSION),
            ManifestDecision::Verify
        );
        assert_eq!(
            manifest_decision(Some(&manifest), "v-next", FC_SNAPSHOT_VERSION),
            ManifestDecision::Reseed
        );
        assert_eq!(
            manifest_decision(Some(&manifest), FC_VERSION, "next-format"),
            ManifestDecision::Reseed
        );
    }

    #[test]
    fn digest_decisions_are_case_insensitive_but_not_length_insensitive() {
        let expected = "a".repeat(64);
        assert_eq!(
            digest_decision(&expected, &expected.to_uppercase()),
            DigestDecision::Match
        );
        assert_eq!(
            digest_decision(&expected, &format!("b{}", &expected[1..])),
            DigestDecision::Mismatch
        );
        assert_eq!(
            digest_decision(&expected, &expected[..63]),
            DigestDecision::Mismatch
        );
    }

    #[test]
    fn manifest_attributes_require_a_root_owned_private_regular_file() {
        assert!(trusted_manifest_attributes(true, 0, 0o600, 0));
        assert!(!trusted_manifest_attributes(false, 0, 0o600, 0));
        assert!(!trusted_manifest_attributes(true, 1000, 0o600, 0));
        assert!(!trusted_manifest_attributes(true, 0, 0o644, 0));
        assert!(!trusted_manifest_attributes(true, 0, 0o400, 0));
    }

    #[test]
    fn kernel_attributes_require_root_owned_readable_nonwritable_file() {
        assert!(trusted_kernel_attributes(true, 0, 0o644, 0));
        assert!(trusted_kernel_attributes(true, 0, 0o400, 0));
        assert!(!trusted_kernel_attributes(true, 0, 0o200, 0));
        assert!(!trusted_kernel_attributes(true, 0, 0o664, 0));
    }

    #[test]
    fn atomic_manifest_write_sets_mode_and_cleans_staging_file() {
        let root = test_root();
        let assets = assets_dir(&root);
        std::fs::create_dir_all(&assets).expect("create fixture assets");
        std::fs::set_permissions(&assets, std::fs::Permissions::from_mode(0o755))
            .expect("set fixture assets mode");
        let path = manifest_path(&root);
        let manifest = current_manifest();

        write_manifest(&path, &manifest).expect("write manifest");

        let metadata = std::fs::symlink_metadata(&path).expect("manifest metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(
            std::fs::read_dir(&assets)
                .expect("read staging directory")
                .count(),
            1
        );
        assert_eq!(read_manifest(&path).expect("read manifest"), Some(manifest));

        std::fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn existing_unsafe_manifest_is_not_replaced() {
        let root = test_root();
        let assets = assets_dir(&root);
        std::fs::create_dir_all(&assets).expect("create fixture assets");
        let path = manifest_path(&root);
        std::fs::write(&path, b"original").expect("write fixture manifest");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set fixture manifest mode");

        assert!(write_manifest(&path, &current_manifest()).is_err());
        assert_eq!(
            std::fs::read(&path).expect("read fixture manifest"),
            b"original"
        );

        std::fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn executable_attributes_require_regular_root_owned_nonwritable_file() {
        assert!(trusted_executable_attributes(true, 0, 0o755, 0));
        assert!(!trusted_executable_attributes(false, 0, 0o755, 0));
        assert!(!trusted_executable_attributes(true, 1000, 0o755, 0));
        assert!(!trusted_executable_attributes(true, 0, 0o775, 0));
        assert!(!trusted_executable_attributes(true, 0, 0o644, 0));
    }

    #[test]
    fn existing_symlink_asset_is_rejected_without_following_target() {
        let root = test_root();
        std::fs::create_dir_all(&root).expect("create fixture root");
        let target = root.join("target");
        let link = root.join("asset");
        std::fs::write(&target, b"not a trusted binary").expect("write fixture target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("set fixture mode");
        symlink(&target, &link).expect("create asset symlink");

        let result = executable(&link);

        assert!(matches!(result, Err(super::Error::Invalid(_))));
        std::fs::remove_dir_all(root).expect("remove fixture");
    }
}
