use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use shinu_core::{
    Error, FC_URL, FC_VERSION, KERNEL_URL, Result, assets_dir, cache_dir, firecracker_bin,
    jailer_bin, kernel_path,
};

use super::fetch::{curl_to_file, pick_sums_digest, sha256_file};

fn release_tarball(root: &Path) -> Result<PathBuf> {
    let cache = cache_dir(root);
    std::fs::create_dir_all(&cache)?;
    let tarball = cache.join(format!("firecracker-{FC_VERSION}-x86_64.tgz"));
    if !tarball.exists() {
        curl_to_file(FC_URL, &tarball)?;
    }
    Ok(tarball)
}

/// Extracts and verifies one binary from the official release tarball.
///
/// Keeping extraction in one path makes the firecracker and jailer artifacts
/// receive identical digest and permission checks.
fn install_from_tarball(tarball: &Path, member: &str, dst: &Path) -> Result<()> {
    let unpack = dst
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".unpack");
    let _ = std::fs::remove_dir_all(&unpack);
    std::fs::create_dir_all(&unpack)?;
    let result = (|| -> Result<()> {
        let output = std::process::Command::new("tar")
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
        let digest =
            pick_sums_digest(&std::fs::read_to_string(unpack.join("SHA256SUMS"))?, member)?;
        let binary = unpack.join(member);
        let actual = sha256_file(&binary)?;
        if actual != digest {
            return Err(Error::Invalid(format!(
                "sha256 mismatch for {member}: expected {digest}, got {actual}"
            )));
        }
        let staged = dst.with_extension("part");
        std::fs::rename(binary, &staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staged, dst)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&unpack);
    result
}

fn install_firecracker(root: &Path, dst: &Path) -> Result<()> {
    let tarball = release_tarball(root)?;
    let member = format!("firecracker-{FC_VERSION}-x86_64");
    install_from_tarball(&tarball, &member, dst)
}

fn install_jailer(root: &Path, dst: &Path) -> Result<()> {
    let tarball = release_tarball(root)?;
    let member = format!("jailer-{FC_VERSION}-x86_64");
    install_from_tarball(&tarball, &member, dst)
}

/// Whether metadata describes an executable asset trusted by the daemon.
///
/// Keep the attribute check separate from filesystem access so tests can
/// exercise the expected uid without impersonating root.
fn trusted_executable_attributes(regular: bool, uid: u32, mode: u32, expected_uid: u32) -> bool {
    regular && uid == expected_uid && mode & 0o111 != 0 && mode & 0o022 == 0
}

/// Returns whether an asset is absent, or rejects an unsafe existing asset.
/// `symlink_metadata` is required: following an existing link would turn a
/// user-controlled path into a root-executed program.
fn executable(path: &Path) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
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

/// Fetches the hypervisor, jailer, and guest kernel once. Called before
/// `ensure_base` so a host with no network fails before building an image it
/// cannot boot.
pub fn ensure_assets(root: &Path) -> Result<()> {
    std::fs::create_dir_all(assets_dir(root))?;
    let fc = firecracker_bin(root);
    if !executable(&fc)? {
        install_firecracker(root, &fc)?;
    }
    let jailer = jailer_bin(root);
    if !executable(&jailer)? {
        install_jailer(root, &jailer)?;
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

#[cfg(test)]
mod asset_tests {
    use super::{executable, trusted_executable_attributes};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("shinu-assets-{}", Uuid::new_v4()))
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
