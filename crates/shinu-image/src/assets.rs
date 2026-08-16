use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use shinu_core::{
    assets_dir, cache_dir, firecracker_bin, jailer_bin, kernel_path, Error, Result, FC_URL,
    FC_VERSION, KERNEL_URL,
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
        let digest = pick_sums_digest(
            &std::fs::read_to_string(unpack.join("SHA256SUMS"))?,
            member,
        )?;
        let binary = unpack.join(member);
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

fn executable(path: &Path) -> bool {
    path.metadata()
        .map(|metadata| {
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
        })
        .unwrap_or(false)
}

/// Fetches the hypervisor, jailer, and guest kernel once. Called before
/// `ensure_base` so a host with no network fails before building an image it
/// cannot boot.
pub fn ensure_assets(root: &Path) -> Result<()> {
    std::fs::create_dir_all(assets_dir(root))?;
    let fc = firecracker_bin(root);
    if !fc.exists() {
        install_firecracker(root, &fc)?;
    }
    let jailer = jailer_bin(root);
    if !executable(&jailer) {
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
