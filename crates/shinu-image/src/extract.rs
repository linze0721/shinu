use std::path::Path;

use shinu_core::{Error, Image, Result, cache_dir};

use super::fetch::{oci_layer_member, oci_manifest_member, tar_member};

/// Mounts an image read-write for image construction and guest authorization.
/// Callers comparing an existing image must use [`mount_image_read_only`].
pub fn mount_image(image: &Path, mnt: &Path) -> Result<()> {
    mount_image_with_options(image, mnt, false)
}

/// Mounts an existing image read-only so inspection cannot dirty a reflink
/// ancestor or change the source that later spaces inherit.
pub fn mount_image_read_only(image: &Path, mnt: &Path) -> Result<()> {
    mount_image_with_options(image, mnt, true)
}

fn mount_image_with_options(image: &Path, mnt: &Path, read_only: bool) -> Result<()> {
    std::fs::create_dir_all(mnt)?;
    let output = std::process::Command::new("mount")
        .arg("-o")
        .arg(mount_options(read_only))
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

/// `noload` accompanies `ro` because a checkpoint is a reflink of a disk that
/// may have been captured while the guest was running, so its ext4 journal can
/// hold unreplayed records. The kernel refuses such a filesystem read-only
/// ("recovery required on readonly filesystem") and replaying the journal would
/// mean writing to it, dirtying an image every later space inherits. Skipping
/// the journal is correct here: inspection only ever reads.
pub(crate) fn mount_options(read_only: bool) -> &'static str {
    if read_only { "loop,ro,noload" } else { "loop" }
}

pub fn umount(mnt: &Path) -> Result<()> {
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

pub(super) fn extract_rootfs(root: &Path, image: Image, archive: &Path, mnt: &Path) -> Result<()> {
    match image {
        Image::Void => extract_archive(archive, mnt, ["-xJpf"], false),
        Image::Ubuntu => extract_archive(archive, mnt, ["-xzpf"], false),
        Image::Arch => extract_archive(archive, mnt, ["--zstd", "-xpf"], true),
        Image::Rocky => extract_oci_rootfs(root, archive, mnt),
    }
}

fn extract_archive<const N: usize>(
    archive: &Path,
    mnt: &Path,
    flags: [&str; N],
    strip_root: bool,
) -> Result<()> {
    let mut command = std::process::Command::new("tar");
    command
        .args(flags)
        .arg(archive)
        .arg("-C")
        .arg(mnt)
        .arg("--numeric-owner");
    if strip_root {
        command.arg("--strip-components=1");
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "extracting {} failed: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn extract_oci_rootfs(root: &Path, archive: &Path, mnt: &Path) -> Result<()> {
    let index = tar_member(archive, "index.json")?;
    let index = std::str::from_utf8(&index)
        .map_err(|error| Error::Invalid(format!("OCI index.json is not UTF-8: {error}")))?;
    let manifest_member = oci_manifest_member(index)?;
    let manifest = tar_member(archive, &manifest_member)?;
    let manifest = std::str::from_utf8(&manifest)
        .map_err(|error| Error::Invalid(format!("OCI manifest is not UTF-8: {error}")))?;
    let layer_member = oci_layer_member(manifest)?;

    // The OCI outer archive is compressed, while its layer is a plain tar
    // stream. Stage it in cache so extraction never buffers a rootfs in RAM.
    let stage = cache_dir(root).join("rocky-layer.tar.part");
    let _ = std::fs::remove_file(&stage);
    let result = (|| -> Result<()> {
        let file = std::fs::File::create(&stage)?;
        let output = std::process::Command::new("tar")
            .args(["-xJOf"])
            .arg(archive)
            .arg(&layer_member)
            .stdout(std::process::Stdio::from(file))
            .output()?;
        if !output.status.success() {
            return Err(Error::Invalid(format!(
                "extracting OCI layer {} failed: {}",
                layer_member,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        extract_archive(&stage, mnt, ["-xpf"], false)
    })();
    let _ = std::fs::remove_file(&stage);
    result
}
