//! Extent-aware operations on complete, immutable checkpoint memory images.

use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const CHUNK: usize = 2 * 1024 * 1024;
const ZERO_PAGE: [u8; 4096] = [0; 4096];

/// The kernel's data ranges, excluding holes. A seek failure is not an empty image.
pub(crate) fn data_extents(file: &File, size: u64) -> impl Iterator<Item = io::Result<Range<u64>>> {
    let mut offset = 0;
    std::iter::from_fn(move || {
        if offset >= size {
            return None;
        }
        let next = match seek(file, offset, libc::SEEK_DATA) {
            Ok(start) => seek(file, start, libc::SEEK_HOLE).and_then(|end| {
                if start < offset || end <= start || start >= size {
                    return Err(io::Error::other("invalid snapshot extent"));
                }
                Ok(start..end.min(size))
            }),
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => return None,
            Err(error) => Err(error),
        };
        offset = next.as_ref().map_or(size, |range| range.end);
        Some(next)
    })
}

fn seek(file: &File, offset: u64, whence: libc::c_int) -> io::Result<u64> {
    let offset = i64::try_from(offset).map_err(io::Error::other)?;
    // SAFETY: file owns the descriptor, and lseek takes no pointers.
    let result = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
    u64::try_from(result).map_err(|_| io::Error::last_os_error())
}

/// Storage allocated to this inode (not its filesystem-exclusive cost) and its
/// logical holes before and after punching. All figures are bytes.
#[derive(Debug, serde::Serialize)]
pub struct SparsifyStats {
    pub logical_bytes: u64,
    pub hole_bytes_before: u64,
    pub hole_bytes_after: u64,
    pub allocated_bytes_before: u64,
    pub allocated_bytes_after: u64,
}

fn hole_bytes(file: &File, size: u64) -> io::Result<u64> {
    data_extents(file, size).try_fold(size, |holes, range| {
        let range = range?;
        Ok(holes - (range.end - range.start))
    })
}

fn punch(file: &File, range: Range<u64>) -> io::Result<()> {
    let offset = i64::try_from(range.start).map_err(io::Error::other)?;
    let len = i64::try_from(range.end - range.start).map_err(io::Error::other)?;
    // SAFETY: file owns a writable descriptor; punch preserves the file length.
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            len,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Punch only wholly zero, aligned 2 MiB chunks. Caller must own the unpublished
/// image or ensure no VM is using the image and prevent concurrent writers.
pub fn sparsify(memory: &Path) -> io::Result<SparsifyStats> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(memory)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(io::Error::other("snapshot memory is not a regular file"));
    }
    file.sync_all()?;
    let size = before.len();
    let hole_bytes_before = hole_bytes(&file, size)?;
    let mut buffer = vec![0; CHUNK];
    let chunk = CHUNK as u64;
    let mut punch_start = None;
    let mut examined = 0;
    for extent in data_extents(&file, size) {
        let extent = extent?;
        let start = (extent.start / chunk * chunk).max(examined);
        let end = extent.end.next_multiple_of(chunk).min(size / chunk * chunk);
        if start >= end {
            continue;
        }
        if start > examined
            && let Some(at) = punch_start.take()
        {
            punch(&file, at..examined)?;
        }
        for offset in (start..end).step_by(CHUNK) {
            file.read_exact_at(&mut buffer, offset)?;
            if buffer
                .chunks_exact(ZERO_PAGE.len())
                .all(|page| page == ZERO_PAGE)
            {
                punch_start.get_or_insert(offset);
            } else if let Some(at) = punch_start.take() {
                punch(&file, at..offset)?;
            }
        }
        examined = end;
    }
    if let Some(at) = punch_start {
        punch(&file, at..examined)?;
    }
    file.sync_all()?;
    Ok(SparsifyStats {
        logical_bytes: size,
        hole_bytes_before,
        hole_bytes_after: hole_bytes(&file, size)?,
        allocated_bytes_before: before.blocks() * 512,
        allocated_bytes_after: file.metadata()?.blocks() * 512,
    })
}

/// Run in the cache charging cgroup. Suppress speculative readahead across
/// extent boundaries; only data extents are read into the page cache.
pub fn warm_file(memory: &Path) -> io::Result<()> {
    let file = File::open(memory)?;
    file.sync_all()?;
    for advice in [libc::POSIX_FADV_DONTNEED, libc::POSIX_FADV_RANDOM] {
        // SAFETY: the descriptor is open and a zero length means to EOF.
        let status = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, advice) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
    }
    let mut buffer = vec![0; CHUNK];
    for extent in data_extents(&file, file.metadata()?.len()) {
        let mut extent = extent?;
        while extent.start < extent.end {
            let bytes = usize::try_from((extent.end - extent.start).min(CHUNK as u64))
                .map_err(io::Error::other)?;
            file.read_exact_at(&mut buffer[..bytes], extent.start)?;
            extent.start += bytes as u64;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn only_whole_zero_chunks_are_punched_and_warming_keeps_them_holes() {
        let path = std::env::temp_dir().join(format!("shinu-sparse-{}", uuid::Uuid::new_v4()));
        let mut contents = vec![0; 4 * CHUNK + 4096];
        // Isolate one nonzero byte so punching its otherwise zero chunk fails the comparison.
        contents[3 * CHUNK - 1] = 0x91;
        let mut file = File::create_new(&path).unwrap();
        file.write_all(&contents).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let stats = sparsify(&path).unwrap();
        assert_eq!(stats.logical_bytes, (4 * CHUNK + 4096) as u64);
        assert_eq!(stats.hole_bytes_before, 0);
        assert_eq!(stats.hole_bytes_after, 3 * CHUNK as u64);
        assert_eq!(std::fs::read(&path).unwrap(), contents);
        warm_file(&path).unwrap();
        assert_eq!(sparsify(&path).unwrap().hole_bytes_before, 3 * CHUNK as u64);
        std::fs::remove_file(path).unwrap();
    }
}
