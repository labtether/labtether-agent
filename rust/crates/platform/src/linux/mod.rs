//! The Linux readers. Each module ports one Go file; see the module notes.

pub mod disk;
pub mod host;
mod lookpath;
pub mod metadata;
pub mod netid;
pub mod netlink;
pub mod process;
pub mod procfs;
pub mod sampler;
pub mod temperature;

pub use lookpath::{LookPathError, command_exists, look_path};
pub use metadata::{heartbeat_disk_available, host_metadata};
pub use sampler::{Sample, Sampler, SysPaths};

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Reads a whole file into `buf`, reusing its allocation. `/proc` files
/// report a size of zero, so this reads until the end.
pub fn read_into(path: &Path, buf: &mut String) -> io::Result<()> {
    buf.clear();
    File::open(path)?.read_to_string(buf).map(|_| ())
}

/// Go's `readTrimmedFile`: the trimmed text, or `None` when the file is
/// missing, empty or says `None` (some firmware fills DMI fields so).
pub fn read_trimmed(path: &Path) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty() && value != "None").then(|| value.to_owned())
}

#[cfg(test)]
mod tests;
