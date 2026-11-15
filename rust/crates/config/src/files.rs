//! Bounded reads of the agent's own files, ported from Go's
//! `readBoundedRegularFile`: refuse a final symlink or any non-regular file,
//! refuse a file swapped between the check and the open, and cap the size.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Tokens and one-use enrollment tokens.
pub const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;
/// A CA certificate file.
pub const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;
/// The device private key.
pub const MAX_DEVICE_KEY_FILE_BYTES: u64 = 4 * 1024;
/// `enrollment-state.json` and `agent-config.json`.
pub const MAX_STATE_FILE_BYTES: u64 = 64 * 1024;

/// Why a bounded read failed.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("refusing a file that is not a regular file")]
    NotRegular,
    #[error("the file changed while it was being opened")]
    Changed,
    #[error("the file is larger than {0} bytes")]
    TooLarge(u64),
}

impl ReadError {
    /// True when the file does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::NotFound)
    }
}

/// Reads one regular file of at most `max_bytes`.
pub fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ReadError> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(ReadError::NotRegular);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() || opened.dev() != before.dev() || opened.ino() != before.ino()
    {
        return Err(ReadError::Changed);
    }
    if opened.len() > max_bytes {
        return Err(ReadError::TooLarge(max_bytes));
    }
    let mut data = Vec::with_capacity(opened.len() as usize);
    file.by_ref().take(max_bytes + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max_bytes {
        return Err(ReadError::TooLarge(max_bytes));
    }
    Ok(data)
}

/// Reads a bounded text file and trims surrounding white space.
pub fn read_trimmed(path: &Path, max_bytes: u64) -> Result<String, ReadError> {
    let data = read_bounded(path, max_bytes)?;
    Ok(String::from_utf8_lossy(&data).trim().to_owned())
}
