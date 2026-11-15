//! Atomic writes of the agent's state files, ported from Go's
//! `writeManagedFileAtomic`: a new file is written beside the target with its
//! final mode, synced, then renamed over the target. A symlink planted at the
//! target is replaced, never followed.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Mode for tokens, keys and enrollment state.
pub const PRIVATE: u32 = 0o600;
/// Mode for the public key, fingerprint and saved CA.
pub const PUBLIC: u32 = 0o644;

/// Writes `data` to `path` with `mode`, creating the folder (0700) if needed.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let dir_meta = fs::symlink_metadata(dir)?;
    if !dir_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing an unsafe state folder",
        ));
    }
    let (tmp_path, mut file) = create_temp(dir, mode)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn create_temp(dir: &Path, mode: u32) -> io::Result<(std::path::PathBuf, fs::File)> {
    for _ in 0..16 {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(|_| io::Error::other("no system randomness"))?;
        let name = format!(".labtether-tmp-{}", data_encoding::HEXLOWER.encode(&suffix));
        let tmp_path = dir.join(name);
        // create_new is O_CREAT|O_EXCL, which never follows a symlink.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a temporary file",
    ))
}

/// Removes a file, treating "already gone" as success.
pub fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.raw_os_error() == Some(20) => Ok(()), // ENOTDIR, as in Go
        Err(error) => Err(error),
    }
}
