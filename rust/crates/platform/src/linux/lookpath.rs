//! Go's `exec.LookPath` for a bare command name: to tell whether a program
//! is installed, and to find the file the security crate starts.

use std::path::{Path, PathBuf};

use rustix::fs::{Access, AtFlags, CWD};
use rustix::io::Errno;

/// Go's `findExecutable` on Unix: an existing file that is not a folder and
/// that this process may run. Where `faccessat` is unavailable or refused
/// by a sandbox, any execute bit counts, as in Go.
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.is_dir() {
        return false;
    }
    match rustix::fs::accessat(CWD, path, Access::EXEC_OK, AtFlags::EACCESS) {
        Ok(()) => true,
        Err(Errno::NOSYS | Errno::PERM) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Why [`look_path`] found no program, in Go's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookPathError {
    /// `exec.ErrNotFound`: no entry of the search path holds the program.
    NotFound,
    /// `exec.ErrDot`: the first match came through a relative entry (an
    /// empty entry means the current folder).
    RelativeToCurrentDir,
}

/// Go's `exec.LookPath` for a bare name (no `/`) on Unix: the first entry of
/// `search_path` (the agent's `PATH`) that holds an executable file of that
/// name. A first match through a relative entry is refused, as in Go.
pub fn look_path(name: &str, search_path: &str) -> Result<PathBuf, LookPathError> {
    for dir in search_path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate = Path::new(dir).join(name);
        if executable(&candidate) {
            if !Path::new(dir).is_absolute() {
                return Err(LookPathError::RelativeToCurrentDir);
            }
            return Ok(candidate);
        }
    }
    Err(LookPathError::NotFound)
}

/// True when `name` is found in `search_path` (the agent's `PATH`). As in
/// Go, an empty entry means the current folder, and a match found through a
/// relative entry is refused (`exec.ErrDot`), so it counts as not found.
pub fn command_exists(name: &str, search_path: &str) -> bool {
    !name.is_empty() && !name.contains('/') && look_path(name, search_path).is_ok()
}
