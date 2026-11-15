//! Go's `exec.LookPath` for a bare command name, used only to tell whether a
//! program is installed. Nothing is run.

use std::path::Path;

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

/// True when `name` is found in `search_path` (the agent's `PATH`). As in
/// Go, an empty entry means the current folder, and a match found through a
/// relative entry is refused (`exec.ErrDot`), so it counts as not found.
pub fn command_exists(name: &str, search_path: &str) -> bool {
    if name.is_empty() || name.contains('/') {
        return false;
    }
    for dir in search_path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate = Path::new(dir).join(name);
        if executable(&candidate) {
            return Path::new(dir).is_absolute();
        }
    }
    false
}
