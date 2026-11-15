//! Go's `command_readonly.go`: the allowlisted readers stay read-only and
//! away from secrets. `journalctl` may not rotate, vacuum or write files;
//! `cat`, `head`, `tail` and `grep` may not read the agent's own files or
//! common system secrets, and `grep` may not recurse.

use labtether_agent_config::gopath;

use crate::error::Refusal;
use crate::gotext::lower;
use crate::lists::{BUILTIN_PROTECTED_READ_PATHS, JOURNALCTL_CHANGING_OPTIONS};
use crate::parse::normalize_executable_name;

/// Go's `SetProtectedReadPaths` cleaning: trimmed, absolute, cleaned.
pub fn clean_protected_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.trim())
        .filter(|path| !path.is_empty() && gopath::is_abs(path))
        .map(gopath::clean)
        .collect()
}

/// Go's `validateReadOnlyCommand`, for a command an allowlist rule matched.
pub fn validate_read_only_command(args: &[String], protected: &[String]) -> Result<(), Refusal> {
    let name = normalize_executable_name(&args[0]);
    let rest = &args[1..];
    match name.as_str() {
        "journalctl" => {
            for arg in rest {
                let option = lower(arg.split('=').next().unwrap_or(""));
                if let Some(changing) = JOURNALCTL_CHANGING_OPTIONS
                    .iter()
                    .find(|changing| **changing == option)
                {
                    return Err(Refusal::JournalctlChangesLogs(changing));
                }
            }
        }
        "cat" | "head" | "tail" | "grep" => {
            for (index, arg) in rest.iter().enumerate() {
                if name == "grep" && grep_arg_recurses(arg, rest, index) {
                    return Err(Refusal::RecursiveGrep);
                }
                if let Some(candidate) = reader_path_candidates(&name, arg)
                    && read_path_protected(candidate, protected)
                {
                    return Err(Refusal::ProtectedRead(candidate.to_owned()));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Go's `readerPathCandidates`: a plain argument, the value of
/// `--option=VALUE`, and the file of grep's `-fFILE`.
fn reader_path_candidates<'a>(name: &str, arg: &'a str) -> Option<&'a str> {
    if !arg.starts_with('-') {
        return Some(arg);
    }
    if let Some(index) = arg.find('=') {
        return Some(&arg[index + 1..]);
    }
    if name == "grep"
        && !arg.starts_with("--")
        && let Some(index) = arg.find('f')
        && index > 0
        && index + 1 < arg.len()
    {
        return Some(&arg[index + 1..]);
    }
    None
}

/// Go's `grepArgRecurses`: -r, -R, --recursive, --dereference-recursive, or
/// -d/--directories with the value `recurse`.
fn grep_arg_recurses(arg: &str, args: &[String], index: usize) -> bool {
    let next = || args.get(index + 1).map(String::as_str).unwrap_or("");
    if arg == "--recursive" || arg == "--dereference-recursive" {
        return true;
    }
    if let Some(after) = arg.strip_prefix("--directories") {
        let value = after.strip_prefix('=').unwrap_or(after);
        let value = if value.is_empty() { next() } else { value };
        return value == "recurse";
    }
    if arg.starts_with('-') && !arg.starts_with("--") {
        for (position, flag) in arg[1..].char_indices() {
            match flag {
                'r' | 'R' => return true,
                'd' => {
                    let value = &arg[position + 2..];
                    let value = if value.is_empty() { next() } else { value };
                    return value == "recurse";
                }
                // The rest of the argument is this option's value.
                'e' | 'f' | 'm' | 'A' | 'B' | 'C' | 'D' => return false,
                _ => {}
            }
        }
    }
    false
}

/// Go's `filepath.EvalSymlinks` for an absolute, cleaned path: the real
/// path, or `None` when a part is missing or unreadable.
fn resolve(path: &str) -> Option<String> {
    let real = std::fs::canonicalize(path).ok()?;
    real.to_str().map(str::to_owned)
}

/// Go's `readPathProtected`. A relative candidate is taken from the agent's
/// current folder at check time, as in Go; symlinks are followed on both
/// the candidate and each protected root.
fn read_path_protected(candidate: &str, protected: &[String]) -> bool {
    if candidate.is_empty() || candidate == "-" {
        return false;
    }
    let mut path = candidate.to_owned();
    if !gopath::is_abs(&path)
        && let Some(cwd) = std::env::current_dir()
            .ok()
            .and_then(|dir| dir.to_str().map(str::to_owned))
    {
        path = gopath::join(&[&cwd, &path]);
    }
    let path = gopath::clean(&path);
    let mut targets = vec![path.clone()];
    if let Some(real) = resolve(&path).filter(|real| *real != path) {
        targets.push(real);
    }
    let roots = BUILTIN_PROTECTED_READ_PATHS
        .iter()
        .map(|root| (*root).to_owned())
        .chain(protected.iter().cloned());
    for root in roots {
        let mut root_targets = vec![root.clone()];
        if let Some(real) = resolve(&root).filter(|real| *real != root) {
            root_targets.push(real);
        }
        let hit = targets
            .iter()
            .any(|target| root_targets.iter().any(|root| path_within(target, root)));
        if hit {
            return true;
        }
    }
    targets.iter().any(|target| secret_path_by_name(target))
}

/// Go's `secretPathByName`: SSH private keys, host keys, and any process's
/// environment or memory under `/proc`.
fn secret_path_by_name(path: &str) -> bool {
    let base = gopath::base(path);
    let parent = gopath::base(&gopath::dir(path));
    (path.starts_with("/proc/") && (base == "environ" || base == "mem"))
        || (base.starts_with("ssh_host_") && base.ends_with("_key"))
        || (parent == ".ssh" && base.starts_with("id_") && !base.ends_with(".pub"))
}

/// Go's `pathWithin` on Unix.
fn path_within(path: &str, root: &str) -> bool {
    let root_dir = format!("{}/", root.strip_suffix('/').unwrap_or(root));
    path == root || path.starts_with(&root_dir)
}
