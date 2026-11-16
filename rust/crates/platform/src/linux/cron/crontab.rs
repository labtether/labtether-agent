//! Go's crontab reading (`CollectCrontabs`, `collectCrontabsFromPathsWithFS`,
//! `parseCrontabData`).
//!
//! Files: every entry of each user folder that is not a folder (the file
//! name is the user), then every such entry of `/etc/cron.d` (user from the
//! sixth word), then `/etc/crontab`. Entries come in name order, dot files
//! included; a symbolic link is read through, as Go's `os.ReadFile` does.
//!
//! Lines: blank lines, `#` comments and environment lines (an `=`, unless
//! the line starts with `*`, `@`, or a digit and is two or more long) are
//! skipped. `@reboot`-style lines need two words (three in system files);
//! others need six (seven), the schedule being the first five. The command
//! is the remaining words joined by single spaces.
//!
//! Errors: a folder or file that cannot be read is reported, a missing one
//! only when no source could be read at all; the readable sources' entries
//! are kept either way.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::{Entry, combine_errors};
use crate::linux::tool_output::gotext::{lossy, path_error, scan_lines};

/// Where Go looks for crontabs.
#[derive(Debug, Clone)]
pub struct CrontabPaths {
    pub user_dirs: Vec<PathBuf>,
    pub cron_d: PathBuf,
    pub system: PathBuf,
}

impl Default for CrontabPaths {
    /// Go's `CollectCrontabs` paths.
    fn default() -> Self {
        Self {
            user_dirs: vec![
                PathBuf::from("/var/spool/cron/crontabs"),
                PathBuf::from("/var/spool/cron"),
            ],
            cron_d: PathBuf::from("/etc/cron.d"),
            system: PathBuf::from("/etc/crontab"),
        }
    }
}

/// Go's `parseCrontabData`. `system_style` files carry a user column.
pub fn parse_crontab(data: &[u8], default_user: &str, system_style: bool) -> Vec<Entry> {
    let mut entries = Vec::new();
    for line in scan_lines(data).0 {
        let line = lossy(line);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let first = line.as_bytes()[0];
        if line.contains('=')
            && first != b'*'
            && first != b'@'
            && (line.len() < 2 || !first.is_ascii_digit())
        {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (schedule_words, min_fields) = if first == b'@' { (1, 2) } else { (5, 6) };
        let min_fields = if system_style {
            min_fields + 1
        } else {
            min_fields
        };
        if fields.len() < min_fields {
            continue;
        }
        let (user, command_start) = if system_style {
            (fields[schedule_words].to_owned(), schedule_words + 1)
        } else {
            (default_user.to_owned(), schedule_words)
        };
        entries.push(Entry {
            source: "crontab",
            schedule: fields[..schedule_words].join(" "),
            command: fields[command_start..].join(" "),
            user,
            next_run: String::new(),
        });
    }
    entries
}

/// Go's `os.ReadFile`, with its error text (`open ...` or `read ...`).
fn read_file(path: &Path) -> Result<Vec<u8>, (String, io::Error)> {
    let mut file = File::open(path).map_err(|e| (path_error("open", path, &e), e))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| (path_error("read", path, &e), e))?;
    Ok(data)
}

/// Go's `os.ReadDir`: the names of entries that are not folders (a link
/// to a folder counts as a file), sorted by name.
fn read_dir_files(dir: &Path) -> Result<Vec<PathBuf>, (String, io::Error)> {
    // Go reports a folder it cannot list, or a file given as one, as
    // `open <path>: <reason>`.
    let entries = std::fs::read_dir(dir).map_err(|e| (path_error("open", dir, &e), e))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| (path_error("readdirent", dir, &e), e))?;
        let is_dir = entry
            .file_type()
            .map_err(|e| (path_error("lstat", &entry.path(), &e), e))?
            .is_dir();
        if !is_dir {
            files.push(entry.path());
        }
    }
    files.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    Ok(files)
}

fn file_name(path: &Path) -> String {
    lossy(path.file_name().unwrap_or_default().as_encoded_bytes())
}

/// The failures Go collects, in the order it meets them.
#[derive(Default)]
struct Failures {
    readable: usize,
    failed: Vec<String>,
    missing: Vec<String>,
}

impl Failures {
    /// Go's `recordSourceFailure`: a missing source is kept apart.
    fn source(&mut self, kind: &str, path: &Path, (text, error): (String, io::Error)) {
        let wrapped = format!("{kind} {}: {text}", show(path));
        if error.kind() == io::ErrorKind::NotFound {
            self.missing.push(wrapped);
        } else {
            self.failed.push(wrapped);
        }
    }

    /// A file inside a readable folder: always a failure, even when missing.
    fn file(&mut self, kind: &str, path: &Path, text: &str) {
        self.failed.push(format!("{kind} {}: {text}", show(path)));
    }

    /// Go's final error text, if any.
    fn error(self) -> Option<String> {
        if self.readable == 0 {
            let all = self.failed.into_iter().chain(self.missing);
            return Some(match combine_errors(all) {
                Some(text) => format!("no configured crontab source is readable: {text}"),
                None => "no configured crontab source is readable".to_owned(),
            });
        }
        combine_errors(self.failed)
            .map(|text| format!("some crontab sources could not be read: {text}"))
    }
}

fn show(path: &Path) -> String {
    lossy(path.as_os_str().as_encoded_bytes())
}

/// Reads every file of a folder Go lists; user files take the user from
/// the file name, system files from their sixth word.
fn read_folder(
    dir: &Path,
    kinds: (&str, &str),
    user_files: bool,
    entries: &mut Vec<Entry>,
    failures: &mut Failures,
) {
    match read_dir_files(dir) {
        Err(error) => failures.source(kinds.0, dir, error),
        Ok(files) => {
            failures.readable += 1;
            for path in files {
                match read_file(&path) {
                    Ok(data) if user_files => {
                        entries.extend(parse_crontab(&data, &file_name(&path), false))
                    }
                    Ok(data) => entries.extend(parse_crontab(&data, "", true)),
                    Err((text, _)) => failures.file(kinds.1, &path, &text),
                }
            }
        }
    }
}

/// Go's `collectCrontabsFromPathsWithFS`: the entries, and the error text
/// Go returns with them, if any.
pub fn collect_crontabs(paths: &CrontabPaths) -> (Vec<Entry>, Option<String>) {
    let mut entries = Vec::new();
    let mut failures = Failures::default();
    let user_kinds = ("read user crontab directory", "read user crontab");
    for dir in &paths.user_dirs {
        read_folder(dir, user_kinds, true, &mut entries, &mut failures);
    }
    let system_kinds = ("read system crontab directory", "read system crontab");
    read_folder(
        &paths.cron_d,
        system_kinds,
        false,
        &mut entries,
        &mut failures,
    );
    match read_file(&paths.system) {
        Err(error) => failures.source("read system crontab", &paths.system, error),
        Ok(data) => {
            failures.readable += 1;
            entries.extend(parse_crontab(&data, "", true));
        }
    }
    (entries, failures.error())
}
