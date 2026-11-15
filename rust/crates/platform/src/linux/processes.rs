//! The process list behind `process.list`: every process in `/proc`, with
//! the columns `ps -axo user=,pid=,%cpu=,%mem=,rss=,command=` prints (see
//! `procps.rs`), then read back the way Go's `parseProcessRows` reads that
//! output (`internal/agentcore/system/process_collect_unix.go`): fields
//! split on white space, the command joined with single spaces, the name
//! taken from the command's first word after its last `/`.
//!
//! Go falls back to BusyBox's `ps -o user=,pid=,rss=,args=` (no CPU or
//! memory percent) when the first form fails. This reader never needs it.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use super::procfs::meminfo_kb;
use super::procps::{TextMode, command_text, cpu_percent, cpu_tenths, memory_percent, user_text};

/// One row of the list, as Go fills `protocol.ProcessInfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessRow {
    pub pid: i64,
    pub name: String,
    pub user: String,
    pub cpu_pct: f64,
    pub mem_pct: f64,
    /// Resident memory in KiB.
    pub mem_rss: i64,
    pub command: String,
}

/// Where the list is read from; tests point these at a made-up tree.
#[derive(Debug, Clone)]
pub struct ProcPaths {
    pub proc: PathBuf,
    pub passwd: PathBuf,
    /// Clock ticks per second (`sysconf(_SC_CLK_TCK)`).
    pub hertz: u64,
}

impl Default for ProcPaths {
    fn default() -> Self {
        Self {
            proc: PathBuf::from("/proc"),
            passwd: PathBuf::from("/etc/passwd"),
            hertz: rustix::param::clock_ticks_per_second(),
        }
    }
}

/// The `/proc/<pid>/stat` fields the list uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFields {
    /// The command name between the first `(` and the last `)`.
    pub comm: Vec<u8>,
    pub state: u8,
    /// `utime + stime` in clock ticks.
    pub busy_ticks: u64,
    /// Start time in clock ticks after boot.
    pub start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. The name may hold spaces and parentheses, so
/// the fields are counted from the last `)`.
pub fn parse_stat(bytes: &[u8]) -> Option<StatFields> {
    let open = bytes.iter().position(|b| *b == b'(')?;
    let close = bytes.iter().rposition(|b| *b == b')')?;
    let comm = bytes.get(open + 1..close)?.to_vec();
    let rest = std::str::from_utf8(bytes.get(close + 1..)?).ok()?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
    let number = |index: usize| fields.get(index)?.parse::<u64>().ok();
    // After the name: state (field 3), utime (14), stime (15), start (22).
    Some(StatFields {
        comm,
        state: *fields.first()?.as_bytes().first()?,
        busy_ticks: number(11)?.wrapping_add(number(12)?),
        start_ticks: number(19)?,
    })
}

/// The effective user ID and `VmRSS` in KiB from `/proc/<pid>/status`.
/// Kernel threads have no `VmRSS`; that reads as 0, as in `ps`.
pub fn parse_status(text: &str) -> Option<(u32, u64)> {
    let mut euid = None;
    let mut rss = 0;
    for line in text.lines() {
        if let Some(ids) = line.strip_prefix("Uid:") {
            euid = ids.split_whitespace().nth(1)?.parse().ok();
        } else if let Some(value) = line.strip_prefix("VmRSS:") {
            rss = value.split_whitespace().next()?.parse().unwrap_or(0);
        }
    }
    Some((euid?, rss))
}

/// User names by ID from `/etc/passwd`; the first line for an ID wins, as
/// `getpwuid` scans the file.
pub fn parse_passwd(text: &str) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for line in text.lines() {
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>() {
            names.entry(uid).or_insert_with(|| name.to_owned());
        }
    }
    names
}

/// The first number in `/proc/uptime`.
pub fn parse_uptime(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// Go's row parsing applied to one `ps` line: the command is the words
/// after the five numeric columns joined by one space, and a line with no
/// command words is skipped.
pub fn go_row(
    pid: i64,
    user: String,
    cpu_pct: f64,
    mem_pct: f64,
    rss_kb: u64,
    command: &str,
) -> Option<ProcessRow> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let first = words.first()?;
    let name = first.rsplit('/').next().unwrap_or(first).to_owned();
    Some(ProcessRow {
        pid,
        name,
        user,
        cpu_pct,
        mem_pct,
        mem_rss: i64::try_from(rss_kb).unwrap_or(i64::MAX),
        command: words.join(" "),
    })
}

/// Facts read once per list, as `ps` reads them once per run.
struct Snapshot {
    uptime_secs: f64,
    mem_total_kb: u64,
    users: HashMap<u32, String>,
}

/// One process, or `None` when it ended while being read.
fn read_process(
    dir: &Path,
    pid: i64,
    paths: &ProcPaths,
    snap: &Snapshot,
    mode: TextMode,
) -> Option<ProcessRow> {
    let stat = parse_stat(&std::fs::read(dir.join("stat")).ok()?)?;
    let (euid, rss_kb) = parse_status(&std::fs::read_to_string(dir.join("status")).ok()?)?;
    let cmdline = std::fs::read(dir.join("cmdline")).unwrap_or_default();
    let tenths = cpu_tenths(
        stat.busy_ticks,
        stat.start_ticks,
        snap.uptime_secs,
        paths.hertz,
    );
    let user = user_text(snap.users.get(&euid).map(String::as_str), euid, mode);
    let command = command_text(&cmdline, &stat.comm, stat.state, mode);
    let mem_pct = memory_percent(rss_kb, snap.mem_total_kb);
    go_row(pid, user, cpu_percent(tenths), mem_pct, rss_kb, &command)
}

/// Every process in PID order, as `ps -ax` lists them.
pub fn process_list_with(paths: &ProcPaths, mode: TextMode) -> io::Result<Vec<ProcessRow>> {
    let mut pids: Vec<i64> = std::fs::read_dir(&paths.proc)?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|pid| *pid > 0)
        .collect();
    pids.sort_unstable();
    let read = |name: &str| std::fs::read_to_string(paths.proc.join(name)).unwrap_or_default();
    let snap = Snapshot {
        uptime_secs: parse_uptime(&read("uptime")).unwrap_or(0.0),
        mem_total_kb: meminfo_kb(&read("meminfo"), "MemTotal:").unwrap_or(0),
        users: parse_passwd(&std::fs::read_to_string(&paths.passwd).unwrap_or_default()),
    };
    Ok(pids
        .into_iter()
        .filter_map(|pid| read_process(&paths.proc.join(pid.to_string()), pid, paths, &snap, mode))
        .collect())
}

/// Every process on this host.
pub fn process_list(mode: TextMode) -> io::Result<Vec<ProcessRow>> {
    process_list_with(&ProcPaths::default(), mode)
}
