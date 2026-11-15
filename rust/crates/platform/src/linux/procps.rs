//! What procps-ng 4.0.4 prints for one process in
//! `ps -axo user=,pid=,%cpu=,%mem=,rss=,command=`, the command the Go agent
//! runs for its process list (`internal/agentcore/system/process_collect_unix.go`).
//! The Rust agent runs no outside commands, so it reads `/proc` and applies
//! the same rules, taken from procps-ng 4.0.4 `src/ps/output.c` (`pr_pcpu`,
//! `pr_pmem`, `pr_args`, `do_pr_name`, `escape_str`), `library/pids.c`
//! (`TIME_ELAPSED`), `library/readproc.c` (`read_unvectored`,
//! `fill_cmdline_cvt`) and `library/escape.c` (`esc_all`, `esc_ctl`,
//! `escape_command`).

/// How `ps` escapes text: by whether its locale's character set is UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextMode {
    /// The C locale (or any other 8-bit one): control bytes become `.` and
    /// every byte from 0x80 becomes `?`.
    Plain,
    /// A UTF-8 locale: invalid sequences and control characters become `?`,
    /// other characters are kept.
    Utf8,
}

/// The width of the `user` column (procps format table: 8).
const USER_WIDTH: usize = 8;

/// `esc_all` and `escape_str` in an 8-bit locale. Both map the same way, so
/// applying them in turn is the same as once.
fn escape_plain(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| match b {
            0x00..=0x1f | 0x7f => b'.',
            0x80..=0xff => b'?',
            _ => b,
        })
        .collect()
}

/// The sequence length `esc_ctl` reads from a lead byte (`UTF_tab`), or
/// `None` for a byte that cannot start one.
fn utf8_lead_len(b: u8) -> Option<usize> {
    match b {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// `esc_ctl`: a bad lead or continuation byte, a C1 control (U+0080 to
/// U+009F) or a C0 control becomes `?`, one byte at a time.
fn esc_ctl(bytes: &mut [u8]) {
    let mut i = 0;
    while i < bytes.len() {
        let lead = bytes[i];
        let good = utf8_lead_len(lead).filter(|n| {
            i + n <= bytes.len()
                && !(lead == 0xc2
                    && (0x80..=0x9f).contains(&bytes.get(i + 1).copied().unwrap_or(0)))
                && bytes[i + 1..i + n]
                    .iter()
                    .all(|c| (0x80..=0xbf).contains(c))
        });
        match good {
            Some(n) => {
                if lead < 0x20 || lead == 0x7f {
                    bytes[i] = b'?';
                }
                i += n;
            }
            None => {
                bytes[i] = b'?';
                i += 1;
            }
        }
    }
}

/// `esc_ctl`, then `ps`'s `escape_str_utf8`, which turns each byte that
/// still does not decode into `?`.
fn escape_utf8(bytes: &[u8]) -> String {
    let mut bytes = bytes.to_vec();
    esc_ctl(&mut bytes);
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(std::iter::repeat_n('?', chunk.invalid().len()));
    }
    out
}

/// The escaped text, as `ps` prints it.
pub fn escape(bytes: &[u8], mode: TextMode) -> String {
    match mode {
        TextMode::Plain => String::from_utf8(escape_plain(bytes)).unwrap_or_default(),
        TextMode::Utf8 => escape_utf8(bytes),
    }
}

/// The `command` column. `cmdline` is `/proc/<pid>/cmdline` (empty when it
/// cannot be read); `comm` and `state` come from `/proc/<pid>/stat`.
///
/// With a command line: trailing NULs dropped, NULs and newlines turned
/// into spaces (`read_unvectored`), then escaped; `?` when nothing is left.
/// Without one (kernel threads, zombies): `[comm]`, plus ` <defunct>` for a
/// zombie (`escape_command`).
pub fn command_text(cmdline: &[u8], comm: &[u8], state: u8, mode: TextMode) -> String {
    if cmdline.is_empty() {
        let mut text = format!("[{}]", escape(comm, mode));
        if state == b'Z' {
            text.push_str(" <defunct>");
        }
        return text;
    }
    let end = cmdline.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    let joined: Vec<u8> = cmdline[..end]
        .iter()
        .map(|&b| if b == 0 || b == b'\n' { b' ' } else { b })
        .collect();
    let text = escape(&joined, mode);
    if text.is_empty() {
        "?".to_owned()
    } else {
        text
    }
}

/// The `user` column (`do_pr_name`): the escaped name when it fits in eight
/// cells, else its first seven bytes and `+` when the eighth byte is ASCII,
/// else the number.
pub fn user_text(name: Option<&str>, uid: u32, mode: TextMode) -> String {
    let Some(name) = name else {
        return uid.to_string();
    };
    let escaped = escape(name.as_bytes(), mode);
    if escaped.chars().count() <= USER_WIDTH {
        return escaped;
    }
    let bytes = escaped.as_bytes();
    if bytes.len() >= USER_WIDTH && bytes[USER_WIDTH - 1] < 127 {
        return format!("{}+", &escaped[..USER_WIDTH - 1]);
    }
    uid.to_string()
}

/// `%cpu` in tenths of a percent (`pr_pcpu` with `TIME_ELAPSED`): CPU ticks
/// used over ticks since the process started. `uptime_secs` is the first
/// number in `/proc/uptime`, read once per list as `ps` does.
pub fn cpu_tenths(busy_ticks: u64, start_ticks: u64, uptime_secs: f64, hertz: u64) -> u32 {
    let hertz_f = hertz as f64;
    // C: `boot_tics = up_secs * hertz` into an unsigned long long, and the
    // unsigned subtraction wraps for a process younger than one tick.
    let boot_ticks = (uptime_secs * hertz_f) as u64;
    let since_start = boot_ticks.wrapping_sub(start_ticks) as f64;
    let elapsed = if since_start > 0.0 {
        since_start / hertz_f
    } else {
        0.0
    };
    let jiffies = (elapsed * hertz_f) as u64;
    if jiffies == 0 {
        return 0;
    }
    // C assigns the unsigned long long quotient to an unsigned int.
    (busy_ticks.wrapping_mul(1000) / jiffies) as u32
}

/// The value Go parses from the `%cpu` column: `ps` prints whole percents
/// above 99.9.
pub fn cpu_percent(tenths: u32) -> f64 {
    if tenths > 999 {
        f64::from(tenths / 10)
    } else {
        f64::from(tenths) / 10.0
    }
}

/// `%mem` (`pr_pmem`): resident KiB over `MemTotal` KiB in tenths of a
/// percent, at most 99.9.
pub fn memory_percent(rss_kb: u64, mem_total_kb: u64) -> f64 {
    if mem_total_kb == 0 {
        return 0.0;
    }
    let tenths = (rss_kb.wrapping_mul(1000) / mem_total_kb).min(999);
    tenths as f64 / 10.0
}
