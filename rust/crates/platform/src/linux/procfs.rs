//! Parsers for `/proc/stat`, `/proc/meminfo` and `/proc/net/dev`, ported
//! from Go's `provider_telemetry.go` and `provider_metadata.go`.

/// The aggregate CPU counters from the `cpu ` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    /// `idle` plus `iowait`.
    pub idle: u64,
    /// The sum of the first eight columns. `guest` and `guest_nice` are left
    /// out: the kernel already counts them in `user` and `nice`.
    pub total: u64,
}

/// Why `/proc/stat` gave no CPU counters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CpuStatError {
    #[error("unexpected /proc/stat format")]
    TooFewFields,
    #[error("/proc/stat has a value that is not a number: {0:?}")]
    NotANumber(String),
    #[error("cpu line not found")]
    NoCpuLine,
}

/// Go's `readCPUSample`: the first line starting with `cpu `, at least four
/// numbers, every column parsed. Any bad column fails the whole line. Only
/// the first eight columns are added into the total.
pub fn parse_cpu_times(text: &str) -> Result<CpuTimes, CpuStatError> {
    let Some(line) = text.lines().find(|line| line.starts_with("cpu ")) else {
        return Err(CpuStatError::NoCpuLine);
    };
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return Err(CpuStatError::TooFewFields);
    }
    let mut times = CpuTimes::default();
    for (index, token) in fields[1..].iter().enumerate() {
        let value: u64 = token
            .parse()
            .map_err(|_| CpuStatError::NotANumber((*token).to_owned()))?;
        if index < 8 {
            times.total = times.total.wrapping_add(value);
        }
        if index == 3 || index == 4 {
            times.idle = times.idle.wrapping_add(value);
        }
    }
    Ok(times)
}

/// Go's CPU formula between two samples. The subtraction wraps like Go's
/// `uint64` arithmetic, so a counter that went backwards gives a value the
/// caller clamps to 0..100, as Go does.
pub fn cpu_percent(previous: CpuTimes, current: CpuTimes) -> f64 {
    let delta_idle = current.idle.wrapping_sub(previous.idle) as f64;
    let delta_total = current.total.wrapping_sub(previous.total) as f64;
    if delta_total > 0.0 {
        (1.0 - delta_idle / delta_total) * 100.0
    } else {
        0.0
    }
}

pub(crate) fn meminfo_kb(text: &str, key: &str) -> Option<u64> {
    let mut found = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(name), Some(value)) = (fields.next(), fields.next())
            && name == key
        {
            // Go keeps the last match and a parse error gives zero.
            found = Some(value.parse().unwrap_or(0));
        }
    }
    found
}

/// Go's `readMemoryUsagePercent`: `(MemTotal - MemAvailable) / MemTotal`.
/// Kernels before 3.14 have no `MemAvailable` line; then available is
/// `MemFree + Buffers + Cached`, at most `MemTotal`. A missing `MemTotal`
/// gives 0.
pub fn memory_used_percent(text: &str) -> f64 {
    let total = meminfo_kb(text, "MemTotal:").unwrap_or(0);
    let available = meminfo_kb(text, "MemAvailable:").unwrap_or_else(|| {
        let field = |key| meminfo_kb(text, key).unwrap_or(0);
        field("MemFree:")
            .wrapping_add(field("Buffers:"))
            .wrapping_add(field("Cached:"))
            .min(total)
    });
    if total == 0 || available >= total {
        return 0.0;
    }
    (total - available) as f64 / total as f64 * 100.0
}

/// Go's `readMemTotalBytes`: the first `MemTotal:` line, in bytes.
pub fn mem_total_bytes(text: &str) -> u64 {
    text.lines()
        .find(|line| line.starts_with("MemTotal:"))
        .and_then(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |kb| kb.wrapping_mul(1024))
}

fn net_dev_rows(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("Inter-") && !line.starts_with("face"))
}

/// Go's `readNetworkBytes`: received and sent bytes summed over every
/// interface except `lo`. A row with fewer than 16 numbers is skipped; a
/// column that does not parse adds nothing.
pub fn net_totals(text: &str) -> (u64, u64) {
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in net_dev_rows(text) {
        let Some(colon) = line.find(':').filter(|colon| *colon > 0) else {
            continue;
        };
        if line[..colon].trim() == "lo" {
            continue;
        }
        let fields: Vec<&str> = line[colon + 1..].split_whitespace().collect();
        if fields.len() < 16 {
            continue;
        }
        rx = rx.wrapping_add(fields[0].parse().unwrap_or(0));
        tx = tx.wrapping_add(fields[8].parse().unwrap_or(0));
    }
    (rx, tx)
}

/// Go's `readNetworkInterfaceCount`: rows with exactly one `:`, except `lo`.
pub fn interface_count(text: &str) -> usize {
    net_dev_rows(text)
        .filter(|line| {
            let mut parts = line.split(':');
            let name = parts.next().unwrap_or_default().trim();
            parts.next().is_some() && parts.next().is_none() && name != "lo"
        })
        .count()
}

/// Go's per-second rate: zero on the first sample, when no time passed, or
/// when the counter went down (an interface went away or was reset).
pub fn rate_per_sec(previous: f64, current: f64, seconds: f64) -> f64 {
    let delta = current - previous;
    if seconds > 0.0 && delta >= 0.0 {
        delta / seconds
    } else {
        0.0
    }
}
