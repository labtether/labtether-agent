//! One telemetry sample on macOS, ported from Go's `generic.Provider.Collect`
//! (`internal/agentplatform/generic/provider.go`) and the gopsutil v4.26.9
//! calls behind it:
//!
//! - CPU: `cpu.Percent(0, false)`: busy share of the host's CPU ticks
//!   (`HOST_CPU_LOAD_INFO`) since the last sample. gopsutil takes its first
//!   reading when the package loads, so the first sample covers the time
//!   since start; [`Sampler::new`] reads the same baseline.
//! - Memory: `mem.VirtualMemory().UsedPercent`: pages in use over all pages,
//!   where free means free plus inactive (`HOST_VM_INFO`, `hw.memsize`).
//! - Disk: `disk.Usage("/").UsedPercent`: `(f_blocks - f_bfree)` over that
//!   plus `f_bavail`, read on every sample (Go's macOS provider keeps no
//!   one-minute cache).
//! - Network: `net.IOCounters(false)`: the bytes of every interface,
//!   loopback included, summed. Go runs `netstat -ibdnW`; the same link
//!   counters come from the interface table here.
//! - Temperature: none. gopsutil reads it on Apple silicon through the
//!   private `IOHIDEventSystemClient` interface, and Go falls back to
//!   running `osx-cpu-temp` or `istats`. A Mac App Store app may use neither
//!   (public interfaces only, no outside program), so the sample carries no
//!   temperature, as Go's does on a host where every reading fails.

use std::path::PathBuf;
use std::time::Instant;

use labtether_agent_macos_sys::{self as sys, CpuTicks};

use super::{disk, route};

/// Where the sampler reads: the filesystem whose usage is reported.
#[derive(Debug, Clone)]
pub struct SysPaths {
    pub root: PathBuf,
}

impl Default for SysPaths {
    fn default() -> Self {
        Self { root: "/".into() }
    }
}

/// What one collection measured (Go's `TelemetrySample` values).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Sample {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub net_rx_bytes: f64,
    pub net_tx_bytes: f64,
    pub net_rx_bytes_per_sec: f64,
    pub net_tx_bytes_per_sec: f64,
    pub temp_celsius: Option<f64>,
}

/// A temperature failure to log. macOS reads no temperature, so there is
/// none.
#[derive(Debug)]
pub enum TemperatureError {}

impl std::fmt::Display for TemperatureError {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl std::error::Error for TemperatureError {}

/// Go's `ClampPercent`.
pub fn clamp_percent(value: f64) -> f64 {
    value.clamp(0.0, 100.0)
}

/// gopsutil's `calculateBusy` on two tick readings, each tick divided by
/// `clock` as gopsutil does (`ClocksPerSec`, the `_SC_CLK_TCK` value).
pub fn cpu_busy_percent(before: CpuTicks, after: CpuTicks, clock: f64) -> f64 {
    let split = |t: CpuTicks| {
        let [user, system, idle, nice] =
            [t.user, t.system, t.idle, t.nice].map(|v| f64::from(v) / clock);
        let total = user + system + idle + nice;
        (total, total - idle)
    };
    let (all1, busy1) = split(before);
    let (all2, busy2) = split(after);
    if busy2 <= busy1 {
        return 0.0;
    }
    if all2 <= all1 {
        return 100.0;
    }
    ((busy2 - busy1) / (all2 - all1) * 100.0).clamp(0.0, 100.0)
}

/// gopsutil's `VirtualMemory().UsedPercent` with its 32-bit page counts.
pub fn memory_used_percent(total_bytes: u64, page_size: u64, counts: sys::VmCounts) -> f64 {
    if page_size == 0 {
        return 0.0;
    }
    let total = (total_bytes / page_size) as u32;
    let available = counts.inactive.wrapping_add(counts.free);
    100.0 * f64::from(total.wrapping_sub(available)) / f64::from(total)
}

/// gopsutil's `disk.Usage(path).UsedPercent`.
pub fn disk_used_percent(capacity: &disk::Capacity) -> f64 {
    let size = u64::try_from(capacity.block_size).unwrap_or(0);
    let used = capacity
        .blocks
        .wrapping_sub(capacity.free_blocks)
        .wrapping_mul(size);
    let free = capacity.available_blocks.wrapping_mul(size);
    match used.wrapping_add(free) {
        0 => 0.0,
        all => used as f64 / all as f64 * 100.0,
    }
}

/// Go's `computeNetworkRates` for one direction: bytes per second, 0 when
/// the counter went down or no time passed.
pub fn rate_per_sec(previous: f64, current: f64, seconds: f64) -> f64 {
    let delta = current - previous;
    if seconds > 0.0 && delta >= 0.0 {
        delta / seconds
    } else {
        0.0
    }
}

/// The bytes received and sent by every interface, summed; `(0, 0)` when
/// the table cannot be read (gopsutil then returns an error and Go sends 0).
pub fn net_totals(links: &[route::Link]) -> (u64, u64) {
    links.iter().fold((0u64, 0u64), |(rx, tx), link| {
        (
            rx.wrapping_add(link.rx_bytes),
            tx.wrapping_add(link.tx_bytes),
        )
    })
}

/// The state kept between samples.
#[derive(Debug)]
pub struct Sampler {
    paths: SysPaths,
    clock: f64,
    page_size: u64,
    previous_cpu: Option<CpuTicks>,
    previous_net: Option<(f64, f64, Instant)>,
}

impl Sampler {
    pub fn new(paths: SysPaths) -> Self {
        Self {
            paths,
            clock: rustix::param::clock_ticks_per_second() as f64,
            page_size: rustix::param::page_size() as u64,
            previous_cpu: sys::cpu_load_ticks().ok(),
            previous_net: None,
        }
    }

    /// Takes one sample at `now`. macOS has no temperature warning to give.
    pub fn collect(&mut self, now: Instant) -> (Sample, Option<TemperatureError>) {
        // gopsutil keeps its previous reading when a read fails.
        let cpu_percent = match sys::cpu_load_ticks() {
            Ok(current) => {
                let percent = self.previous_cpu.map_or(0.0, |previous| {
                    cpu_busy_percent(previous, current, self.clock)
                });
                self.previous_cpu = Some(current);
                percent
            }
            Err(_) => 0.0,
        };
        let memory_percent = match (sys::sysctl_u64("hw.memsize"), sys::vm_counts()) {
            (Ok(total), Ok(counts)) => memory_used_percent(total, self.page_size, counts),
            _ => 0.0,
        };
        let disk_percent = disk::statfs(&self.paths.root).map_or(0.0, |c| disk_used_percent(&c));
        let (rx, tx) = route::links().map_or((0, 0), |links| net_totals(&links));
        let (rx, tx) = (rx as f64, tx as f64);
        let (rx_rate, tx_rate) = match self.previous_net {
            Some((prev_rx, prev_tx, at)) => {
                let seconds = now.duration_since(at).as_secs_f64();
                (
                    rate_per_sec(prev_rx, rx, seconds),
                    rate_per_sec(prev_tx, tx, seconds),
                )
            }
            None => (0.0, 0.0),
        };
        self.previous_net = Some((rx, tx, now));
        let sample = Sample {
            cpu_percent: clamp_percent(cpu_percent),
            memory_percent: clamp_percent(memory_percent),
            disk_percent: clamp_percent(disk_percent),
            net_rx_bytes: rx,
            net_tx_bytes: tx,
            net_rx_bytes_per_sec: rx_rate,
            net_tx_bytes_per_sec: tx_rate,
            temp_celsius: None,
        };
        (sample, None)
    }
}
