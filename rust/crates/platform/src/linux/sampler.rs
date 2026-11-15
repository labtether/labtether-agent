//! One telemetry sample, ported from Go's Linux `Provider.Collect`.
//!
//! - CPU: busy share of the `/proc/stat` counters since the last sample; 0
//!   on the first sample and after a failed read.
//! - Memory: `(MemTotal - MemAvailable) / MemTotal`; without a
//!   `MemAvailable` line, available is `MemFree + Buffers + Cached`.
//! - Disk: `statfs("/")`, read at most once a minute; between reads the last
//!   value is reused.
//! - Network: bytes per second since the last sample, summed over every
//!   interface but `lo`; 0 on the first sample and when a counter went down.
//! - Temperature: read at most every 30 s; a failed read keeps the last good
//!   value, and a host that never had one sends none.
//!
//! A sample reuses one text buffer, so after the first one it allocates
//! nothing for `/proc` (the temperature scan allocates every 30 s).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::procfs::{self, CpuTimes};
use super::temperature::{self, TemperatureError};
use super::{disk, read_into};

const DISK_EVERY: Duration = Duration::from_secs(60);
const TEMPERATURE_EVERY: Duration = Duration::from_secs(30);

/// Where the sampler reads; tests point these at captured files.
#[derive(Debug, Clone)]
pub struct SysPaths {
    pub proc_stat: PathBuf,
    pub proc_meminfo: PathBuf,
    pub proc_net_dev: PathBuf,
    /// The filesystem whose usage is reported (`/`).
    pub root: PathBuf,
    /// The sysfs root for temperature sensors (`/sys`).
    pub sys: PathBuf,
}

impl Default for SysPaths {
    fn default() -> Self {
        Self {
            proc_stat: "/proc/stat".into(),
            proc_meminfo: "/proc/meminfo".into(),
            proc_net_dev: "/proc/net/dev".into(),
            root: "/".into(),
            sys: "/sys".into(),
        }
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

/// Go's `ClampPercent`.
pub fn clamp_percent(value: f64) -> f64 {
    value.clamp(0.0, 100.0)
}

/// The state kept between samples.
#[derive(Debug)]
pub struct Sampler {
    paths: SysPaths,
    text: String,
    previous_cpu: Option<CpuTimes>,
    previous_net: Option<(f64, f64, Instant)>,
    disk: Option<(f64, Instant)>,
    temperature: Option<f64>,
    temperature_at: Option<Instant>,
    /// Go's `ReportOnce`: a failing sensor is reported once until it works.
    temperature_reported: bool,
}

impl Sampler {
    pub fn new(paths: SysPaths) -> Self {
        Self {
            paths,
            text: String::with_capacity(16 * 1024),
            previous_cpu: None,
            previous_net: None,
            disk: None,
            temperature: None,
            temperature_at: None,
            temperature_reported: false,
        }
    }

    /// Takes one sample at `now`. The error is a temperature failure to log;
    /// it is given once until a reading works again.
    pub fn collect(&mut self, now: Instant) -> (Sample, Option<TemperatureError>) {
        let cpu = self.read_cpu();
        let cpu_percent = match (self.previous_cpu, cpu) {
            (Some(previous), Some(current)) => procfs::cpu_percent(previous, current),
            _ => 0.0,
        };
        self.previous_cpu = cpu;

        let memory_percent = match read_into(&self.paths.proc_meminfo, &mut self.text) {
            Ok(()) => procfs::memory_used_percent(&self.text),
            Err(_) => 0.0,
        };

        let disk_percent = match self.disk {
            Some((percent, at)) if now.duration_since(at) < DISK_EVERY => percent,
            _ => {
                let percent = disk::capacity(&self.paths.root).map_or(0.0, |c| c.used_percent());
                self.disk = Some((percent, now));
                percent
            }
        };

        let (rx, tx) = match read_into(&self.paths.proc_net_dev, &mut self.text) {
            Ok(()) => procfs::net_totals(&self.text),
            Err(_) => (0, 0),
        };
        let (rx, tx) = (rx as f64, tx as f64);
        let (rx_rate, tx_rate) = match self.previous_net {
            Some((prev_rx, prev_tx, at)) => {
                let seconds = now.duration_since(at).as_secs_f64();
                (
                    procfs::rate_per_sec(prev_rx, rx, seconds),
                    procfs::rate_per_sec(prev_tx, tx, seconds),
                )
            }
            None => (0.0, 0.0),
        };
        self.previous_net = Some((rx, tx, now));

        let warning = self.refresh_temperature(now);
        let sample = Sample {
            cpu_percent: clamp_percent(cpu_percent),
            memory_percent: clamp_percent(memory_percent),
            disk_percent: clamp_percent(disk_percent),
            net_rx_bytes: rx,
            net_tx_bytes: tx,
            net_rx_bytes_per_sec: rx_rate,
            net_tx_bytes_per_sec: tx_rate,
            temp_celsius: self.temperature,
        };
        (sample, warning)
    }

    fn read_cpu(&mut self) -> Option<CpuTimes> {
        read_into(&self.paths.proc_stat, &mut self.text).ok()?;
        procfs::parse_cpu_times(&self.text).ok()
    }

    fn refresh_temperature(&mut self, now: Instant) -> Option<TemperatureError> {
        if self
            .temperature_at
            .is_some_and(|at| now.duration_since(at) < TEMPERATURE_EVERY)
        {
            return None;
        }
        self.temperature_at = Some(now);
        match temperature::read_celsius(&self.paths.sys) {
            Ok(celsius) => {
                self.temperature = Some(celsius);
                self.temperature_reported = false;
                None
            }
            Err(error) if !self.temperature_reported => {
                self.temperature_reported = true;
                Some(error)
            }
            Err(_) => None,
        }
    }
}
