//! `docker.stats`: Go's `collector_stats.go`. Each running container has
//! its own sampling interval: it starts at the discovery interval, halves
//! (to a floor) while the container is busy (CPU 25 % or more, memory 70 %
//! or more, or 150 processes or more), grows by half (to a ceiling) while it
//! is not, and doubles after a failed read. A tick samples at most 24 due
//! containers, starting after the last one sampled, so busy containers
//! cannot starve the rest. The message holds the latest sample of every
//! running container and is sent when something was sampled, when the
//! running set changed, or when a discovery interval passed since the last.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use labtether_agent_core::HubSender;
use labtether_protocol::{DockerContainerStats, DockerStatsData, MSG_DOCKER_STATS, Message};

use super::engine::{self, EngineApi};
use super::raw;

/// Go's `dockerStatsMaxSamplesTick`.
pub(crate) const MAX_SAMPLES_PER_TICK: usize = 24;
const HOT_CPU: f64 = 25.0;
const HOT_MEMORY: f64 = 70.0;
const HOT_PIDS: i64 = 150;
const POLL_MIN: Duration = Duration::from_secs(5);
const POLL_MAX: Duration = Duration::from_secs(20);

/// Go's `deriveDockerStatsPollInterval`: half the discovery interval,
/// 5 s to 20 s.
pub(crate) fn poll_interval(interval: Duration) -> Duration {
    (interval / 2).clamp(POLL_MIN, POLL_MAX)
}

/// The running containers as discovery last saw them, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Running {
    pub ids: Vec<String>,
    pub hash: String,
}

impl Running {
    pub fn new(ids: impl IntoIterator<Item = String>) -> Self {
        let mut ids: Vec<String> = ids.into_iter().collect();
        ids.sort();
        ids.dedup();
        Self {
            hash: ids.join(","),
            ids,
        }
    }
}

#[derive(Debug, Clone)]
struct Schedule {
    interval: Duration,
    next: Instant,
    last: Option<DockerContainerStats>,
}

/// The sampler's state: Go's `statsSchedule`, `statsCursor`,
/// `lastRunningSetHash` and `lastStatsPublish`.
#[derive(Debug)]
pub(crate) struct Sampler {
    interval: Duration,
    schedules: BTreeMap<String, Schedule>,
    cursor: String,
    sent_hash: String,
    sent_at: Option<Instant>,
}

impl Sampler {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            schedules: BTreeMap::new(),
            cursor: String::new(),
            sent_hash: String::new(),
            sent_at: None,
        }
    }

    /// Go's `defaultStatsInterval`.
    fn start_interval(&self) -> Duration {
        let base = if self.interval.is_zero() {
            Duration::from_secs(30)
        } else {
            self.interval
        };
        base.max(POLL_MIN)
    }

    /// Go's `minStatsInterval`.
    fn floor(&self) -> Duration {
        let mut floor = (self.interval / 2).max(Duration::from_secs(10));
        if !self.interval.is_zero() && floor > self.interval {
            floor = self.interval;
        }
        floor.max(POLL_MIN)
    }

    /// Go's `maxStatsInterval`.
    fn ceiling(&self) -> Duration {
        (self.interval * 6).clamp(Duration::from_secs(120), Duration::from_secs(600))
    }

    /// Go's `nextStatsInterval`.
    fn next_interval(&self, current: Duration, sample: Option<&DockerContainerStats>) -> Duration {
        let current = if current.is_zero() {
            self.start_interval()
        } else {
            current
        };
        let Some(stats) = sample else {
            return (current * 2).min(self.ceiling());
        };
        let hot = stats.cpu_percent >= HOT_CPU
            || stats.memory_percent >= HOT_MEMORY
            || stats.pids >= HOT_PIDS;
        if hot {
            (current / 2).max(self.floor())
        } else {
            (current + current / 2).min(self.ceiling())
        }
    }

    /// The due containers in rotation order, at most 24 (Go's loop from
    /// the cursor).
    fn due(&mut self, running: &Running, now: Instant) -> Vec<String> {
        let ids = &running.ids;
        self.schedules.retain(|id, _| ids.binary_search(id).is_ok());
        let start_interval = self.start_interval();
        for id in ids {
            self.schedules.entry(id.clone()).or_insert(Schedule {
                interval: start_interval,
                next: now,
                last: None,
            });
        }
        let mut start = ids.partition_point(|id| *id < self.cursor);
        if ids.get(start) == Some(&self.cursor) {
            start += 1;
        }
        let mut due = Vec::new();
        for offset in 0..ids.len() {
            let id = &ids[(start + offset) % ids.len()];
            if self.schedules.get(id).is_some_and(|s| now >= s.next) {
                due.push(id.clone());
                if due.len() == MAX_SAMPLES_PER_TICK {
                    break;
                }
            }
        }
        if let Some(last) = due.last() {
            self.cursor = last.clone();
        }
        due
    }

    /// One tick: Go's `collectAndSendStats`. `now` is read before and after
    /// each sample, as Go reads `time.Now()`.
    pub fn tick(
        &mut self,
        api: &dyn EngineApi,
        sender: &dyn HubSender,
        running: &Running,
        now: &dyn Fn() -> Instant,
    ) {
        if !sender.connected() {
            return;
        }
        let mut at = now();
        let due = self.due(running, at);
        let mut sampled = 0;
        for id in due {
            let read = engine::stats(api, &id);
            at = now();
            let sample = read.ok().map(|raw| calculate(&id, &raw));
            let interval = self
                .schedules
                .get(&id)
                .map(|s| s.interval)
                .unwrap_or_default();
            let next_interval = self.next_interval(interval, sample.as_ref());
            if let Some(schedule) = self.schedules.get_mut(&id) {
                schedule.interval = next_interval;
                schedule.next = at + next_interval;
                if sample.is_some() {
                    schedule.last = sample;
                    sampled += 1;
                }
            }
        }
        let interval_passed = self
            .sent_at
            .is_none_or(|sent| at.saturating_duration_since(sent) >= self.interval);
        let send = sampled > 0
            || running.hash != self.sent_hash
            || (!running.ids.is_empty() && interval_passed);
        if !send {
            return;
        }
        let containers = running
            .ids
            .iter()
            .filter_map(|id| self.schedules.get(id).and_then(|s| s.last.clone()))
            .collect();
        let payload = DockerStatsData {
            host_id: sender.asset_id().trim().to_owned(),
            containers,
        };
        let sent = Message::with_data(MSG_DOCKER_STATS, "", &payload)
            .map_err(|error| error.to_string())
            .and_then(|message| sender.send(&message).map_err(|error| error.to_string()));
        match sent {
            Ok(()) => {
                self.sent_hash = running.hash.clone();
                self.sent_at = Some(now());
            }
            Err(error) => log::info!("docker: failed to send stats: {error}"),
        }
    }
}

/// Go's `calculateStats`, with Go's integer wrapping and float order.
pub(crate) fn calculate(id: &str, raw: &raw::Stats) -> DockerContainerStats {
    let cpu_delta = raw
        .cpu_stats
        .cpu_usage
        .total_usage
        .wrapping_sub(raw.precpu_stats.cpu_usage.total_usage) as f64;
    let system_delta = raw
        .cpu_stats
        .system_cpu_usage
        .wrapping_sub(raw.precpu_stats.system_cpu_usage) as f64;
    let mut cpu_percent = 0.0;
    if system_delta > 0.0 && cpu_delta > 0.0 {
        let cpus = match raw.cpu_stats.online_cpus {
            0 => 1,
            cpus => cpus,
        };
        cpu_percent = (cpu_delta / system_delta) * cpus as f64 * 100.0;
    }
    let memory = &raw.memory_stats;
    let memory_percent = if memory.limit > 0 {
        memory.usage as f64 / memory.limit as f64 * 100.0
    } else {
        0.0
    };
    let (mut rx, mut tx) = (0i64, 0i64);
    for network in raw.networks.values() {
        rx = rx.wrapping_add(network.rx_bytes);
        tx = tx.wrapping_add(network.tx_bytes);
    }
    let (mut read, mut write) = (0i64, 0i64);
    for entry in &raw.blkio_stats.io_service_bytes_recursive {
        match entry.op.as_str() {
            "Read" | "read" => read = read.wrapping_add(entry.value),
            "Write" | "write" => write = write.wrapping_add(entry.value),
            _ => {}
        }
    }
    DockerContainerStats {
        id: id.to_owned(),
        cpu_percent,
        memory_bytes: memory.usage,
        memory_limit: memory.limit,
        memory_percent,
        net_rx_bytes: rx,
        net_tx_bytes: tx,
        block_read_bytes: read,
        block_write_bytes: write,
        pids: raw.pids_stats.current,
    }
}
