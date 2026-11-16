//! The read-only view of the agent that the local API shows. No HTTP here:
//! the local API crate turns this into Go's JSON bodies.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

pub use labtether_agent_platform::Sample;

use crate::agent::Agent;
use crate::alerts::Alert;
use crate::link_status::ConnectionView;

/// The latest telemetry sample and when it was taken. Before the first
/// collection every number is 0 and the time is the agent's start, as Go's
/// placeholder sample.
#[derive(Debug, Clone, Copy)]
pub struct LatestSample {
    pub sample: Sample,
    pub collected_at: SystemTime,
}

/// Holds [`LatestSample`]; the telemetry loop writes it after each
/// collection.
#[derive(Debug)]
pub struct LatestCell(Mutex<LatestSample>);

impl LatestCell {
    pub fn new(started_at: SystemTime) -> Self {
        Self(Mutex::new(LatestSample {
            sample: Sample::default(),
            collected_at: started_at,
        }))
    }

    fn lock(&self) -> MutexGuard<'_, LatestSample> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn store(&self, sample: Sample, collected_at: SystemTime) {
        *self.lock() = LatestSample {
            sample,
            collected_at,
        };
    }

    pub fn get(&self) -> LatestSample {
        *self.lock()
    }
}

/// When the agent started: wall time for the page, a monotonic clock for
/// the uptime (Go's `time.Since` uses the monotonic reading too).
#[derive(Debug, Clone, Copy)]
pub struct StartTime {
    pub wall: SystemTime,
    pub clock: Instant,
}

impl StartTime {
    pub fn now() -> Self {
        Self {
            wall: SystemTime::now(),
            clock: Instant::now(),
        }
    }
}

/// Everything the status, telemetry and metrics pages need.
#[derive(Debug, Clone)]
pub struct StatusView {
    pub agent_name: String,
    /// The asset ID in use now (the Hub's once known); also the metrics'.
    pub asset_id: String,
    pub group_id: String,
    pub device_fingerprint: String,
    pub device_key_algorithm: String,
    pub connection: ConnectionView,
    pub started_at: SystemTime,
    pub uptime: Duration,
    pub latest: LatestSample,
    pub alerts: Vec<Alert>,
    pub agent_version: String,
    pub allow_insecure_transport: bool,
}

impl Agent {
    /// The agent's state now, read without waiting on the network.
    pub fn status_view(&self) -> StatusView {
        let identity = self.identity.snapshot();
        StatusView {
            agent_name: self.settings.name.clone(),
            asset_id: identity.asset_id,
            group_id: identity.group_id,
            device_fingerprint: self.device.fingerprint.clone(),
            device_key_algorithm: self.device.key_algorithm().to_owned(),
            connection: self.link_status.view(),
            started_at: self.started.wall,
            uptime: self.started.clock.elapsed(),
            latest: self.latest.get(),
            alerts: self.alerts.snapshot(),
            agent_version: self.settings.version.clone(),
            allow_insecure_transport: self.settings.allow_insecure_transport,
        }
    }
}
