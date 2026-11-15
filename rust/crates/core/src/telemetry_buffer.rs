//! Telemetry samples waiting for the Hub, ported from Go's `RingBuffer` and
//! `telemetry_delivery.go`.
//!
//! Each heartbeat tick adds the latest sample here and then sends what is
//! queued, oldest first. While the agent is offline the samples stay, up to
//! 60; a new one then pushes out the oldest. A sample that cannot be queued
//! on the connection stays for the next try; one that cannot be encoded
//! (not a finite number, which Go's JSON encoder refuses) is dropped alone.
//!
//! The Hub stamps a sample when it arrives, so samples sent after a gap are
//! stored at the reconnect time, as with the Go agent.

use std::collections::VecDeque;

use labtether_agent_platform::Sample;
use labtether_protocol::{MSG_TELEMETRY, Message, TelemetryData};

use crate::outbox::{Outbox, SendError};

/// Go's buffer size.
pub const CAPACITY: usize = 60;

/// The `telemetry` message for `sample`, or `None` when a value is not a
/// finite number.
pub fn telemetry_message(asset_id: &str, sample: &Sample) -> Option<Message> {
    let values = [
        sample.cpu_percent,
        sample.memory_percent,
        sample.disk_percent,
        sample.net_rx_bytes_per_sec,
        sample.net_tx_bytes_per_sec,
        sample.temp_celsius.unwrap_or(0.0),
    ];
    if values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let data = TelemetryData {
        asset_id: asset_id.to_owned(),
        cpu_percent: sample.cpu_percent,
        memory_percent: sample.memory_percent,
        disk_percent: sample.disk_percent,
        net_rx_bytes_per_sec: sample.net_rx_bytes_per_sec,
        net_tx_bytes_per_sec: sample.net_tx_bytes_per_sec,
        temp_celsius: sample.temp_celsius,
    };
    Message::with_data(MSG_TELEMETRY, "", &data).ok()
}

/// What one flush did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Flushed {
    pub sent: usize,
    pub discarded: usize,
    /// Why the flush stopped early; the rest stays queued.
    pub stopped: Option<SendError>,
}

/// At most `capacity` samples, oldest first.
#[derive(Debug)]
pub struct TelemetryBuffer {
    samples: VecDeque<Sample>,
    capacity: usize,
}

impl TelemetryBuffer {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Adds a sample; when full, the oldest one is dropped.
    pub fn push(&mut self, sample: Sample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Queues the samples on `outbox` in order, at most `capacity` per call,
    /// as Go's `Flush`. A full or closed queue stops the flush and keeps the
    /// rest.
    pub fn flush(&mut self, asset_id: &str, outbox: &Outbox) -> Flushed {
        let mut done = Flushed::default();
        for _ in 0..self.capacity {
            let Some(sample) = self.samples.front() else {
                break;
            };
            let Some(message) = telemetry_message(asset_id, sample) else {
                self.samples.pop_front();
                done.discarded += 1;
                continue;
            };
            match outbox.send(&message) {
                Ok(()) => {
                    self.samples.pop_front();
                    done.sent += 1;
                }
                Err(error) => {
                    done.stopped = Some(error);
                    break;
                }
            }
        }
        if done.discarded > 0 {
            log::warn!("discarded {} invalid telemetry samples", done.discarded);
        }
        done
    }
}
