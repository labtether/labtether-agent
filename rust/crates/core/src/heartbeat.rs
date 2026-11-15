//! The heartbeat, ported from Go's `ws_publisher.go` and
//! `heartbeat_metadata.go`: the host details read at start, free disk space
//! read for each heartbeat, the latest sample's metrics with two decimals,
//! and the connection counters.
//!
//! The agent advertises nothing it cannot do: the `capabilities` list and
//! the `cap_*` and `*_backend` keys come only from the features built in
//! (see [`crate::Features`]), so no desktop, WebRTC, power or terminal keys
//! are sent and the Hub offers no actions for them. `connectors` is empty:
//! Go fills it by probing local ports, which this agent does not do.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use labtether_agent_config::Settings;
use labtether_agent_platform::{Sample, heartbeat_disk_available, host_metadata};
use labtether_protocol::{HeartbeatData, MSG_HEARTBEAT, Message};

use crate::credential::HubIdentity;
use crate::features::Advertised;
use crate::identity::DeviceIdentity;

/// Go's transport counters, kept for the life of the process.
#[derive(Debug)]
pub struct LinkStats {
    /// Messages written to a socket (pings not counted).
    pub sent: AtomicU64,
    /// Messages read from the Hub.
    pub received: AtomicU64,
    /// Successful connections, the first one included.
    pub connects: AtomicU64,
    started: Instant,
}

impl Default for LinkStats {
    fn default() -> Self {
        Self {
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            connects: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

/// Static heartbeat values, read once at start.
#[derive(Debug, Clone)]
pub struct HeartbeatTemplate {
    source: String,
    metadata: BTreeMap<String, String>,
    capabilities: Vec<String>,
}

impl HeartbeatTemplate {
    pub fn new(settings: &Settings, device: &DeviceIdentity, advertised: &Advertised) -> Self {
        let mut metadata =
            host_metadata(&settings.hostname, &settings.source, &settings.search_path);
        metadata.extend(advertised.metadata.clone());
        let version = settings.version.trim();
        if !version.is_empty() {
            metadata.insert("agent_version".to_owned(), version.to_owned());
        }
        metadata.insert(
            "agent_device_fingerprint".to_owned(),
            device.fingerprint.clone(),
        );
        metadata.insert(
            "agent_device_key_alg".to_owned(),
            device.key_algorithm().to_owned(),
        );
        Self {
            source: settings.source.clone(),
            metadata,
            capabilities: advertised.capabilities.clone(),
        }
    }

    /// A template with given static values, for tests.
    #[cfg(test)]
    pub(crate) fn from_parts(source: &str, metadata: BTreeMap<String, String>) -> Self {
        Self {
            source: source.to_owned(),
            metadata,
            capabilities: Vec::new(),
        }
    }

    /// The metadata with this heartbeat's values, in Go's order: static,
    /// free disk, metrics, counters.
    pub fn metadata(&self, sample: &Sample, stats: &LinkStats) -> BTreeMap<String, String> {
        let mut metadata = self.metadata.clone();
        metadata.insert(
            "disk_root_available_bytes".to_owned(),
            heartbeat_disk_available(),
        );
        let two = |value: f64| format!("{value:.2}");
        for (keys, value) in [
            (["cpu_percent", "cpu_used_percent"], sample.cpu_percent),
            (
                ["memory_percent", "memory_used_percent"],
                sample.memory_percent,
            ),
            (["disk_percent", "disk_used_percent"], sample.disk_percent),
        ] {
            for key in keys {
                metadata.insert(key.to_owned(), two(value));
            }
        }
        metadata.insert(
            "network_rx_bytes_per_sec".to_owned(),
            two(sample.net_rx_bytes_per_sec),
        );
        metadata.insert(
            "network_tx_bytes_per_sec".to_owned(),
            two(sample.net_tx_bytes_per_sec),
        );
        if let Some(celsius) = sample.temp_celsius {
            metadata.insert("temp_celsius".to_owned(), two(celsius));
            metadata.insert("temperature_celsius".to_owned(), two(celsius));
        }
        let count = |counter: &AtomicU64| counter.load(Ordering::Relaxed).to_string();
        metadata.insert(
            "agent_uptime_sec".to_owned(),
            stats.started.elapsed().as_secs().to_string(),
        );
        metadata.insert("agent_reconnect_count".to_owned(), count(&stats.connects));
        metadata.insert("agent_messages_sent".to_owned(), count(&stats.sent));
        metadata.insert("agent_messages_received".to_owned(), count(&stats.received));
        metadata
    }

    /// The heartbeat for the current identity.
    pub fn build(
        &self,
        identity: &HubIdentity,
        sample: &Sample,
        stats: &LinkStats,
    ) -> HeartbeatData {
        HeartbeatData {
            asset_id: identity.asset_id.clone(),
            r#type: "host".to_owned(),
            name: identity.asset_id.clone(),
            source: self.source.clone(),
            group_id: identity.group_id.clone(),
            status: "online".to_owned(),
            platform: "linux".to_owned(),
            metadata: self.metadata(sample, stats),
            capabilities: self.capabilities.clone(),
            connectors: Vec::new(),
        }
    }

    /// The heartbeat as a protocol message.
    pub fn message(
        &self,
        identity: &HubIdentity,
        sample: &Sample,
        stats: &LinkStats,
    ) -> Option<Message> {
        Message::with_data(MSG_HEARTBEAT, "", &self.build(identity, sample, stats)).ok()
    }
}
