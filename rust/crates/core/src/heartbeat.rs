//! The heartbeat, with the fields the Hub needs to list the device. Ported
//! from Go's `ws_publisher.go` and the Linux static metadata in
//! `internal/agentplatform/linux`. Metrics, connectors and the rest of the
//! metadata come in a later step.
//!
//! The agent advertises nothing it cannot do: `capabilities` is empty and
//! no `cap_*` metadata is sent, so the Hub offers no actions for it.

use std::collections::BTreeMap;
use std::fs;

use labtether_agent_config::Settings;
use labtether_protocol::{HeartbeatData, MSG_HEARTBEAT, Message};

use crate::credential::HubIdentity;
use crate::identity::DeviceIdentity;

/// Static heartbeat values, read once at start.
#[derive(Debug, Clone)]
pub struct HeartbeatTemplate {
    source: String,
    metadata: BTreeMap<String, String>,
}

/// Go's `runtime.GOARCH` names, which the Hub shows.
fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "arm" => "arm",
        other => other,
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty() && value != "None").then(|| value.to_owned())
}

/// Go's `parseKeyValueFile` for `/etc/os-release`.
fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            (key.trim().to_owned(), value.to_owned())
        })
        .collect()
}

fn os_metadata() -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    let release = fs::read_to_string("/etc/os-release")
        .map(|text| parse_os_release(&text))
        .unwrap_or_default();
    for (from, to) in [
        ("PRETTY_NAME", "os_pretty_name"),
        ("NAME", "os_name"),
        ("ID", "os_id"),
        ("ID_LIKE", "os_id_like"),
        ("VERSION_ID", "os_version_id"),
        ("VERSION", "os_version"),
    ] {
        if let Some(value) = release
            .get(from)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            metadata.insert(to.to_owned(), value.to_owned());
        }
    }
    if let Some(value) = read_trimmed("/proc/sys/kernel/osrelease") {
        metadata.insert("kernel_release".to_owned(), value);
    }
    if let Some(value) = read_trimmed("/proc/sys/kernel/version") {
        metadata.insert("kernel_version".to_owned(), value);
    }
    metadata
}

impl HeartbeatTemplate {
    pub fn new(settings: &Settings, device: &DeviceIdentity) -> Self {
        let mut metadata = os_metadata();
        let fixed = [
            ("hostname", settings.hostname.as_str()),
            ("agent", settings.source.as_str()),
            ("cpu_architecture", go_arch()),
            ("os", "linux"),
            ("platform", "linux"),
            ("agent_device_fingerprint", device.fingerprint.as_str()),
            ("agent_device_key_alg", device.key_algorithm()),
        ];
        for (key, value) in fixed {
            metadata.insert(key.to_owned(), value.to_owned());
        }
        if !settings.version.trim().is_empty() {
            metadata.insert(
                "agent_version".to_owned(),
                settings.version.trim().to_owned(),
            );
        }
        Self {
            source: settings.source.clone(),
            metadata,
        }
    }

    /// The heartbeat for the current identity.
    pub fn build(&self, identity: &HubIdentity) -> HeartbeatData {
        HeartbeatData {
            asset_id: identity.asset_id.clone(),
            r#type: "host".to_owned(),
            name: identity.asset_id.clone(),
            source: self.source.clone(),
            group_id: identity.group_id.clone(),
            status: "online".to_owned(),
            platform: "linux".to_owned(),
            metadata: self.metadata.clone(),
            capabilities: Vec::new(),
            connectors: Vec::new(),
        }
    }

    /// The heartbeat as a protocol message.
    pub fn message(&self, identity: &HubIdentity) -> Option<Message> {
        Message::with_data(MSG_HEARTBEAT, "", &self.build(identity)).ok()
    }
}
