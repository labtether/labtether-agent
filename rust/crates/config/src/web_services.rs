//! The web service discovery settings this agent reads, as the Go agent's
//! `LoadConfig` reads them (`config.go`, `settings_env_pins.go`):
//!
//! - the interval from `LABTETHER_SERVICES_DISCOVERY_INTERVAL` (60 s, or
//!   10 min in low-power mode; 30 s to 6 h), from the environment only;
//! - the Docker source from `LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED`
//!   (on by default);
//! - the local port scan from `LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_ENABLED`
//!   and `_INCLUDE_LISTENING` (both on, both off in low-power mode) and the
//!   port list `_PORTS` (empty: Go's default ports), with Go's older names
//!   `LABTETHER_WEBSVC_PORTSCAN_DISABLED`, `_INCLUDE_LISTENING` and `_PORTS`
//!   read after (the first two) or instead of (the list) the new ones.
//!
//! `agent-config.json`'s `services_discovery_*` keys win over the defaults;
//! a setting chosen in the environment (any of its names set, or low-power
//! mode for the two scan switches) wins over the file. An unreadable
//! environment value gives the default, as Go's `parseBoolEnv`; a port list
//! with any bad entry gives the default ports, as Go's
//! `NormalizeDiscoveryPortListValue` failing.
//!
//! The proxy and LAN scan settings come with the parts that read them.

use std::time::Duration;

use crate::env::{Environment, parse_duration_or, parse_go_bool};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
const LOW_POWER_INTERVAL: Duration = Duration::from_secs(600);
const MIN_INTERVAL: Duration = Duration::from_secs(30);
const MAX_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const DOCKER_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED";
const SCAN_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_ENABLED";
const SCAN_OFF_VARIABLE: &str = "LABTETHER_WEBSVC_PORTSCAN_DISABLED";
const LISTENING_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_INCLUDE_LISTENING";
const OLD_LISTENING_VARIABLE: &str = "LABTETHER_WEBSVC_PORTSCAN_INCLUDE_LISTENING";
const PORTS_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_PORTS";
const OLD_PORTS_VARIABLE: &str = "LABTETHER_WEBSVC_PORTSCAN_PORTS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebServiceSettings {
    pub interval: Duration,
    /// Go's `ServicesDiscoveryDockerEnabled`.
    pub docker_enabled: bool,
    pub port_scan: PortScanSettings,
}

/// Go's `ServicesDiscoveryPortScan*` settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortScanSettings {
    pub enabled: bool,
    /// Add the host's listening TCP ports to the list.
    pub include_listening: bool,
    /// The ports to check, sorted, each once; empty for Go's defaults.
    pub ports: Vec<u16>,
}

/// The `services_discovery_*` values found in `agent-config.json`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FileServices {
    pub docker_enabled: Option<bool>,
    pub port_scan_enabled: Option<bool>,
    pub port_scan_include_listening: Option<bool>,
    /// A valid list (Go drops a bad one when it reads the file).
    pub port_scan_ports: Option<Vec<u16>>,
}

/// Go's `NormalizeDiscoveryPortListValue`: entries split at commas,
/// semicolons, spaces, tabs and new lines, each read as Go's `Atoi`
/// (an optional sign, decimal digits) and kept between 1 and 65535, sorted
/// and each once. `None` when an entry is not such a port.
pub fn normalize_port_list(raw: &str) -> Option<Vec<u16>> {
    let mut ports = Vec::new();
    for token in raw.split([',', ';', ' ', '\n', '\t']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let digits = token.strip_prefix('+').unwrap_or(token);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port = digits.parse::<u16>().ok().filter(|port| *port > 0)?;
        ports.push(port);
    }
    ports.sort_unstable();
    ports.dedup();
    Some(ports)
}

pub(crate) fn load(env: &Environment, file: &FileServices, low_power: bool) -> WebServiceSettings {
    let fallback = if low_power {
        LOW_POWER_INTERVAL
    } else {
        DEFAULT_INTERVAL
    };
    let interval = parse_duration_or(
        env.get("LABTETHER_SERVICES_DISCOVERY_INTERVAL"),
        fallback,
        MIN_INTERVAL,
        MAX_INTERVAL,
    );
    let docker_enabled = match (env.get(DOCKER_VARIABLE), file.docker_enabled) {
        (None, Some(enabled)) => enabled,
        _ => env.bool_or(DOCKER_VARIABLE, true),
    };
    WebServiceSettings {
        interval,
        docker_enabled,
        port_scan: port_scan(env, file, low_power),
    }
}

fn port_scan(env: &Environment, file: &FileServices, low_power: bool) -> PortScanSettings {
    let mut enabled = env.bool_or(SCAN_VARIABLE, !low_power);
    if let Some(raw) = env.get(SCAN_OFF_VARIABLE) {
        enabled =
            !(raw.eq_ignore_ascii_case("true") || raw == "1" || raw.eq_ignore_ascii_case("on"));
    }
    let mut include_listening = env.bool_or(LISTENING_VARIABLE, !low_power);
    if let Some(parsed) = env.get(OLD_LISTENING_VARIABLE).and_then(parse_go_bool) {
        include_listening = parsed;
    }
    let ports_env = env
        .get(PORTS_VARIABLE)
        .or_else(|| env.get(OLD_PORTS_VARIABLE));
    let mut ports = ports_env.and_then(normalize_port_list).unwrap_or_default();
    let set = |names: [&str; 2]| names.iter().any(|name| env.get(name).is_some());
    if let (false, false, Some(file)) = (
        low_power,
        set([SCAN_VARIABLE, SCAN_OFF_VARIABLE]),
        file.port_scan_enabled,
    ) {
        enabled = file;
    }
    if let (false, false, Some(file)) = (
        low_power,
        set([LISTENING_VARIABLE, OLD_LISTENING_VARIABLE]),
        file.port_scan_include_listening,
    ) {
        include_listening = file;
    }
    if let (None, Some(file)) = (ports_env, &file.port_scan_ports) {
        ports.clone_from(file);
    }
    PortScanSettings {
        enabled,
        include_listening,
        ports,
    }
}
