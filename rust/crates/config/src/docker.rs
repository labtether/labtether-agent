//! The Docker settings, read as the Go agent's `LoadConfig` reads them
//! (`config.go`, `settings_env_pins.go`, `sysconfig/settings_value_validation.go`):
//!
//! - the mode from `LABTETHER_DOCKER_ENABLED` (default `auto`),
//! - the endpoint from `LABTETHER_DOCKER_SOCKET` (default
//!   `/var/run/docker.sock`),
//! - the discovery interval from `LABTETHER_DOCKER_DISCOVERY_INTERVAL`
//!   (30 s, or 5 min in low-power mode; 5 s to 1 h).
//!
//! `agent-config.json` (`docker_enabled`, `docker_endpoint`,
//! `docker_discovery_interval_sec`) wins over each default, and the
//! environment wins over the file when the variable is set; low-power mode
//! pins the interval as well. The Go agent does not read `DOCKER_HOST`, so
//! neither does this one.

use std::time::Duration;

use crate::env::{Environment, parse_duration_or};

/// Go's `DefaultDockerEndpoint` on Linux and macOS.
pub const DEFAULT_DOCKER_ENDPOINT: &str = "/var/run/docker.sock";
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
const LOW_POWER_INTERVAL: Duration = Duration::from_secs(300);
const MIN_INTERVAL: Duration = Duration::from_secs(5);
const MAX_INTERVAL: Duration = Duration::from_secs(3600);
const NPIPE_PREFIX: &str = "npipe:////./pipe/";
const NPIPE_NAME_MAX: usize = 128;

/// Go's Docker collector mode, after `strings.ToLower`: `false` turns
/// Docker off, `true` lists the endpoint in the heartbeat even when it does
/// not answer, and any other value acts as `auto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerMode {
    Auto,
    On,
    Off,
}

impl DockerMode {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "false" => Self::Off,
            "true" => Self::On,
            _ => Self::Auto,
        }
    }
}

/// The Docker settings, read once at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerSettings {
    pub mode: DockerMode,
    /// The endpoint as Go's settings check leaves it: an absolute path,
    /// `unix://` and an absolute path, a named pipe or an http(s) address.
    /// An endpoint that check refuses gives the default socket.
    pub endpoint: String,
    pub discovery_interval: Duration,
}

/// The file's Docker values, each trimmed and present only when set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FileDocker {
    pub enabled: Option<String>,
    pub endpoint: Option<String>,
    /// Whole seconds, 5 to 3600 (Go's `docker_discovery_interval_sec`).
    pub interval_sec: Option<u64>,
}

pub(crate) fn load(env: &Environment, file: &FileDocker, low_power: bool) -> DockerSettings {
    let mode_env = env.get("LABTETHER_DOCKER_ENABLED");
    let mode = match (mode_env, &file.enabled) {
        (None, Some(raw)) => raw.as_str(),
        _ => mode_env.unwrap_or("auto"),
    };
    let endpoint_env = env.get("LABTETHER_DOCKER_SOCKET");
    let endpoint = match (endpoint_env, &file.endpoint) {
        (None, Some(raw)) => raw.as_str(),
        _ => endpoint_env.unwrap_or(DEFAULT_DOCKER_ENDPOINT),
    };
    let interval_env = env.get("LABTETHER_DOCKER_DISCOVERY_INTERVAL");
    let fallback = if low_power {
        LOW_POWER_INTERVAL
    } else {
        DEFAULT_INTERVAL
    };
    let mut discovery_interval =
        parse_duration_or(interval_env, fallback, MIN_INTERVAL, MAX_INTERVAL);
    if let (None, false, Some(seconds)) = (interval_env, low_power, file.interval_sec) {
        discovery_interval = Duration::from_secs(seconds);
    }
    DockerSettings {
        mode: DockerMode::parse(mode),
        endpoint: normalize_endpoint(endpoint)
            .unwrap_or_else(|| DEFAULT_DOCKER_ENDPOINT.to_owned()),
        discovery_interval,
    }
}

/// Go's `TrimDockerUnixScheme`: the trimmed path after a `unix://` prefix
/// in any case, when there is one.
pub fn trim_unix_scheme(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let prefix = trimmed.get(..7)?;
    prefix
        .eq_ignore_ascii_case("unix://")
        .then(|| trimmed[7..].trim())
}

/// Go's `normalizeDockerEndpointValue`; `None` where Go returns an error.
/// An http(s) address is kept as Go keeps it after its outbound address
/// check, which this agent does not make: it reads Docker only over a Unix
/// socket and reports such an endpoint as not supported.
pub fn normalize_endpoint(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if value
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("npipe:"))
    {
        return valid_npipe(value).then(|| value.to_owned());
    }
    if value.starts_with('/') {
        return (!matches!(value.as_bytes().get(1), Some(b'/' | b'\\'))).then(|| value.to_owned());
    }
    if let Some(path) = trim_unix_scheme(value) {
        return path.starts_with('/').then(|| format!("unix://{path}"));
    }
    let (scheme, rest) = value.split_once("://")?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let known = scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
    if !known || rest[..host_end].is_empty() {
        return None;
    }
    let kept = value.split(['?', '#']).next().unwrap_or(value);
    Some(kept.trim_end_matches('/').to_owned())
}

/// Go's `NormalizeDockerNpipeEndpoint` for a value already known to start
/// with `npipe:`.
fn valid_npipe(value: &str) -> bool {
    let Some(name) = value.strip_prefix(NPIPE_PREFIX) else {
        return false;
    };
    let bytes = name.as_bytes();
    let start = |c: u8| c.is_ascii_alphanumeric();
    !bytes.is_empty()
        && bytes.len() <= NPIPE_NAME_MAX
        && start(bytes[0])
        && !name.contains("..")
        && !name.ends_with('.')
        && bytes[1..]
            .iter()
            .all(|&c| start(c) || matches!(c, b'_' | b'-' | b'.'))
}
