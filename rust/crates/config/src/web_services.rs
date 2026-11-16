//! The web service discovery settings this agent reads, as the Go agent's
//! `LoadConfig` reads them (`config.go`, `settings_env_pins.go`):
//!
//! - the interval from `LABTETHER_SERVICES_DISCOVERY_INTERVAL` (60 s, or
//!   10 min in low-power mode; 30 s to 6 h), from the environment only;
//! - the Docker source from `LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED`
//!   (on by default). `agent-config.json`'s
//!   `services_discovery_docker_enabled` wins over the default, and the
//!   environment wins over the file when the variable is set at all (an
//!   unreadable value then gives the default, as Go's `parseBoolEnv`).
//!
//! The proxy and scan settings come with the parts that read them.

use std::time::Duration;

use crate::env::{Environment, parse_duration_or};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
const LOW_POWER_INTERVAL: Duration = Duration::from_secs(600);
const MIN_INTERVAL: Duration = Duration::from_secs(30);
const MAX_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const DOCKER_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebServiceSettings {
    pub interval: Duration,
    /// Go's `ServicesDiscoveryDockerEnabled`.
    pub docker_enabled: bool,
}

pub(crate) fn load(
    env: &Environment,
    file_docker: Option<bool>,
    low_power: bool,
) -> WebServiceSettings {
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
    let docker_enabled = match (env.get(DOCKER_VARIABLE), file_docker) {
        (None, Some(enabled)) => enabled,
        _ => env.bool_or(DOCKER_VARIABLE, true),
    };
    WebServiceSettings {
        interval,
        docker_enabled,
    }
}
