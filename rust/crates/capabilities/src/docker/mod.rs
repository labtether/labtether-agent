//! Docker on Linux, the read-only half of the Go agent's Docker support
//! (`internal/agentcore/docker`): the inventory, its deltas, container
//! stats and engine events, sent without being asked
//! (`docker.discovery`, `docker.discovery.delta`, `docker.stats`,
//! `docker.events`), and the Docker endpoint in each heartbeat's
//! `connectors`, which the Hub reads to set up its Docker collector for
//! the device.
//!
//! None of these is a request, so the page registers no handler and
//! advertises no `cap_*` word: the Hub's rule has none for the inventory,
//! and `cap_docker=manage` (container and Compose actions, exec, logs, the
//! endpoint test) is not advertised, so the Hub refuses those requests
//! itself. The discovery leaves out Go's Compose action version for the
//! same reason.
//!
//! Started as Go's `run.go` starts the collector: off when the mode is
//! `false`; otherwise the endpoint is checked once at start (it exists and
//! `GET /_ping` answers within 5 s), and the collector runs only when it
//! answered. The heartbeat lists the endpoint when it answered at the last
//! check (every 60 s, 4 s each) or when the mode is `true`. This agent
//! reads Docker only over a Unix socket: an http(s) endpoint, which the Go
//! agent supports, is reported and left unread.

mod compose;
mod compose_memory;
mod discovery;
mod engine;
mod events;
mod inventory;
mod raw;
mod schedule;
mod stats;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use labtether_agent_config::docker::trim_unix_scheme;
use labtether_agent_config::{DockerMode, Settings};
use labtether_agent_core::{Features, HubSender, Stop};
use labtether_protocol::ConnectorInfo;

use compose_memory::ComposeMemory;
use discovery::Inventory;
use engine::{Blocking, Socket};
use schedule::{DISCOVERY_QUEUE, STATS_QUEUE, Trigger, Triggers};

/// The producers' names.
pub const DISCOVERY: &str = "docker-discovery";
pub const STATS: &str = "docker-stats";
pub const EVENTS: &str = "docker-events";
pub const CONNECTOR: &str = "docker-connector";

/// Go's `IsAvailable` limit at start, and `dockerEndpointReachable`'s
/// limit and cache age for the heartbeat.
const START_CHECK: Duration = Duration::from_secs(5);
const CONNECTOR_CHECK: Duration = Duration::from_secs(4);
const CONNECTOR_AGE: Duration = Duration::from_secs(60);

/// The endpoint's Unix socket path, if it names one.
fn socket_path(endpoint: &str) -> Option<PathBuf> {
    let path = trim_unix_scheme(endpoint).unwrap_or(endpoint.trim());
    path.starts_with('/').then(|| PathBuf::from(path))
}

/// Go's `connectorDockerEndpointForMetadata`.
fn metadata_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.starts_with('/') {
        format!("unix://{trimmed}")
    } else {
        trimmed.to_owned()
    }
}

/// The heartbeat's Docker entry and its last check.
struct Connector {
    mode: DockerMode,
    endpoint: String,
    socket: Option<Socket>,
    reachable: AtomicBool,
}

impl Connector {
    /// Go's `dockerEndpointReachable` and `IsAvailable`: the socket file
    /// exists and `GET /_ping` answers within `limit`.
    fn check(&self, limit: Duration) -> bool {
        let reachable = self
            .socket
            .as_ref()
            .is_some_and(|socket| socket.0.exists() && engine::ping(socket, limit));
        self.reachable.store(reachable, Ordering::Relaxed);
        reachable
    }

    /// Go's `discoverConnectors`, Docker part.
    fn list(&self) -> Vec<ConnectorInfo> {
        let reachable = self.reachable.load(Ordering::Relaxed);
        if !reachable && self.mode != DockerMode::On {
            return Vec::new();
        }
        vec![ConnectorInfo {
            r#type: "docker".to_owned(),
            endpoint: self.endpoint.clone(),
            reachable,
        }]
    }
}

/// The state the collector's threads share.
struct Collector {
    socket: Socket,
    interval: Duration,
    inventory: Inventory,
    discovery: Triggers<Trigger>,
    stats: Triggers<()>,
}

impl Collector {
    /// A thread's engine; `None` (logged) when its runtime cannot start.
    fn engine(&self, stop: &Stop, name: &str) -> Option<Blocking> {
        Blocking::new(self.socket.clone(), stop)
            .map_err(|error| log::error!("{name}: could not start: {error}"))
            .ok()
    }
}

pub fn register(features: &mut Features, settings: &Settings) {
    let docker = &settings.docker;
    let name = &settings.name;
    if docker.mode == DockerMode::Off {
        log::info!("{name}: Docker collector disabled by configuration");
        return;
    }
    let socket = socket_path(&docker.endpoint).map(Socket);
    if socket.is_none() {
        log::info!(
            "{name}: Docker endpoint {} is not a Unix socket; this agent reads Docker only over a Unix socket",
            docker.endpoint
        );
    }
    let connector = Arc::new(Connector {
        mode: docker.mode,
        endpoint: metadata_endpoint(&docker.endpoint),
        socket: socket.clone(),
        reachable: AtomicBool::new(false),
    });
    // At start, before the agent runs: off the async thread that builds
    // the features, as each check has a runtime of its own.
    let available = std::thread::scope(|scope| {
        scope
            .spawn(|| connector.check(START_CHECK))
            .join()
            .unwrap_or(false)
    });
    let listed = Arc::clone(&connector);
    features.heartbeat_connectors(move || listed.list());
    features.on_start(CONNECTOR, move |_sender: &dyn HubSender, stop: &Stop| {
        while !stop.wait(CONNECTOR_AGE) {
            connector.check(CONNECTOR_CHECK);
        }
    });
    let socket = match (available, socket) {
        (true, Some(socket)) => socket,
        _ if docker.mode == DockerMode::On => {
            log::info!(
                "{name}: Docker collector explicitly enabled but endpoint unavailable: {}",
                docker.endpoint
            );
            return;
        }
        _ => {
            log::info!(
                "{name}: Docker endpoint not available at {}, Docker collector disabled",
                docker.endpoint
            );
            return;
        }
    };
    let mode = if docker.mode == DockerMode::On {
        "true"
    } else {
        "auto"
    };
    log::info!(
        "{name}: Docker collector enabled ({mode}): {}",
        docker.endpoint
    );
    start_collector(features, settings, socket);
}

fn start_collector(features: &mut Features, settings: &Settings, socket: Socket) {
    let collector = Arc::new(Collector {
        socket,
        interval: settings.docker.discovery_interval,
        inventory: Inventory::new(ComposeMemory::load(Some(settings.state_dir()))),
        discovery: Triggers::new(DISCOVERY_QUEUE),
        stats: Triggers::new(STATS_QUEUE),
    });
    let shared = Arc::clone(&collector);
    features.on_start(DISCOVERY, move |sender: &dyn HubSender, stop: &Stop| {
        let Some(engine) = shared.engine(stop, DISCOVERY) else {
            return;
        };
        let waker = Arc::clone(&shared);
        let _wake = stop.on_stop(move || waker.discovery.wake());
        schedule::run_discovery(
            &shared.inventory,
            &engine,
            sender,
            stop,
            &shared.discovery,
            shared.interval,
        );
    });
    let shared = Arc::clone(&collector);
    features.on_start(STATS, move |sender: &dyn HubSender, stop: &Stop| {
        let Some(engine) = shared.engine(stop, STATS) else {
            return;
        };
        let waker = Arc::clone(&shared);
        let _wake = stop.on_stop(move || waker.stats.wake());
        schedule::run_stats(
            &shared.inventory,
            &engine,
            sender,
            stop,
            &shared.stats,
            shared.interval,
        );
    });
    features.on_start(EVENTS, move |sender: &dyn HubSender, stop: &Stop| {
        let Some(engine) = collector.engine(stop, EVENTS) else {
            return;
        };
        events::run(
            &engine,
            sender,
            stop,
            &collector.discovery,
            &collector.stats,
        );
    });
}

#[cfg(test)]
mod tests;
