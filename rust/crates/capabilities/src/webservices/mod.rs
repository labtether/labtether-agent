//! Web services on Linux, the first part of the Go agent's web service
//! discovery (`internal/agentcore/webservice`): the running containers'
//! web ports, named by the registry of known services, checked for
//! health, and sent as `webservice.report` without being asked. The
//! Services page lists them.
//!
//! The report needs no capability word: the Hub takes it from any agent.
//! `webservice.sync` (the page's sync) is not answered yet, so
//! `cap_web_services` is not advertised and the Hub does not send it.
//! Reverse-proxy routes, the port scans and the probes that name unknown
//! services are later parts; the report says their sources are not
//! enabled.
//!
//! Timers as Go's `Run`: the host's address is read once at start, a cycle
//! runs at start only if the agent is already connected (in the agent it
//! never is, so the first report comes an interval after start) and then
//! one every `LABTETHER_SERVICES_DISCOVERY_INTERVAL` (60 s by default),
//! a missed tick running once at once, as Go's ticker.

mod client;
mod containers;
mod cycle;
mod health;
mod labtether;
mod registry;
mod urls;

use std::time::{Instant, SystemTime};

use labtether_agent_config::Settings;
use labtether_agent_config::web_services::WebServiceSettings;
use labtether_agent_core::{Features, HubSender, Stop};
use labtether_agent_platform::{netid, netlink};

use crate::docker::engine::{Blocking, EngineApi, Socket};
use crate::docker::schedule::Ticker;
use client::{HttpProber, TIMEOUT};
use cycle::{Collector, Runner};

/// The producer's name.
pub const PRODUCER: &str = "web-services";

/// Go's `ResolveHostIP`: the LAN address the service URLs use, or
/// `localhost`.
fn host_ip() -> String {
    let nics = netlink::interfaces().unwrap_or_default();
    let ip = netid::primary_ip(&nics, netid::default_route_ip());
    if ip.is_empty() {
        "localhost".to_owned()
    } else {
        ip
    }
}

/// Adds the producer. `docker` is the engine's socket when the Docker
/// collector runs (Go hands the web service collector the Docker collector
/// only then).
pub fn register(features: &mut Features, settings: &Settings, docker: Option<Socket>) {
    let config = settings.web_services.clone();
    let name = settings.name.clone();
    features.on_start(PRODUCER, move |sender: &dyn HubSender, stop: &Stop| {
        run(sender, stop, &config, docker.clone(), &name);
    });
}

fn run(
    sender: &dyn HubSender,
    stop: &Stop,
    config: &WebServiceSettings,
    docker: Option<Socket>,
    name: &str,
) {
    // Go's first cycle runs as the collector starts, before the agent's
    // first connection, so it sends nothing: the first report comes an
    // interval later. The connection is checked before the slower set-up
    // below (the system CA roots), as Go's order is.
    let started = Instant::now();
    let connected_at_start = sender.connected();
    let host_ip = host_ip();
    let runner = match Runner::new(stop) {
        Ok(runner) => runner,
        Err(error) => return log::error!("{PRODUCER}: could not start: {error}"),
    };
    let prober = match HttpProber::new(TIMEOUT) {
        Ok(prober) => prober,
        Err(error) => return log::error!("{PRODUCER}: could not start: {error}"),
    };
    let engine = docker.and_then(|socket| {
        Blocking::new(socket, stop)
            .map_err(|error| log::error!("{PRODUCER}: Docker source not started: {error}"))
            .ok()
    });
    let docker = engine.as_ref().map(|engine| engine as &dyn EngineApi);
    log::info!("{name}: Web service collector enabled (host IP: {host_ip})");
    let mut collector = Collector::new(host_ip, config.docker_enabled, config.interval);
    let mut ticker = Ticker::new(config.interval, started);
    if connected_at_start {
        collector.run(sender, docker, &prober, &runner, SystemTime::now());
        ticker = Ticker::new(config.interval, Instant::now());
    }
    while !stop.is_stopped() {
        if ticker.due(Instant::now()) {
            collector.run(sender, docker, &prober, &runner, SystemTime::now());
        } else if stop.wait(ticker.next.saturating_duration_since(Instant::now())) {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
