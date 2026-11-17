//! Web services on Linux, from the Go agent's web service discovery
//! (`internal/agentcore/webservice`): the running containers' web ports,
//! named by the registry of known services or, for the others, by Go's
//! recognition probes, matched to the Hub's connectors (`compat_*`),
//! checked for health, and sent as `webservice.report` without being
//! asked. The Services page lists them and the Hub suggests connectors
//! from them.
//!
//! Services on the host outside Docker come from the local port scan
//! (`scan.rs`): Go's default ports and the listening ones, dialled on the
//! host's own address only.
//!
//! The report needs no capability word: the Hub takes it from any agent.
//! `webservice.sync` (the page's sync) runs one cycle at once
//! (`sync.rs`); its handler advertises `cap_web_services=sync`.
//! Reverse-proxy routes and the LAN scan are later parts; the report says
//! their sources are not enabled.
//!
//! Timers as Go's `Run`: the host's address is read once at start, a cycle
//! runs at start only if the agent is already connected (in the agent it
//! never is, so the first report comes an interval after start) and then
//! one every `LABTETHER_SERVICES_DISCOVERY_INTERVAL` (60 s by default),
//! a missed tick running once at once, as Go's ticker.

mod cache;
mod client;
mod compat;
mod compat_probes;
mod containers;
mod cycle;
mod fingerprint;
mod health;
mod labtether;
mod location;
mod pages;
mod registry;
mod scan;
mod scan_host;
mod sync;
mod urls;

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use labtether_agent_config::Settings;
use labtether_agent_config::web_services::WebServiceSettings;
use labtether_agent_core::{Features, HubSender, Stop};
use labtether_agent_platform::{netid, netlink};
use labtether_protocol::MSG_WEBSERVICE_SYNC;

use crate::docker::engine::{Blocking, EngineApi, Socket};
use crate::docker::schedule::Ticker;
use client::{HttpProber, TIMEOUT};
use cycle::{Collector, Runner};
use scan_host::LocalHost;
use sync::{Requests, Woken};

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

/// Adds the producer and the sync handler. `docker` is the engine's
/// socket when the Docker collector runs (Go hands the web service
/// collector the Docker collector only then).
pub fn register(features: &mut Features, settings: &Settings, docker: Option<Socket>) {
    let config = settings.web_services.clone();
    let name = settings.name.clone();
    let requests = Arc::new(Requests::default());
    let asked = Arc::clone(&requests);
    features.on_message(MSG_WEBSERVICE_SYNC, move |_| {
        asked.ask();
        None
    });
    features.on_start(PRODUCER, move |sender: &dyn HubSender, stop: &Stop| {
        run(sender, stop, &config, docker.clone(), &name, &requests);
    });
}

fn run(
    sender: &dyn HubSender,
    stop: &Stop,
    config: &WebServiceSettings,
    docker: Option<Socket>,
    name: &str,
    requests: &Arc<Requests>,
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
    let host = match LocalHost::new() {
        Ok(host) => host,
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
    collector.scan = config.port_scan.clone();
    let mut ticker = Ticker::new(config.interval, started);
    let clock = SystemTime::now;
    let _open = requests.open(stop);
    if connected_at_start {
        collector.run(sender, docker, &prober, &host, &runner, &clock);
        ticker = Ticker::new(config.interval, Instant::now());
    }
    while !stop.is_stopped() {
        if ticker.due(Instant::now()) {
            collector.run(sender, docker, &prober, &host, &runner, &clock);
            continue;
        }
        match requests.wait(ticker.next, stop) {
            Woken::Sync => {
                collector.run(sender, docker, &prober, &host, &runner, &clock);
                requests.served();
            }
            Woken::Due => {}
            Woken::Stopped => return,
        }
    }
}

#[cfg(test)]
mod tests;
