//! One discovery cycle and its report: Go's `RunCycle` and `sendReport`
//! (`collector.go`) for the sources this agent reads. Only while
//! connected: the running containers' services (when the Docker source is
//! on and the Docker collector runs), the last report's Docker services
//! again when the container list fails, the recognition probes (names for
//! unknown services and the connector suggestions' `compat_*` metadata),
//! LabTether naming, health checks, then one `webservice.report` with the
//! asset ID in use when it is sent.
//!
//! Go also reads reverse-proxy routes and runs a local and a LAN port
//! scan; those come in later parts, so their sources are reported as not
//! enabled.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use labtether_agent_core::{HubSender, OnStop, Stop};
use labtether_agent_platform::gotime::rfc3339;
use labtether_protocol::{
    DiscoveredWebService, MSG_WEBSERVICE_REPORT, Message, WebServiceDiscoverySourceStat,
    WebServiceDiscoveryStats, WebServiceReportData,
};
use tokio::sync::watch;

use super::fingerprint::Recognizer;
use super::health::{HealthCache, Prober};
use super::{containers, labtether};
use crate::docker::engine::{self, EngineApi};

/// Go's source names, in its log line's order.
pub(crate) const SOURCES: [&str; 4] = ["docker", "proxy", "local_scan", "lan_scan"];

/// The probes' runtime on the collector's thread; work ends when the
/// agent stops.
pub(crate) struct Runner {
    runtime: tokio::runtime::Runtime,
    stopped: watch::Receiver<bool>,
    _hook: OnStop,
}

impl Runner {
    pub fn new(stop: &Stop) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (stopping, stopped) = watch::channel(false);
        let hook = stop.on_stop(move || {
            let _ = stopping.send(true);
        });
        Ok(Self {
            runtime,
            stopped,
            _hook: hook,
        })
    }

    /// Runs `work` to its end; `None` when the agent stopped first.
    pub fn run<T>(&self, work: impl Future<Output = T>) -> Option<T> {
        let mut stopped = self.stopped.clone();
        self.runtime.block_on(async move {
            tokio::select! {
                done = work => Some(done),
                _ = stopped.wait_for(|stopped| *stopped) => None,
            }
        })
    }
}

fn millis_since(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Go's `countDiscoveredServicesBySource`.
fn count_by_source(services: &[DiscoveredWebService]) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for svc in services {
        let source = svc.source.trim().to_lowercase();
        let source = if source.is_empty() {
            "unknown".to_owned()
        } else {
            source
        };
        *out.entry(source).or_default() += 1;
    }
    out
}

/// Go's `dedupeDiscoveredServices`: the first service with an ID stays.
fn dedupe(services: Vec<DiscoveredWebService>) -> Vec<DiscoveredWebService> {
    let mut seen = std::collections::BTreeSet::new();
    services
        .into_iter()
        .filter(|svc| svc.id.is_empty() || seen.insert(svc.id.clone()))
        .collect()
}

/// The collector's state between cycles.
pub(crate) struct Collector {
    pub host_ip: String,
    /// Go's `DockerEnabled`: the Docker source's setting.
    pub docker_enabled: bool,
    health: HealthCache,
    recognizer: Recognizer,
    /// The last sent report's services and the connection it went on: Go's
    /// `lastServices`, which its reconnect callback clears.
    last: Option<(u64, Vec<DiscoveredWebService>)>,
}

impl Collector {
    pub fn new(host_ip: String, docker_enabled: bool, interval: std::time::Duration) -> Self {
        Self {
            host_ip,
            docker_enabled,
            health: HealthCache::new(interval),
            recognizer: Recognizer::default(),
            last: None,
        }
    }

    /// Go's `RunCycle`. `docker` is the engine when the Docker collector
    /// runs; `clock` is Go's `wsc.now()`: read once at the start for the
    /// health results and at each recognition cache look-up.
    pub fn run(
        &mut self,
        sender: &dyn HubSender,
        docker: Option<&dyn EngineApi>,
        prober: &dyn Prober,
        runner: &Runner,
        clock: &dyn Fn() -> SystemTime,
    ) {
        if !sender.connected() {
            return;
        }
        let started = Instant::now();
        let now = clock();
        let mut sources: BTreeMap<String, WebServiceDiscoverySourceStat> = SOURCES
            .iter()
            .map(|name| ((*name).to_owned(), WebServiceDiscoverySourceStat::default()))
            .collect();
        sources.insert(
            "docker".to_owned(),
            WebServiceDiscoverySourceStat {
                enabled: self.docker_enabled,
                ..Default::default()
            },
        );
        let mut services = Vec::new();
        if let (true, Some(api)) = (self.docker_enabled, docker) {
            let docker_started = Instant::now();
            let found = match engine::containers(api) {
                Ok(listed) => {
                    let found = containers::services(&listed, &self.host_ip, &sender.asset_id());
                    let count = found.len();
                    services.extend(found);
                    count
                }
                Err(error) => {
                    log::warn!("webservices: docker list failed: {error}");
                    // Go keeps the last report's Docker services while the
                    // list fails, until the next connection.
                    if let Some((_, last)) = self
                        .last
                        .as_ref()
                        .filter(|(connection, _)| *connection == sender.connection())
                    {
                        services.extend(last.iter().filter(|s| s.source == "docker").cloned());
                    }
                    0
                }
            };
            sources.insert(
                "docker".to_owned(),
                WebServiceDiscoverySourceStat {
                    enabled: true,
                    duration_ms: millis_since(docker_started),
                    services_found: i64::try_from(found).unwrap_or(i64::MAX),
                },
            );
        }
        let mut services = dedupe(services);
        let (recognizer, health) = (&mut self.recognizer, &mut self.health);
        let checked = runner.run(async {
            recognizer.apply(prober, &mut services, clock).await;
            labtether::normalize(&mut services);
            health.apply(prober, &mut services, now).await;
        });
        if checked.is_none() {
            return;
        }
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let discovery = WebServiceDiscoveryStats {
            collected_at: rfc3339(unix, 0),
            cycle_duration_ms: millis_since(started),
            total_services: i64::try_from(services.len()).unwrap_or(i64::MAX),
            final_source_count: count_by_source(&services),
            sources,
        };
        let line = SOURCES
            .iter()
            .map(|name| {
                let stat = &discovery.sources[*name];
                format!("{name}={}/{}ms", stat.services_found, stat.duration_ms)
            })
            .collect::<Vec<_>>()
            .join(" ");
        let (total, duration) = (discovery.total_services, discovery.cycle_duration_ms);
        if let Err(error) = send_report(sender, &mut services, discovery) {
            log::warn!("webservices: failed to send report: {error}");
            return;
        }
        log::info!("webservices: discovery cycle total={total} duration_ms={duration} {line}");
        self.last = Some((sender.connection(), services));
    }
}

/// Go's `sendReport`: the report's and each service's host is the asset
/// in use now (kept in the services, as Go's report shares their slice).
fn send_report(
    sender: &dyn HubSender,
    services: &mut [DiscoveredWebService],
    discovery: WebServiceDiscoveryStats,
) -> Result<(), String> {
    let asset = sender.asset_id();
    for svc in services.iter_mut() {
        svc.host_asset_id = asset.clone();
    }
    let report = WebServiceReportData {
        host_asset_id: asset,
        services: services.to_vec(),
        discovery: Some(discovery),
    };
    let message = Message::with_data(MSG_WEBSERVICE_REPORT, "", &report)
        .map_err(|error| format!("marshal report: {error}"))?;
    sender.send(&message).map_err(|error| error.to_string())
}
