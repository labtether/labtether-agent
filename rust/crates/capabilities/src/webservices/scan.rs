//! The local port scan: Go's `discoverPortScannedServicesWithConfig`,
//! `scanCandidatePortsWithOptions` and `scannedPortMetadata`
//! (`scan_discovery.go`) and `addKnownServicePorts` (`scan_endpoints.go`).
//! Host services outside Docker: Go's 49 default ports (or the owner's
//! list) and, when asked, the first 128 listening TCP ports, each dialled
//! on the host's own address only (250 ms, 16 at once) and kept when it
//! answers an HTTP or HTTPS GET. Ports a service found earlier in the cycle
//! already uses are skipped. A port the registry gives to one service is
//! named after it; at most 8 others are listed, as "Port N". The
//! recognition probes and health checks then treat them as any service.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures_util::StreamExt;
use labtether_agent_config::PortScanSettings;
use labtether_protocol::DiscoveredWebService;

use super::containers::make_service_id;
use super::health::{Method, Prober, request};
use super::registry::{self, OTHER};
use super::urls::{
    alternate_scheme_url, build_service_url, is_likely_https_port, is_likely_web_port, parse_port,
    port_from_url,
};

/// Go's `defaultPortScanCandidates`.
const DEFAULT_PORTS: [u16; 49] = [
    80, 81, 82, 88, 443, 591, 593, 631, 2375, 2376, 3000, 3001, 3002, 4000, 5000, 5055, 5601, 6001,
    7000, 7080, 7081, 7443, 7474, 8000, 8001, 8006, 8007, 8080, 8081, 8082, 8088, 8089, 8090, 8091,
    8096, 8123, 8181, 8443, 8888, 8989, 9000, 9001, 9090, 9091, 9443, 9696, 10443, 19999, 32400,
];
/// Go's `maxListeningScanPorts`, `maxUnknownScannedServices` and
/// `maxPortScanConcurrency`.
const MAX_LISTENING: usize = 128;
const MAX_UNKNOWN: usize = 8;
const MAX_IN_FLIGHT: usize = 16;
/// Go's `portScanDialTimeout`.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_millis(250);

pub(crate) type Dialing<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// What the scan reads from the host.
pub(crate) trait ScanHost: Send + Sync {
    /// The listening TCP ports, sorted, each once (Go's
    /// `detectListeningTCPPorts`).
    fn listening(&self) -> Vec<u16>;

    /// Go's `isTCPPortReachable`: whether `host:port` took a TCP
    /// connection within 250 ms; with `tls_hello`, a TLS hello is sent
    /// before closing it (the reply does not matter).
    fn dial<'a>(&'a self, host: &'a str, port: u16, tls_hello: bool) -> Dialing<'a>;
}

/// Go's `scanCandidatePortsWithOptions`: the owner's list or the default
/// ports, the first 128 listening ports (the lowest: the list is sorted)
/// when asked, sorted, each once.
fn candidates(settings: &PortScanSettings, host: &dyn ScanHost) -> Vec<u16> {
    let mut ports = if settings.ports.is_empty() {
        DEFAULT_PORTS.to_vec()
    } else {
        settings.ports.clone()
    };
    if settings.include_listening {
        ports.extend(host.listening().into_iter().take(MAX_LISTENING));
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Go's `addKnownServicePorts` over the services found so far: the port
/// written in each URL (also `raw_url`, `backend_url` and every
/// `alt_urls` entry) and the `public_port` and `private_port` metadata.
fn known_ports(services: &[DiscoveredWebService]) -> BTreeSet<u16> {
    let mut known = BTreeSet::new();
    for svc in services {
        let meta = |key: &str| svc.metadata.get(key).map_or("", String::as_str);
        let mut ports = vec![
            port_from_url(&svc.url),
            port_from_url(meta("raw_url")),
            port_from_url(meta("backend_url")),
            parse_port(meta("public_port")).unwrap_or(0),
            parse_port(meta("private_port")).unwrap_or(0),
        ];
        let alt = meta("alt_urls").trim();
        if !alt.is_empty() {
            ports.extend(alt.split(',').map(|url| port_from_url(url.trim())));
        }
        known.extend(ports.into_iter().filter(|port| *port > 0));
    }
    known
}

/// Go's `answersHTTP`: a GET at the port's URL, then at the other scheme.
async fn answers_http(prober: &dyn Prober, host: &str, port: u16) -> bool {
    let base = build_service_url(host, i64::from(port));
    if request(prober, Method::Get, &base).await.is_some() {
        return true;
    }
    let alternate = alternate_scheme_url(&base);
    !alternate.is_empty() && request(prober, Method::Get, &alternate).await.is_some()
}

/// Go's order: ports the registry names first, then the likely web
/// ports, then by number.
fn order(port: u16) -> (bool, bool, u16) {
    (
        registry::unique_by_port(port).is_none(),
        !is_likely_web_port(i64::from(port)),
        port,
    )
}

/// The services the scan finds. `existing` are the services found earlier
/// in the cycle; `asset` gives the asset ID, read after the dials as Go.
pub(crate) async fn services(
    settings: &PortScanSettings,
    host_ip: &str,
    asset: &dyn Fn() -> String,
    existing: &[DiscoveredWebService],
    host: &dyn ScanHost,
    prober: &dyn Prober,
) -> Vec<DiscoveredWebService> {
    if !settings.enabled {
        return Vec::new();
    }
    let ports = candidates(settings, host);
    let address = match host_ip.trim() {
        "" => "localhost",
        trimmed => trimmed,
    };
    let known = known_ports(existing);
    let mut open: Vec<u16> =
        futures_util::stream::iter(ports.into_iter().filter(|port| !known.contains(port)))
            .map(|port| async move {
                let reachable = host
                    .dial(address, port, is_likely_https_port(i64::from(port)))
                    .await;
                (reachable && answers_http(prober, address, port).await).then_some(port)
            })
            .buffer_unordered(MAX_IN_FLIGHT)
            .filter_map(std::future::ready)
            .collect()
            .await;
    if open.is_empty() {
        return Vec::new();
    }
    open.sort_by_key(|port| order(*port));
    let asset_id = asset();
    let mut unknown = 0;
    let mut found = Vec::new();
    for port in open {
        let known = registry::unique_by_port(port);
        if known.is_none() {
            if unknown >= MAX_UNKNOWN {
                continue;
            }
            unknown += 1;
        }
        let mut svc = DiscoveredWebService {
            id: make_service_id(&asset_id, "scan", &port.to_string()),
            name: format!("Port {port}"),
            category: OTHER.to_owned(),
            url: build_service_url(address, i64::from(port)),
            source: "scan".to_owned(),
            host_asset_id: asset_id.clone(),
            ..DiscoveredWebService::default()
        };
        svc.metadata
            .insert("public_port".to_owned(), port.to_string());
        if let Some(known) = known {
            svc.service_key = known.key.to_owned();
            svc.name = known.name.to_owned();
            svc.category = known.category.to_owned();
            svc.icon_key = known.icon_key.to_owned();
            if !known.health_path.is_empty() {
                svc.metadata
                    .insert("health_path".to_owned(), known.health_path.to_owned());
            }
        }
        found.push(svc);
    }
    log::info!(
        "webservices: port scan discovered {} services on host {address}",
        found.len()
    );
    found
}
