//! Services with their proxy routes: Go's `enrichServicesWithRoutes` and
//! helpers (`proxy_provider.go`). Each route with a domain goes to one
//! service: for Traefik, a service an earlier route to the same backend
//! went to; then a container whose Traefik router labels name the route's
//! router (when only one service has it); then the first container
//! publishing the backend's port as its private port; then the one service
//! whose URL has that port. The first route a service gets becomes its
//! URL (the old URL kept as `raw_url`, the provider as `proxy_provider`);
//! the others are added to `alt_urls`. A route that matches nothing
//! becomes a service of its own, source `proxy`, named by a registry
//! service with the backend's port, else by a hint in the domain or the
//! router's name, else by the domain's first label.

use std::collections::{BTreeMap, BTreeSet};

use labtether_protocol::DiscoveredWebService;

use super::containers::make_service_id;
use super::gourl;
use super::proxy::Route;
use super::registry::{self, OTHER};
use crate::docker::raw::Container;

const ROUTER_PREFIX: &str = "traefik.http.routers.";

/// Go's `buildProxiedURL`.
fn proxied_url(domain: &str, tls: bool) -> String {
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://{domain}")
}

/// Go's `portFromURL` of `proxy_provider.go`: a port written in a URL Go
/// can parse, else 0.
pub(crate) fn port_from_url(raw: &str) -> u16 {
    if raw.is_empty() {
        return 0;
    }
    let Some(url) = gourl::parse(raw) else {
        return 0;
    };
    if url.host.is_empty() {
        return 0;
    }
    let host = url.host.as_str();
    let port = match host.strip_prefix('[') {
        Some(inner) => match inner.rfind(']') {
            Some(end) => inner[end + 1..].strip_prefix(':').unwrap_or(""),
            None => return 0,
        },
        None => host.rsplit_once(':').map_or("", |(_, port)| port),
    };
    super::urls::parse_port(port).unwrap_or(0)
}

/// Go's `canonicalBackendIdentity`.
pub(crate) fn backend_identity(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let Some(url) = gourl::parse(raw.trim()) else {
        return String::new();
    };
    let host = url.hostname().trim().to_lowercase();
    if host.is_empty() {
        return String::new();
    }
    let scheme = match url.scheme.trim().to_lowercase() {
        scheme if scheme.is_empty() => "http".to_owned(),
        scheme => scheme,
    };
    let port = match (url.port().trim(), scheme.as_str()) {
        ("", "https") => "443",
        ("", "http") => "80",
        (port, _) => port,
    };
    let path = match url.escaped_path().trim() {
        "" => "/".to_owned(),
        path => path.to_owned(),
    };
    if port.is_empty() {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    }
}

/// Go's `domainToName`: the domain's first label.
fn domain_to_name(domain: &str) -> &str {
    domain.split('.').next().unwrap_or("")
}

/// Go's `appendAltURL`: added once (case ignored), order kept.
pub(crate) fn append_alt_url(existing: &str, url: &str) -> String {
    let url = url.trim();
    let mut seen = BTreeSet::new();
    let mut out: Vec<&str> = existing
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty() && seen.insert(part.to_lowercase()))
        .collect();
    if !url.is_empty() && !seen.contains(&url.to_lowercase()) {
        out.push(url);
    }
    out.join(",")
}

/// Go's `applyEnrichment`.
fn apply(svc: &mut DiscoveredWebService, url: &str, provider: &str) {
    if svc
        .metadata
        .get("proxy_provider")
        .is_none_or(String::is_empty)
    {
        let raw = std::mem::replace(&mut svc.url, url.to_owned());
        svc.metadata.insert("raw_url".into(), raw);
        svc.metadata
            .insert("proxy_provider".into(), provider.into());
    } else if !svc.url.trim().eq_ignore_ascii_case(url.trim()) {
        let alt = svc.metadata.get("alt_urls").map_or("", String::as_str);
        let alt = append_alt_url(alt, url);
        svc.metadata.insert("alt_urls".into(), alt);
    }
}

/// Go's `traefikRoutersFromLabels`: the router names, lower case.
fn routers_in_labels(labels: &BTreeMap<String, String>) -> BTreeSet<String> {
    labels
        .keys()
        .filter_map(|key| {
            let lower = key.trim().to_lowercase();
            let rest = lower.strip_prefix(ROUTER_PREFIX)?.to_owned();
            let dot = rest.find('.').filter(|dot| *dot > 0)?;
            let router = rest[..dot].trim();
            (!router.is_empty()).then(|| router.to_owned())
        })
        .collect()
}

/// Go's `buildProxyOnlyService`.
fn proxy_only(route: &Route, provider: &str, asset: &str, host_ip: &str) -> DiscoveredWebService {
    let port = port_from_url(&route.backend_url);
    let known = (port > 0)
        .then(|| registry::unique_by_port(port))
        .flatten()
        .or_else(|| registry::by_hint(&route.domain))
        .or_else(|| registry::by_hint(&route.router_name));
    let seed = if asset.is_empty() { host_ip } else { asset };
    let mut svc = DiscoveredWebService {
        id: make_service_id(seed, "proxy", &route.domain),
        name: domain_to_name(&route.domain).to_owned(),
        category: OTHER.to_owned(),
        url: proxied_url(&route.domain, route.tls),
        source: "proxy".to_owned(),
        host_asset_id: asset.to_owned(),
        ..DiscoveredWebService::default()
    };
    if let Some(known) = known {
        svc.service_key = known.key.to_owned();
        svc.name = known.name.to_owned();
        known.category.clone_into(&mut svc.category);
        svc.icon_key = known.icon_key.to_owned();
    }
    svc.metadata
        .insert("proxy_provider".into(), provider.into());
    svc.metadata
        .insert("router_name".into(), route.router_name.clone());
    if !route.backend_url.is_empty() {
        svc.metadata
            .insert("backend_url".into(), route.backend_url.clone());
        svc.metadata
            .insert("raw_url".into(), route.backend_url.clone());
    }
    svc
}

/// Go's `enrichServicesWithRoutes`. `containers` is the engine's whole
/// list (empty when it was not read).
pub(crate) fn enrich(
    services: &mut Vec<DiscoveredWebService>,
    routes: &[Route],
    provider: &str,
    asset: &str,
    host_ip: &str,
    containers: &[Container],
) {
    let traefik = provider.eq_ignore_ascii_case("traefik");
    let mut by_private: BTreeMap<i64, Vec<&str>> = BTreeMap::new();
    for c in containers {
        for p in c.ports.iter().filter(|p| p.public_port > 0) {
            by_private.entry(p.private_port).or_default().push(&c.id);
        }
    }
    let mut by_container: BTreeMap<String, usize> = BTreeMap::new();
    for (i, svc) in services.iter().enumerate() {
        if !svc.container_id.is_empty() {
            by_container.insert(svc.container_id.clone(), i);
        }
    }
    let mut by_router: BTreeMap<String, usize> = BTreeMap::new();
    if traefik {
        let mut candidates: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for c in containers {
            if let Some(&i) = by_container.get(&c.id) {
                for router in routers_in_labels(&c.labels) {
                    candidates.entry(router).or_default().insert(i);
                }
            }
        }
        for (router, set) in candidates {
            if let (1, Some(&i)) = (set.len(), set.first()) {
                by_router.insert(router, i);
            }
        }
    }
    let mut by_port: BTreeMap<u16, usize> = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (i, svc) in services.iter().enumerate() {
        let port = port_from_url(&svc.url);
        if port > 0 && by_port.insert(port, i).is_some() {
            ambiguous.insert(port);
        }
    }
    let mut by_backend: BTreeMap<String, usize> = BTreeMap::new();
    for route in routes.iter().filter(|r| !r.domain.is_empty()) {
        let url = proxied_url(&route.domain, route.tls);
        let port = port_from_url(&route.backend_url);
        let key = if traefik {
            backend_identity(&route.backend_url)
        } else {
            String::new()
        };
        if let Some(&i) = by_backend.get(&key).filter(|_| !key.is_empty()) {
            apply(&mut services[i], &url, provider);
            continue;
        }
        let router = route.router_name.trim().to_lowercase();
        let matched = by_router
            .get(&router)
            .filter(|_| !router.is_empty())
            .copied()
            .or_else(|| {
                let ids = by_private.get(&i64::from(port)).filter(|_| port > 0)?;
                ids.iter().find_map(|id| by_container.get(*id).copied())
            })
            .or_else(|| {
                (port > 0 && !ambiguous.contains(&port))
                    .then(|| by_port.get(&port).copied())
                    .flatten()
            });
        let index = match matched {
            Some(i) => {
                apply(&mut services[i], &url, provider);
                i
            }
            None => {
                services.push(proxy_only(route, provider, asset, host_ip));
                services.len() - 1
            }
        };
        if !key.is_empty() {
            by_backend.insert(key, index);
        }
    }
}
