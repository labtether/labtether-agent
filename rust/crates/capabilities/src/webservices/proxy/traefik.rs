//! Traefik: Go's `TraefikProvider` (`proxy/traefik.go`). Found as a
//! `traefik` image with its API port 8080 published (the API at
//! `http://localhost:<published port>`), else through an `api@internal`
//! router in its labels (the API at that router's first host, https when
//! its entry points or TLS labels say so), or at `LABTETHER_TRAEFIK_URL`.
//! The routers and services lists give one route per host in each enabled
//! router's rule, Traefik's own (`@internal`) left out.
//!
//! Go reads the labels in map order, so with two `api@internal` routers it
//! takes either; this takes the first by label name.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::api::{ApiRequest, ProxyApi, send};
use super::{Route, decode_first, find_host_port, normalize_image, nullable};
use crate::docker::raw::Container;

const API_PORT: i64 = 8080;
const ROUTER_PREFIX: &str = "traefik.http.routers.";

/// Go's `DetectAndConnect`.
pub(crate) fn detect(containers: &[Container], manual: &str) -> Option<String> {
    if !manual.is_empty() {
        return Some(manual.to_owned());
    }
    for c in containers {
        if normalize_image(&c.image) != "traefik" {
            continue;
        }
        match find_host_port(&c.ports, API_PORT) {
            0 => {
                if let Some(url) = dashboard_url_from_labels(&c.labels) {
                    return Some(url);
                }
            }
            port => return Some(format!("http://localhost:{port}")),
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct Router {
    #[serde(default, deserialize_with = "nullable")]
    name: String,
    #[serde(default, deserialize_with = "nullable")]
    rule: String,
    #[serde(default, deserialize_with = "nullable")]
    service: String,
    #[serde(default, deserialize_with = "nullable")]
    status: String,
    #[serde(rename = "entryPoints", default, deserialize_with = "nullable")]
    entry_points: Vec<String>,
    /// Go's `*struct{}`: set by any object.
    #[serde(default)]
    tls: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct ServiceItem {
    #[serde(default, deserialize_with = "nullable")]
    name: String,
    #[serde(rename = "loadBalancer", default)]
    load_balancer: Option<LoadBalancer>,
}

#[derive(Debug, Deserialize)]
struct LoadBalancer {
    #[serde(default, deserialize_with = "nullable")]
    servers: Vec<Server>,
}

#[derive(Debug, Deserialize)]
struct Server {
    #[serde(default, deserialize_with = "nullable")]
    url: String,
}

/// One list, as Go's `fetchRouters` and `fetchServices`.
async fn list<T: serde::de::DeserializeOwned>(
    api: &dyn ProxyApi,
    url: String,
    auth: Option<String>,
    what: &str,
) -> Result<Vec<T>, String> {
    let response = send(api, ApiRequest::get(url, auth), None).await?;
    if response.status != 200 {
        return Err(format!("HTTP {} from {what} endpoint", response.status));
    }
    decode_first::<Option<Vec<T>>>(&response.body)
        .map(Option::unwrap_or_default)
        .map_err(|error| format!("decode {what}: {error}"))
}

/// Go's `FetchRoutes`. `auth` is the basic auth header, when both the
/// user and the password are set.
pub(crate) async fn fetch(
    api: &dyn ProxyApi,
    base: &str,
    auth: Option<String>,
) -> Result<Vec<Route>, String> {
    let routers: Vec<Router> = list(
        api,
        format!("{base}/api/http/routers?per_page=1000"),
        auth.clone(),
        "routers",
    )
    .await
    .map_err(|e| format!("traefik routers: {e}"))?;
    let services: Vec<ServiceItem> = list(
        api,
        format!("{base}/api/http/services?per_page=1000"),
        auth,
        "services",
    )
    .await
    .map_err(|e| format!("traefik services: {e}"))?;
    let by_name: BTreeMap<String, ServiceItem> =
        services.into_iter().map(|s| (s.name.clone(), s)).collect();
    let mut routes = Vec::new();
    for router in routers {
        if router.name.ends_with("@internal") || router.status != "enabled" {
            continue;
        }
        let domains = hosts_in_rule(&router.rule);
        if domains.is_empty() {
            continue;
        }
        let tls = router.tls.is_some() || has_secure_entry_point(&router.entry_points);
        let backend_url = by_name
            .get(&router.service)
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.servers.first())
            .map(|server| server.url.clone())
            .unwrap_or_default();
        let router_name = strip_provider_suffix(&router.name);
        for domain in domains {
            routes.push(Route {
                domain,
                backend_url: backend_url.clone(),
                tls,
                router_name: router_name.to_owned(),
            });
        }
    }
    Ok(routes)
}

/// `c` is `want` (lower case) under Go's case folding.
fn folds_to(c: char, want: char) -> bool {
    c.to_ascii_lowercase() == want || (want == 's' && c == '\u{17f}')
}

/// Where `(?i)(Host|HostRegexp)\(` matches at `at`: whether it is
/// `HostRegexp` and where its arguments start.
fn call_at(rule: &str, at: usize) -> Option<(bool, usize)> {
    let mut chars = rule[at..].char_indices();
    for want in ['h', 'o', 's', 't'] {
        if !folds_to(chars.next()?.1, want) {
            return None;
        }
    }
    let after = chars.clone();
    if let Some((i, '(')) = chars.next() {
        return Some((false, at + i + 1));
    }
    let mut chars = after;
    for want in ['r', 'e', 'g', 'e', 'x', 'p'] {
        if !folds_to(chars.next()?.1, want) {
            return None;
        }
    }
    match chars.next() {
        Some((i, '(')) => Some((true, at + i + 1)),
        _ => None,
    }
}

/// Go's `extractHostsFromRule`: every match of
/// `(?i)(Host|HostRegexp)\(([^)]*)\)`, its comma-separated arguments
/// without quotes, a `HostRegexp` pattern left out, each host once.
pub(crate) fn hosts_in_rule(rule: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut at = 0;
    while at < rule.len() {
        if let Some((regexp, start)) = call_at(rule, at)
            && let Some(close) = rule[start..].find(')')
        {
            for raw in rule[start..start + close].split(',') {
                let host = raw.trim().trim_matches(['`', '"', '\'']).trim();
                if host.is_empty() || (regexp && host.contains(['{', '}', '*', '[', ']', '+', '?']))
                {
                    continue;
                }
                if !hosts.iter().any(|h| h == host) {
                    hosts.push(host.to_owned());
                }
            }
            at = start + close + 1;
            continue;
        }
        at += rule[at..].chars().next().map_or(1, char::len_utf8);
    }
    hosts
}

/// Go's `hasSecureEntryPoint`.
fn has_secure_entry_point(entry_points: &[String]) -> bool {
    entry_points
        .iter()
        .any(|ep| matches!(ep.to_lowercase().as_str(), "websecure" | "https" | "tls"))
}

/// Go's `stripProviderSuffix`: `plex@docker` is `plex`.
fn strip_provider_suffix(name: &str) -> &str {
    name.rfind('@').map_or(name, |at| &name[..at])
}

/// Go's `traefikDashboardURLFromLabels`.
pub(crate) fn dashboard_url_from_labels(labels: &BTreeMap<String, String>) -> Option<String> {
    let normalized: BTreeMap<String, String> = labels
        .iter()
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_owned()))
        .collect();
    let get = |key: String| normalized.get(&key).map_or("", String::as_str);
    for (key, value) in &normalized {
        let Some(rest) = key.strip_prefix(ROUTER_PREFIX) else {
            continue;
        };
        if !key.ends_with(".service") || value.trim().to_lowercase() != "api@internal" {
            continue;
        }
        let router = rest.strip_suffix(".service").unwrap_or(rest);
        if router.is_empty() {
            continue;
        }
        let label = |suffix: &str| get(format!("{ROUTER_PREFIX}{router}{suffix}"));
        let domains = hosts_in_rule(label(".rule"));
        let Some(domain) = domains.first() else {
            continue;
        };
        let entry_points: Vec<String> = label(".entrypoints")
            .split(',')
            .map(str::trim)
            .filter(|ep| !ep.is_empty())
            .map(str::to_owned)
            .collect();
        let tls = has_secure_entry_point(&entry_points)
            || !label(".tls").is_empty()
            || !label(".tls.certresolver").is_empty();
        let scheme = if tls { "https" } else { "http" };
        return Some(format!("{scheme}://{domain}"));
    }
    None
}
