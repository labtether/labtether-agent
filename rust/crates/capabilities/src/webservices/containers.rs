//! Services from running containers: Go's `buildServicesFromContainers`
//! and its port choice (`discovery_docker.go`). Each published TCP port
//! that looks like a web port becomes a service (one for a known service,
//! at most four for an unknown one), named and sorted by the registry
//! (image first, then the container name, then the image as a hint) and by
//! the container's `labtether.*` labels.

use std::collections::{BTreeMap, BTreeSet};

use labtether_protocol::DiscoveredWebService;
use sha2::{Digest, Sha256};

use super::registry::{self, KnownService, OTHER};
use super::urls::{build_service_url, is_likely_web_port};
use crate::docker::raw::{Container, Port};

/// Go's `maxUnknownServicePorts`.
const MAX_UNKNOWN_PORTS: usize = 4;

/// Go's `makeServiceID`: the first 8 bytes of SHA-256 over
/// `host:source:identifier`, in hex.
pub(crate) fn make_service_id(host: &str, source: &str, identifier: &str) -> String {
    let digest = Sha256::digest(format!("{host}:{source}:{identifier}"));
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn public_tcp(ports: &[Port]) -> Vec<&Port> {
    ports
        .iter()
        .filter(|p| p.public_port > 0 && p.r#type.eq_ignore_ascii_case("tcp"))
        .collect()
}

/// Go's `extractHostPortsForService`.
fn host_ports(ports: &[Port], known: Option<&KnownService>) -> Vec<i64> {
    let filtered = public_tcp(ports);
    let Some(first) = filtered.first() else {
        return Vec::new();
    };
    if let Some(known) = known {
        let default = i64::from(known.default_port);
        if default > 0
            && is_likely_web_port(default)
            && let Some(p) = filtered
                .iter()
                .find(|p| p.private_port == default || p.public_port == default)
        {
            return vec![p.public_port];
        }
    }
    let mut seen = BTreeSet::new();
    let likely: Vec<i64> = filtered
        .iter()
        .filter(|p| is_likely_web_port(p.public_port) || is_likely_web_port(p.private_port))
        .map(|p| p.public_port)
        .filter(|port| seen.insert(*port))
        .collect();
    match (known, likely.first()) {
        (Some(_), Some(port)) => vec![*port],
        (Some(_), None) | (None, None) => vec![first.public_port],
        (None, Some(_)) => likely.into_iter().take(MAX_UNKNOWN_PORTS).collect(),
    }
}

/// Go's `bindingForPublicPort`.
fn binding(ports: &[Port], public: i64) -> Option<&Port> {
    ports
        .iter()
        .find(|p| p.public_port == public && p.r#type.eq_ignore_ascii_case("tcp"))
}

/// Go's `normalizedBindingHost`: empty for an any-address binding.
fn binding_host(raw: &str) -> &str {
    match raw.trim() {
        "" | "0.0.0.0" | "::" | "[::]" => "",
        "127.0.0.1" | "::1" => "localhost",
        value => value,
    }
}

/// Go's `hostForPublicPort`.
fn host_for(ports: &[Port], public: i64, fallback: &str) -> String {
    match binding(ports, public).map(|p| binding_host(&p.ip)) {
        Some(host) if !host.is_empty() => host.to_owned(),
        _ if fallback.is_empty() => "localhost".to_owned(),
        _ => fallback.to_owned(),
    }
}

/// Go's `ContainerName` then `cleanContainerName`: the first name without
/// its leading `/` (each takes one).
fn container_name(names: &[String]) -> String {
    let first = names.first().map(String::as_str).unwrap_or("");
    let once = first.strip_prefix('/').unwrap_or(first);
    once.strip_prefix('/').unwrap_or(once).to_owned()
}

fn label<'a>(labels: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    labels.get(key).map_or("", |value| value.trim())
}

/// Go's `buildServicesFromContainers`. `asset_id` is the asset in use now;
/// the report sets each service's host again when it is sent.
pub(crate) fn services(
    containers: &[Container],
    host_ip: &str,
    asset_id: &str,
) -> Vec<DiscoveredWebService> {
    let mut services = Vec::new();
    for c in containers.iter().filter(|c| c.state == "running") {
        let mut name = container_name(&c.names);
        let known = registry::by_docker_image(&c.image)
            .or_else(|| registry::by_hint(&name))
            .or_else(|| registry::by_hint(&c.image));
        let (mut category, mut icon_key, mut service_key, mut health_path) =
            (OTHER.to_owned(), String::new(), String::new(), "");
        if let Some(known) = known {
            name = known.name.to_owned();
            category = known.category.to_owned();
            icon_key = known.icon_key.to_owned();
            service_key = known.key.to_owned();
            health_path = known.health_path;
        }
        for (key, field) in [
            ("labtether.name", &mut name),
            ("labtether.category", &mut category),
            ("labtether.icon", &mut icon_key),
        ] {
            let value = label(&c.labels, key);
            if !value.is_empty() {
                *field = value.to_owned();
            }
        }
        let ports = host_ports(&c.ports, known);
        for &port in &ports {
            let url = build_service_url(&host_for(&c.ports, port, host_ip), port);
            let display = if ports.len() > 1 {
                format!("{name}:{port}")
            } else {
                name.clone()
            };
            let mut metadata = BTreeMap::new();
            let image = c.image.trim();
            if !image.is_empty() {
                metadata.insert("image".to_owned(), image.to_owned());
            }
            if !health_path.is_empty() {
                metadata.insert("health_path".to_owned(), health_path.to_owned());
            }
            if label(&c.labels, "labtether.hidden").eq_ignore_ascii_case("true") {
                metadata.insert("hidden".to_owned(), "true".to_owned());
            }
            if let Some(bound) = binding(&c.ports, port) {
                metadata.insert("public_port".to_owned(), bound.public_port.to_string());
                if bound.private_port > 0 {
                    metadata.insert("private_port".to_owned(), bound.private_port.to_string());
                }
            }
            services.push(DiscoveredWebService {
                id: make_service_id(asset_id, "docker", &format!("{}:{port}", c.id)),
                service_key: service_key.clone(),
                name: display,
                category: category.clone(),
                url,
                source: "docker".to_owned(),
                container_id: c.id.clone(),
                host_asset_id: asset_id.to_owned(),
                icon_key: icon_key.clone(),
                metadata,
                ..DiscoveredWebService::default()
            });
        }
    }
    services
}
