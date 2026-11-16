//! LabTether's own services: Go's `normalizeLabTetherServices`
//! (`fingerprinting.go`). A service with the `labtether` key is the
//! console (port 3000, or health path `/api/health`) or the API (8080 or
//! 8443, or `/healthz`, `/version`); the API is hidden on a host whose
//! console is listed, and shown otherwise.

use std::collections::BTreeSet;

use labtether_protocol::DiscoveredWebService;

use super::urls::port_from_url;

const KEY: &str = "labtether";
const CONSOLE: &str = "console";
const API: &str = "api";

fn meta<'a>(svc: &'a DiscoveredWebService, key: &str) -> &'a str {
    svc.metadata.get(key).map_or("", |value| value.trim())
}

/// Go's `classifyLabTetherComponent`.
fn component(svc: &DiscoveredWebService) -> Option<&'static str> {
    match meta(svc, "labtether_component").to_lowercase().as_str() {
        CONSOLE => return Some(CONSOLE),
        API => return Some(API),
        _ => {}
    }
    let mut port = port_from_url(&svc.url);
    for key in ["raw_url", "backend_url"] {
        if port == 0 && !meta(svc, key).is_empty() {
            port = port_from_url(meta(svc, key));
        }
    }
    match port {
        3000 => return Some(CONSOLE),
        8080 | 8443 => return Some(API),
        _ => {}
    }
    match meta(svc, "health_path") {
        "/api/health" => Some(CONSOLE),
        "/healthz" | "/version" => Some(API),
        _ => None,
    }
}

/// Go's `normalizeLabTetherServices`.
pub(crate) fn normalize(services: &mut [DiscoveredWebService]) {
    let mut hosts_with_console = BTreeSet::new();
    for svc in services.iter_mut() {
        if svc.service_key.trim() != KEY {
            continue;
        }
        let Some(component) = component(svc) else {
            continue;
        };
        svc.metadata
            .insert("labtether_component".to_owned(), component.to_owned());
        if component == CONSOLE {
            svc.name = "LabTether Console".to_owned();
            hosts_with_console.insert(svc.host_asset_id.trim().to_owned());
            svc.metadata.remove("hidden");
        } else {
            svc.name = "LabTether API".to_owned();
        }
    }
    for svc in services.iter_mut() {
        let api = svc.metadata.get("labtether_component").map(String::as_str) == Some(API);
        if svc.service_key.trim() != KEY || !api {
            continue;
        }
        if hosts_with_console.contains(svc.host_asset_id.trim()) {
            svc.metadata.insert("hidden".to_owned(), "true".to_owned());
        } else {
            svc.metadata.remove("hidden");
        }
    }
}
