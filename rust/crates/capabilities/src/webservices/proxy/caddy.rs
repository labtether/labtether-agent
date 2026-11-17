//! Caddy: Go's `CaddyProvider` (`proxy/caddy.go`). Found as a `caddy` or
//! `lucaslorentz/caddy-docker-proxy` image with its admin port 2019
//! published (the API at `http://localhost:<published port>`), or at
//! `LABTETHER_CADDY_URL`. `GET /config/` gives one route per host of each
//! route whose handlers (or nested routes) reverse-proxy somewhere: the
//! first upstream as `http://<dial>`, TLS when the server listens on 443,
//! 8443, 9443 or 10443, the server's name as the router name.
//!
//! Go reads the servers in map order; this reads them by name.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::api::{ApiRequest, ProxyApi, send};
use super::{Route, decode_first, find_host_port, normalize_image, nullable};
use crate::docker::raw::Container;

const ADMIN_PORT: i64 = 2019;
const IMAGES: [&str; 2] = ["caddy", "lucaslorentz/caddy-docker-proxy"];
const TLS_PORTS: [&str; 4] = [":443", ":8443", ":9443", ":10443"];

/// Go's `DetectAndConnect`.
pub(crate) fn detect(containers: &[Container], manual: &str) -> Option<String> {
    if !manual.is_empty() {
        return Some(manual.to_owned());
    }
    for c in containers {
        if !IMAGES.contains(&normalize_image(&c.image).as_str()) {
            continue;
        }
        let port = find_host_port(&c.ports, ADMIN_PORT);
        if port == 0 {
            log::info!(
                "webservices: caddy container {} has no published admin port {ADMIN_PORT}; trying the next one",
                c.id
            );
            continue;
        }
        let url = format!("http://localhost:{port}");
        log::info!("webservices: caddy found at {url} (container {})", c.id);
        return Some(url);
    }
    None
}

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default, deserialize_with = "nullable")]
    apps: Apps,
}

#[derive(Debug, Default, Deserialize)]
struct Apps {
    #[serde(default, deserialize_with = "nullable")]
    http: Http,
}

#[derive(Debug, Default, Deserialize)]
struct Http {
    #[serde(default, deserialize_with = "nullable")]
    servers: BTreeMap<String, Server>,
}

#[derive(Debug, Default, Deserialize)]
struct Server {
    #[serde(default, deserialize_with = "nullable")]
    listen: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    routes: Vec<CaddyRoute>,
}

#[derive(Debug, Default, Deserialize)]
struct CaddyRoute {
    #[serde(rename = "match", default, deserialize_with = "nullable")]
    matches: Vec<Match>,
    #[serde(default, deserialize_with = "nullable")]
    handle: Vec<Handler>,
}

#[derive(Debug, Default, Deserialize)]
struct Match {
    #[serde(default, deserialize_with = "nullable")]
    host: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Handler {
    #[serde(default, deserialize_with = "nullable")]
    handler: String,
    #[serde(default, deserialize_with = "nullable")]
    upstreams: Vec<Upstream>,
    #[serde(default, deserialize_with = "nullable")]
    routes: Vec<CaddyRoute>,
}

#[derive(Debug, Default, Deserialize)]
struct Upstream {
    #[serde(default, deserialize_with = "nullable")]
    dial: String,
}

/// Go's `firstCaddyBackendURL`.
fn first_backend(handlers: &[Handler]) -> String {
    for handler in handlers {
        if handler.handler == "reverse_proxy"
            && let Some(first) = handler.upstreams.first()
            && !first.dial.is_empty()
        {
            return format!("http://{}", first.dial);
        }
        for nested in &handler.routes {
            let backend = first_backend(&nested.handle);
            if !backend.is_empty() {
                return backend;
            }
        }
    }
    String::new()
}

/// Go's `FetchRoutes`.
pub(crate) async fn fetch(api: &dyn ProxyApi, base: &str) -> Result<Vec<Route>, String> {
    let response = send(api, ApiRequest::get(format!("{base}/config/"), None), None)
        .await
        .map_err(|e| format!("caddy config request failed: {e}"))?;
    if response.status != 200 {
        return Err(format!("caddy config returned status {}", response.status));
    }
    let config = decode_first::<Option<Config>>(&response.body)
        .map_err(|e| format!("caddy config decode failed: {e}"))?
        .unwrap_or_default();
    let mut routes = Vec::new();
    for (name, server) in &config.apps.http.servers {
        let tls = server
            .listen
            .iter()
            .any(|addr| TLS_PORTS.iter().any(|port| addr.ends_with(port)));
        for route in &server.routes {
            let backend_url = first_backend(&route.handle);
            if backend_url.is_empty() {
                continue;
            }
            for host in route.matches.iter().flat_map(|m| &m.host) {
                routes.push(Route {
                    domain: host.clone(),
                    backend_url: backend_url.clone(),
                    tls,
                    router_name: name.clone(),
                });
            }
        }
    }
    Ok(routes)
}
