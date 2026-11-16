//! LabTether's own services (`fingerprinting.go`). Recognition, Go's
//! `isLabTetherService`: the Hub's `/healthz` or `/version` names the
//! service `labtether` (or `/healthz` says the port only redirects to
//! HTTPS), or the console's `/api/health` answers and its login page or
//! root page names LabTether, or the login page names it and
//! `/api/auth/login` refuses a GET as the Hub does. When nothing at the
//! URL answers, the other scheme is asked.
//!
//! Naming, Go's `normalizeLabTetherServices`: a service with the
//! `labtether` key is the console (port 3000, or health path
//! `/api/health`) or the API (8080 or 8443, or `/healthz`, `/version`);
//! the API is hidden on a host whose console is listed, and shown
//! otherwise.

use std::collections::BTreeSet;

use labtether_protocol::DiscoveredWebService;
use serde_json::{Map, Value};

use super::health::Prober;
use super::location::same_origin_redirect;
use super::pages::{contains, fetch_body, get, json_object, page_contains};
use super::urls::{alternate_scheme_url, port_from_url};

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

/// Go's `hasLabTetherServiceField`.
fn names_labtether(payload: &Map<String, Value>) -> bool {
    payload
        .get("service")
        .and_then(Value::as_str)
        .is_some_and(|service| service.trim().eq_ignore_ascii_case(KEY))
}

/// Go's `isLabTetherHTTPSRedirect`: the Hub's HTTP port when it only
/// redirects to HTTPS.
fn https_redirect(payload: &Map<String, Value>) -> bool {
    let text = |key| payload.get(key).and_then(Value::as_str).unwrap_or("");
    text("status") == "redirect_active" && text("redirect").starts_with("https on port ")
}

/// Go's `hasLabTetherFrontendHealthPayload`.
fn console_health(payload: &Map<String, Value>) -> bool {
    payload
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status.trim().to_lowercase().as_str(), "ok" | "error"))
}

/// Go's `labTetherLoginPageMarker`: whether the login page names
/// LabTether, after one redirect on the same origin (the console sends
/// `/login` to its locale path), and whether it answered under 500.
async fn login_page_names_labtether(prober: &dyn Prober, base: &str) -> (bool, bool) {
    let login = format!("{}/login", base.trim_end_matches('/'));
    let Some(answer) = get(prober, &login).await.filter(|a| a.status < 500) else {
        return (false, false);
    };
    let mut body = answer.body;
    if (300..400).contains(&answer.status) {
        let target = same_origin_redirect(&login, &answer.location);
        if !target.is_empty()
            && let Some(moved) = get(prober, &target).await
            && moved.status < 500
        {
            body = moved.body;
        }
    }
    (contains(&body, KEY), true)
}

/// Go's `hasLabTetherAuthLoginEndpointWithResponse`: the Hub refuses a GET
/// of its login API.
async fn auth_login_refuses_get(prober: &dyn Prober, base: &str) -> (bool, bool) {
    match fetch_body(prober, base, "/api/auth/login").await {
        None => (false, false),
        Some(answer) => (matches!(answer.status, 400 | 405 | 415 | 422), true),
    }
}

/// Go's `isLabTetherServiceAtBase`: found, and whether anything answered.
async fn at_base(prober: &dyn Prober, base: &str) -> (bool, bool) {
    let mut responded = false;
    if let Some(answer) = fetch_body(prober, base, "/healthz").await {
        responded = true;
        let hub = |p: Map<String, Value>| names_labtether(&p) || https_redirect(&p);
        if answer.status == 200 && json_object(&answer.body).is_some_and(hub) {
            return (true, true);
        }
    }
    if let Some(answer) = fetch_body(prober, base, "/version").await {
        responded = true;
        if answer.status == 200 && json_object(&answer.body).is_some_and(|p| names_labtether(&p)) {
            return (true, true);
        }
    }
    if let Some(answer) = fetch_body(prober, base, "/api/health").await {
        responded = true;
        if json_object(&answer.body).is_some_and(|p| console_health(&p)) {
            let (login, login_answered) = login_page_names_labtether(prober, base).await;
            let (root, root_answered) = page_contains(prober, base, "/", KEY).await;
            responded = responded || login_answered || root_answered;
            if login || root {
                return (true, true);
            }
        }
    }
    let (login, login_answered) = login_page_names_labtether(prober, base).await;
    responded = responded || login_answered;
    if login {
        let (auth, auth_answered) = auth_login_refuses_get(prober, base).await;
        responded = responded || auth_answered;
        if auth {
            return (true, true);
        }
    }
    (false, responded)
}

/// Go's `isLabTetherService`.
pub(crate) async fn is_labtether_service(prober: &dyn Prober, base: &str) -> bool {
    let (found, responded) = at_base(prober, base).await;
    if found || responded {
        return found;
    }
    let alternate = alternate_scheme_url(base);
    if alternate.is_empty() || base.eq_ignore_ascii_case(&alternate) {
        return false;
    }
    at_base(prober, &alternate).await.0
}
