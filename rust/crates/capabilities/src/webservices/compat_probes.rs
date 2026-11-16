//! The API probes behind the Hub's connector suggestions: Go's
//! `compat_api_probes.go`. Each asks one product's API and reads its root
//! page for the product's name; what it finds and how sure it is
//! (`confidence`) are Go's, and so is whether the service answered at all.

use serde_json::{Map, Value};

use super::compat::Match;
use super::health::Prober;
use super::pages::{contains, fetch_body, fetch_json, go_lower, page_contains};
use super::registry::{self, MANAGEMENT, STORAGE};
use super::urls::port_from_url;

/// Go's `compatProbeFn`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    Portainer,
    HomeAssistant,
    TrueNas,
    Pbs,
    Proxmox,
    Docker,
}

impl Probe {
    pub async fn run(self, prober: &dyn Prober, base: &str) -> Match {
        match self {
            Self::Portainer => portainer(prober, base).await,
            Self::HomeAssistant => home_assistant(prober, base).await,
            Self::TrueNas => truenas(prober, base).await,
            Self::Pbs => pbs(prober, base).await,
            Self::Proxmox => proxmox(prober, base).await,
            Self::Docker => docker(prober, base).await,
        }
    }
}

/// Go's `strings.EqualFold`, close enough for the ASCII keys asked for.
fn eq_fold(a: &str, b: &str) -> bool {
    a.chars().count() == b.chars().count()
        && a.chars().zip(b.chars()).all(|(x, y)| {
            x == y || x.to_lowercase().eq(y.to_lowercase()) || x.to_uppercase().eq(y.to_uppercase())
        })
}

/// Go's `mapStringValue`: the first key (in `keys` order) a string value
/// sits under, ignoring case, trimmed.
pub(crate) fn map_string_value(values: &Map<String, Value>, keys: &[&str]) -> String {
    for key in keys {
        for (existing, raw) in values {
            if eq_fold(existing.trim(), key.trim())
                && let Some(text) = raw.as_str()
            {
                return text.trim().to_owned();
            }
        }
    }
    String::new()
}

/// Go's `hasProxmoxVersionShape`: `data` holds a version or a release.
fn proxmox_shape(payload: &Map<String, Value>) -> bool {
    let Some(Value::Object(data)) = payload.get("data") else {
        return false;
    };
    !map_string_value(data, &["version"]).is_empty()
        || !map_string_value(data, &["release"]).is_empty()
}

/// Go's `marshalMapToString` then the lower-cased search for `backup`.
fn names_backup(payload: &Map<String, Value>) -> bool {
    let text = serde_json::to_vec(payload).unwrap_or_default();
    contains(&text, "backup")
}

/// A match naming one of the registry's services, as Go's
/// `LookupByKey` fields.
fn known(key: &str, m: Match) -> Match {
    let Some(known) = registry::by_key(key) else {
        return m;
    };
    Match {
        service_key: known.key,
        display_name: known.name,
        category: known.category,
        icon_key: known.icon_key,
        health_path: known.health_path,
        ..m
    }
}

fn found(connector: &'static str, profile: &'static str, auth_hint: &'static str) -> Match {
    Match {
        connector,
        profile,
        auth_hint,
        responded: true,
        ..Match::default()
    }
}

fn answered(responded: bool) -> Match {
    Match {
        responded,
        ..Match::default()
    }
}

/// Go's `probePortainerAPI`.
async fn portainer(prober: &dyn Prober, base: &str) -> Match {
    let mut responded = false;
    let hit = |profile, evidence, confidence| {
        let m = found("portainer", profile, "api_key,password");
        known(
            "portainer",
            Match {
                evidence,
                confidence,
                ..m
            },
        )
    };
    if let Some((status, payload)) = fetch_json(prober, base, "/api/status").await {
        responded = true;
        if status == 200
            && payload.is_some_and(|p| !map_string_value(&p, &["Version", "version"]).is_empty())
        {
            return hit("portainer.api.status", "api/status version", 0.97);
        }
    }
    match page_contains(prober, base, "/", "portainer").await {
        (true, _) => hit("portainer.ui.marker", "page marker", 0.83),
        (false, marker) => answered(responded || marker),
    }
}

/// Go's `probeHomeAssistantAPI`.
async fn home_assistant(prober: &dyn Prober, base: &str) -> Match {
    let mut responded = false;
    let hit = |profile, evidence, confidence| {
        let m = found("homeassistant", profile, "token");
        known(
            "homeassistant",
            Match {
                evidence,
                confidence,
                ..m
            },
        )
    };
    if let Some((status, payload)) = fetch_json(prober, base, "/api").await {
        responded = true;
        let running = |p: Map<String, Value>| {
            go_lower(map_string_value(&p, &["message"]).as_bytes()).contains("api running")
        };
        if status == 200 && payload.is_some_and(running) {
            return hit("homeassistant.api.root", "api running message", 0.97);
        }
    }
    match page_contains(prober, base, "/", "home assistant").await {
        (true, _) => hit("homeassistant.ui.marker", "page marker", 0.82),
        (false, marker) => answered(responded || marker),
    }
}

/// A TrueNAS, Proxmox Backup Server, Proxmox VE or Docker match: Go names
/// these with fixed words, not from the registry.
fn named(
    connector: &'static str,
    profile: &'static str,
    auth_hint: &'static str,
    evidence: &'static str,
    confidence: f64,
    (display_name, category): (&'static str, &'static str),
) -> Match {
    Match {
        evidence,
        confidence,
        display_name,
        category,
        ..found(connector, profile, auth_hint)
    }
}

const TRUENAS: (&str, &str) = ("TrueNAS", STORAGE);
const PBS: (&str, &str) = ("Proxmox Backup Server", STORAGE);
const PVE: (&str, &str) = ("Proxmox VE", MANAGEMENT);
const DOCKER: (&str, &str) = ("Docker Engine API", MANAGEMENT);

/// Go's `probeTrueNASAPI`.
async fn truenas(prober: &dyn Prober, base: &str) -> Match {
    let mut responded = false;
    if let Some(answer) = fetch_body(prober, base, "/api/v2.0/system/version").await {
        responded = true;
        let lower = go_lower(&answer.body);
        if answer.status == 200 && (lower.contains("truenas") || lower.contains("freenas")) {
            let profile = "truenas.api.system.version";
            let evidence = "api/v2.0/system/version";
            return named("truenas", profile, "api_key", evidence, 0.97, TRUENAS);
        }
    }
    match page_contains(prober, base, "/", "truenas").await {
        (true, _) => named(
            "truenas",
            "truenas.ui.marker",
            "api_key",
            "page marker",
            0.82,
            TRUENAS,
        ),
        (false, marker) => answered(responded || marker),
    }
}

/// Go's `probePBSAPI`: the page first, then the version API.
async fn pbs(prober: &dyn Prober, base: &str) -> Match {
    let (marker, mut responded) = page_contains(prober, base, "/", "proxmox backup server").await;
    if marker {
        return named(
            "pbs",
            "pbs.ui.marker",
            "api_token",
            "page marker",
            0.96,
            PBS,
        );
    }
    if let Some((status, payload)) = fetch_json(prober, base, "/api2/json/version").await {
        responded = true;
        if status == 200 && payload.is_some_and(|p| proxmox_shape(&p) && names_backup(&p)) {
            let evidence = "api2 version payload";
            return named("pbs", "pbs.api2.version", "api_token", evidence, 0.88, PBS);
        }
    }
    answered(responded)
}

/// Go's `probeProxmoxAPI`: the page first, then a version API that does
/// not name a backup server.
async fn proxmox(prober: &dyn Prober, base: &str) -> Match {
    let marker = "proxmox virtual environment";
    let (marker, mut responded) = page_contains(prober, base, "/", marker).await;
    let auth = "api_token,password";
    if marker {
        return named(
            "proxmox",
            "proxmox.ui.marker",
            auth,
            "page marker",
            0.96,
            PVE,
        );
    }
    if let Some((status, payload)) = fetch_json(prober, base, "/api2/json/version").await {
        responded = true;
        if status == 200 && payload.is_some_and(|p| proxmox_shape(&p) && !names_backup(&p)) {
            let evidence = "api2 version payload";
            return named("proxmox", "proxmox.api2.version", auth, evidence, 0.74, PVE);
        }
    }
    answered(responded)
}

/// Go's `probeDockerEngineAPI`: `/version`, then `/_ping` on the Docker
/// API's own ports.
async fn docker(prober: &dyn Prober, base: &str) -> Match {
    let mut responded = false;
    if let Some((status, payload)) = fetch_json(prober, base, "/version").await {
        responded = true;
        let engine = |p: Map<String, Value>| {
            !map_string_value(&p, &["ApiVersion"]).is_empty()
                && !map_string_value(&p, &["Version"]).is_empty()
        };
        if status == 200 && payload.is_some_and(engine) {
            let evidence = "docker /version payload";
            return named(
                "docker",
                "docker.api.version",
                "none_or_mtls",
                evidence,
                0.96,
                DOCKER,
            );
        }
    }
    if matches!(port_from_url(base), 2375 | 2376)
        && let Some(answer) = fetch_body(prober, base, "/_ping").await
    {
        responded = true;
        if answer.status == 200 && contains(&answer.body, "ok") {
            let profile = "docker.api.ping";
            return named(
                "docker",
                profile,
                "none_or_mtls",
                "docker /_ping",
                0.86,
                DOCKER,
            );
        }
    }
    answered(responded)
}
