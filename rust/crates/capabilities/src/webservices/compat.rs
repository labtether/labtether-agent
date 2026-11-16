//! Which of the Hub's connectors a service could use: Go's `compat.go`.
//! Portainer and Home Assistant known by their service key need no probe;
//! any other service is asked by the API probes in an order set by its
//! port, stopping at a sure match (0.97); when nothing answered, the other
//! scheme is tried too. A match of at least 0.60 goes into the service's
//! `compat_*` metadata (the Hub's connector suggestions read it) and may
//! name a service that has no better name. Results are kept per base URL,
//! a match for 10 minutes and none for 3.

use std::time::{Duration, SystemTime};

use labtether_protocol::DiscoveredWebService;

use super::compat_probes::Probe::{self, Docker, HomeAssistant, Pbs, Portainer, Proxmox, TrueNas};
use super::health::Prober;
use super::registry::{self, OTHER};
use super::urls::{alternate_scheme_url, parse_port, port_from_url};

/// Go's `compatMinConfidence`, `compatCacheHitTTL` and `compatCacheMissTTL`.
pub(crate) const MIN_CONFIDENCE: f64 = 0.60;
pub(crate) const HIT_TTL: Duration = Duration::from_secs(10 * 60);
pub(crate) const MISS_TTL: Duration = Duration::from_secs(3 * 60);
/// A match this sure ends the probing.
const SURE: f64 = 0.97;

/// Go's `compatMatch`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Match {
    pub connector: &'static str,
    pub profile: &'static str,
    pub auth_hint: &'static str,
    pub evidence: &'static str,
    pub confidence: f64,
    pub responded: bool,
    pub service_key: &'static str,
    pub display_name: &'static str,
    pub category: &'static str,
    pub icon_key: &'static str,
    pub health_path: &'static str,
}

/// Go's `matchCompatibilityFromServiceKey`.
pub(crate) fn from_service_key(service_key: &str) -> Match {
    let (connector, auth_hint) = match service_key.trim().to_lowercase().as_str() {
        "portainer" => ("portainer", "api_key,password"),
        "homeassistant" => ("homeassistant", "token"),
        _ => return Match::default(),
    };
    let known = registry::by_key(connector);
    Match {
        connector,
        profile: if connector == "portainer" {
            "service-key.portainer"
        } else {
            "service-key.homeassistant"
        },
        auth_hint,
        evidence: "known service key",
        confidence: 0.92,
        responded: false,
        service_key: known.map_or("", |k| k.key),
        display_name: known.map_or("", |k| k.name),
        category: known.map_or("", |k| k.category),
        icon_key: known.map_or("", |k| k.icon_key),
        health_path: known.map_or("", |k| k.health_path),
    }
}

/// Go's `compatibilityProbeOrder`.
fn probe_order(port: u16) -> [Probe; 6] {
    match port {
        8123 => [HomeAssistant, Portainer, TrueNas, Pbs, Proxmox, Docker],
        9443 | 9000 => [Portainer, HomeAssistant, TrueNas, Pbs, Proxmox, Docker],
        8006 => [Proxmox, Pbs, Portainer, TrueNas, HomeAssistant, Docker],
        8007 => [Pbs, Proxmox, Portainer, TrueNas, HomeAssistant, Docker],
        2375 | 2376 => [Docker, Portainer, HomeAssistant, TrueNas, Pbs, Proxmox],
        _ => [Portainer, HomeAssistant, TrueNas, Pbs, Proxmox, Docker],
    }
}

/// Go's `detectCompatibleAPIAtBase`: the best match, and whether any
/// probe got an answer.
async fn at_base(prober: &dyn Prober, base: &str, order: &[Probe]) -> (Match, bool) {
    let mut best = Match::default();
    let mut responded = false;
    for probe in order {
        let found = probe.run(prober, base).await;
        responded |= found.responded;
        if found.confidence > best.confidence {
            best = found;
            if best.confidence >= SURE {
                break;
            }
        }
    }
    (best, responded)
}

/// Go's `detectCompatibleAPI`.
pub(crate) async fn detect(prober: &dyn Prober, base: &str) -> Match {
    let trimmed = base.trim();
    if trimmed.is_empty() {
        return Match::default();
    }
    let order = probe_order(port_from_url(trimmed));
    let (best, responded) = at_base(prober, trimmed, &order).await;
    if best.confidence >= SURE || responded {
        return best;
    }
    let alternate = alternate_scheme_url(trimmed);
    if alternate.is_empty() || trimmed.eq_ignore_ascii_case(&alternate) {
        return best;
    }
    let (other, _) = at_base(prober, &alternate, &order).await;
    if other.confidence > best.confidence {
        other
    } else {
        best
    }
}

/// Go's `isGenericPortServiceName`: "Port 8080" and the like.
fn is_generic_port_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower
        .trim()
        .strip_prefix("port ")
        .is_some_and(|port| parse_port(port).is_some())
}

/// Go's `applyCompatMatchToService`.
pub(crate) fn apply(svc: &mut DiscoveredWebService, m: &Match) {
    if m.confidence < MIN_CONFIDENCE || m.connector.trim().is_empty() {
        return;
    }
    let meta = &mut svc.metadata;
    meta.insert("compat_connector".into(), m.connector.trim().into());
    meta.insert("compat_confidence".into(), format!("{:.2}", m.confidence));
    for (key, value) in [
        ("compat_auth_hint", m.auth_hint),
        ("compat_profile", m.profile),
        ("compat_evidence", m.evidence),
    ] {
        if !value.trim().is_empty() {
            meta.insert(key.into(), value.trim().into());
        }
    }
    if svc.service_key.trim().is_empty() && !m.service_key.trim().is_empty() {
        svc.service_key = m.service_key.trim().into();
    }
    let generic = svc.name.trim().is_empty() || is_generic_port_name(&svc.name);
    if !m.display_name.trim().is_empty() && generic {
        svc.name = m.display_name.trim().into();
    }
    let other = svc.category.trim().is_empty() || svc.category.trim().eq_ignore_ascii_case(OTHER);
    if !m.category.trim().is_empty() && other {
        svc.category = m.category.trim().into();
    }
    if !m.icon_key.trim().is_empty() && svc.icon_key.trim().is_empty() {
        svc.icon_key = m.icon_key.trim().into();
    }
    let health_path = svc.metadata.get("health_path").map_or("", |p| p.trim());
    if !m.health_path.trim().is_empty() && health_path.is_empty() {
        svc.metadata
            .insert("health_path".into(), m.health_path.trim().into());
    }
}

/// Go's `applyCompatibilityMetadata` with its cache, kept by the caller.
pub(crate) async fn apply_compatibility(
    cache: &mut super::cache::Expiring<Match>,
    prober: &dyn Prober,
    svc: &mut DiscoveredWebService,
    base: &str,
    now: SystemTime,
) {
    if svc.source == "manual" {
        return;
    }
    let mut key = base.trim().to_lowercase();
    if key.is_empty() {
        key = svc.url.trim().to_lowercase();
    }
    if key.is_empty() {
        return;
    }
    if let Some(cached) = cache.get(&key, now) {
        apply(svc, &cached);
        return;
    }
    let mut found = from_service_key(&svc.service_key);
    if found.confidence < MIN_CONFIDENCE {
        found = detect(prober, base).await;
    }
    if found.confidence >= MIN_CONFIDENCE {
        cache.put(key, found, now + HIT_TTL, now);
        apply(svc, &found);
    } else {
        cache.put(key, Match::default(), now + MISS_TTL, now);
    }
}
