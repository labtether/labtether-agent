//! Naming services the registry does not know: Go's
//! `applyFingerprintMetadata` and its probes (`fingerprinting.go`). A
//! service without a service key is asked whether it is LabTether, then
//! its root page is read for a product's name (and `/ui/` after a
//! redirect), then the TrueNAS, Synology and QNAP APIs; when its URL
//! gives no answer at all, the other scheme is tried. A name found is
//! kept for 15 minutes per base URL, none for 5. Every service then goes
//! through the connector probes (`compat.rs`). The probes run one after
//! another, service by service, before the health checks.

use std::time::{Duration, SystemTime};

use labtether_protocol::DiscoveredWebService;

use super::cache::Expiring;
use super::compat::{self, Match};
use super::health::{Prober, base_url};
use super::labtether::is_labtether_service;
use super::pages::{fetch_body, fetch_json, go_lower};
use super::registry::{self, KnownService};
use super::urls::alternate_scheme_url;

/// Go's `fingerprintCacheHitTTL` and `fingerprintCacheMissTTL`.
pub(crate) const HIT_TTL: Duration = Duration::from_secs(15 * 60);
pub(crate) const MISS_TTL: Duration = Duration::from_secs(5 * 60);

/// Go's `htmlFingerprints`, in its order: the first marker found on the
/// page names the service (the backup server before Proxmox VE).
const HTML_MARKERS: [(&str, &[&str]); 11] = [
    ("truenas", &["truenas"]),
    ("synology", &["synology", "diskstation"]),
    ("qnap", &["qnap"]),
    ("proxmox-backup", &["proxmox backup server"]),
    ("proxmox", &["proxmox virtual environment", "pve manager"]),
    ("pfsense", &["pfsense"]),
    ("opnsense", &["opnsense"]),
    ("homeassistant", &["home-assistant"]),
    ("pihole", &["pi-hole"]),
    ("unifi", &["unifi network", "ubiquiti"]),
    ("cockpit", &["/cockpit/", "cockpit-ws"]),
];

/// Go's `matchHTMLFingerprint`.
pub(crate) fn match_html(body: &[u8]) -> Option<&'static str> {
    let lower = go_lower(body);
    HTML_MARKERS
        .iter()
        .find(|(_, markers)| markers.iter().any(|m| lower.contains(m)))
        .map(|(key, _)| *key)
}

/// Go's `fingerprintByAPIWithResponse`: the TrueNAS, Synology and QNAP
/// APIs.
async fn by_api(prober: &dyn Prober, base: &str) -> (Option<&'static str>, bool) {
    let mut responded = false;
    if let Some(answer) = fetch_body(prober, base, "/api/v2.0/system/version").await {
        responded = true;
        let lower = go_lower(&answer.body);
        if answer.status < 500 && (lower.contains("truenas") || lower.contains("freenas")) {
            return (Some("truenas"), true);
        }
    }
    let synology = "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query";
    if let Some((status, payload)) = fetch_json(prober, base, synology).await {
        responded = true;
        if status == 200 && payload.is_some_and(|p| p.contains_key("data")) {
            return (Some("synology"), true);
        }
    }
    if let Some(answer) = fetch_body(prober, base, "/cgi-bin/authLogin.cgi").await
        && answer.status < 500
    {
        responded = true;
        let lower = go_lower(&answer.body);
        if lower.contains("qnap") || lower.contains("authsid") {
            return (Some("qnap"), true);
        }
    }
    (None, responded)
}

/// Go's `fingerprintByHTTPWithResponse`: the key found, and whether the
/// root page answered (when it did not, nothing else is asked).
async fn by_http(prober: &dyn Prober, base: &str) -> (Option<&'static str>, bool) {
    let Some(root) = fetch_body(prober, base, "/").await else {
        return (None, false);
    };
    if root.status < 500
        && let Some(key) = match_html(&root.body)
    {
        return (Some(key), true);
    }
    if (300..400).contains(&root.status)
        && let Some(ui) = fetch_body(prober, base, "/ui/").await
        && ui.status < 500
        && let Some(key) = match_html(&ui.body)
    {
        return (Some(key), true);
    }
    (by_api(prober, base).await.0, true)
}

/// Go's `fingerprintKnownService`.
async fn known_service(prober: &dyn Prober, base: &str) -> Option<&'static KnownService> {
    if is_labtether_service(prober, base).await
        && let Some(known) = registry::by_key("labtether")
    {
        return Some(known);
    }
    match by_http(prober, base).await {
        (Some(key), _) => registry::by_key(key),
        (None, true) => None,
        (None, false) => {
            let alternate = alternate_scheme_url(base);
            if alternate.is_empty() || base.eq_ignore_ascii_case(&alternate) {
                return None;
            }
            by_http(prober, &alternate)
                .await
                .0
                .and_then(registry::by_key)
        }
    }
}

/// The recognition probes' results kept between cycles.
#[derive(Debug, Default)]
pub(crate) struct Recognizer {
    names: Expiring<Option<&'static KnownService>>,
    compat: Expiring<Match>,
}

impl Recognizer {
    /// Go's `applyFingerprintMetadata` for each service in turn; `clock`
    /// is read as Go's `wsc.now()` is, at each cache look-up.
    pub async fn apply(
        &mut self,
        prober: &dyn Prober,
        services: &mut [DiscoveredWebService],
        clock: &dyn Fn() -> SystemTime,
    ) {
        for svc in services.iter_mut() {
            if !matches!(svc.source.as_str(), "scan" | "proxy" | "docker") {
                continue;
            }
            let base = base_url(svc);
            if base.is_empty() {
                continue;
            }
            if svc.service_key.trim().is_empty()
                && let Some(known) = self.name(prober, &base, clock()).await
            {
                svc.service_key = known.key.to_owned();
                svc.name = known.name.to_owned();
                svc.category = known.category.to_owned();
                svc.icon_key = known.icon_key.to_owned();
                let unset = svc
                    .metadata
                    .get("health_path")
                    .is_none_or(|p| p.trim().is_empty());
                if !known.health_path.is_empty() && unset {
                    svc.metadata
                        .insert("health_path".into(), known.health_path.into());
                }
            }
            compat::apply_compatibility(&mut self.compat, prober, svc, &base, clock()).await;
        }
    }

    /// Go's `cachedFingerprintKnownService`.
    async fn name(
        &mut self,
        prober: &dyn Prober,
        base: &str,
        now: SystemTime,
    ) -> Option<&'static KnownService> {
        let key = base.trim().to_lowercase();
        if key.is_empty() {
            return None;
        }
        if let Some(kept) = self.names.get(&key, now) {
            return kept;
        }
        let found = known_service(prober, base).await;
        let ttl = if found.is_some() { HIT_TTL } else { MISS_TTL };
        self.names.put(key, found, now + ttl, now);
        found
    }
}
