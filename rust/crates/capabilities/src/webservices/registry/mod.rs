//! The known web services, as the Go agent's registry
//! (`internal/agentcore/webservice/registry*.go`): one file per category
//! holds its services, and the lookups by Docker image and by a name or
//! domain hint work from indexes built once, in Go's order (keys sorted;
//! the first key wins a shared image or hint). Go's descriptions are left
//! out: nothing reads them. The port indexes (`LookupByPort`,
//! `LookupUniqueByPort`) come with the parts that read them (the port
//! scan and the proxy routes).

mod databases;
mod development;
mod downloads;
mod gaming;
mod hints;
mod home_automation;
mod management;
mod media;
mod monitoring;
mod networking;
mod productivity;
mod security;
mod storage;

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

pub(crate) use hints::normalize_docker_image;
use hints::{BASELINE_ALIASES, hint_candidates, normalize_service_hint};

/// Go's `Cat*` category names.
pub(crate) const MEDIA: &str = "Media";
pub(crate) const DOWNLOADS: &str = "Downloads";
pub(crate) const GAMING: &str = "Gaming";
pub(crate) const NETWORKING: &str = "Networking";
pub(crate) const MONITORING: &str = "Monitoring";
pub(crate) const DEVELOPMENT: &str = "Development";
pub(crate) const HOME_AUTOMATION: &str = "Home Automation";
pub(crate) const STORAGE: &str = "Storage";
pub(crate) const DATABASES: &str = "Databases";
pub(crate) const SECURITY: &str = "Security";
pub(crate) const PRODUCTIVITY: &str = "Productivity";
pub(crate) const MANAGEMENT: &str = "Management";
pub(crate) const OTHER: &str = "Other";

/// Go's `KnownService`, without the description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KnownService {
    pub key: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub icon_key: &'static str,
    pub default_port: u16,
    pub health_path: &'static str,
    pub docker_images: &'static [&'static str],
}

/// Go's category maps, in Go's `buildServiceRegistry` order.
const CATEGORIES: [&[KnownService]; 12] = [
    media::SERVICES,
    downloads::SERVICES,
    gaming::SERVICES,
    networking::SERVICES,
    monitoring::SERVICES,
    management::SERVICES,
    home_automation::SERVICES,
    storage::SERVICES,
    security::SERVICES,
    databases::SERVICES,
    development::SERVICES,
    productivity::SERVICES,
];

struct Registry {
    services: BTreeMap<&'static str, &'static KnownService>,
    images: HashMap<String, &'static str>,
    hints: HashMap<String, &'static str>,
}

impl Registry {
    /// Go's `buildServiceRegistry`, `buildRegistryIndexes` and
    /// `registerBaselineHintAliases`.
    fn build() -> Self {
        let mut services = BTreeMap::new();
        for service in CATEGORIES.iter().flat_map(|category| category.iter()) {
            assert!(
                services.insert(service.key, service).is_none(),
                "duplicate known service: {}",
                service.key
            );
        }
        let mut registry = Self {
            services,
            images: HashMap::new(),
            hints: HashMap::new(),
        };
        let all: Vec<&'static KnownService> = registry.services.values().copied().collect();
        for service in all {
            let key = service.key;
            for image in service.docker_images {
                let normalized = normalize_docker_image(image);
                if !normalized.is_empty() {
                    registry.images.entry(normalized).or_insert(key);
                }
            }
            registry.add_hint(key, key);
            registry.add_hint(key, service.name);
            registry.add_hint(key, service.icon_key);
            for image in service.docker_images {
                let normalized = normalize_docker_image(image);
                registry.add_hint(key, &normalized);
                if let Some(slash) = normalized.rfind('/')
                    && slash + 1 < normalized.len()
                {
                    registry.add_hint(key, &normalized[slash + 1..]);
                }
            }
        }
        for (key, alias) in BASELINE_ALIASES {
            registry.add_hint(key, alias);
        }
        registry
    }

    /// Go's `addHintAlias`: the first key for a hint stays.
    fn add_hint(&mut self, key: &'static str, raw: &str) {
        let normalized = normalize_service_hint(raw);
        if !normalized.is_empty() {
            self.hints.entry(normalized).or_insert(key);
        }
    }

    fn get(&self, key: &str) -> Option<&'static KnownService> {
        self.services.get(key).copied()
    }
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::build);

/// Go's `LookupByDockerImage`: the image without tag, digest or registry.
pub(crate) fn by_docker_image(image: &str) -> Option<&'static KnownService> {
    let normalized = normalize_docker_image(image);
    if normalized.is_empty() {
        return None;
    }
    REGISTRY
        .images
        .get(&normalized)
        .and_then(|key| REGISTRY.get(key))
}

/// Go's `LookupByHint`: a name, domain, URL or container name, tried whole
/// and in parts.
pub(crate) fn by_hint(hint: &str) -> Option<&'static KnownService> {
    let mut seen = Vec::new();
    for candidate in hint_candidates(hint) {
        let normalized = normalize_service_hint(candidate);
        if normalized.is_empty() || seen.contains(&normalized) {
            continue;
        }
        if let Some(key) = REGISTRY.hints.get(&normalized) {
            return REGISTRY.get(key);
        }
        seen.push(normalized);
    }
    None
}

/// Go's `LookupByKey`.
pub(crate) fn by_key(key: &str) -> Option<&'static KnownService> {
    REGISTRY.get(key)
}

/// Every known service, sorted by key.
#[cfg(test)]
pub(crate) fn all() -> impl Iterator<Item = &'static KnownService> {
    REGISTRY.services.values().copied()
}
