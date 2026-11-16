//! The inventory as the Hub gets it, from the engine's answers: Go's
//! `collector_inventory.go`. Each kind is kept by ID (volumes by name);
//! the lists sent are sorted as Go sorts them. Two inventories are equal
//! when every field is, as Go's `dockerInventorySnapshotsEqual`; Compose
//! stacks compare by name, in any order.

use std::collections::{BTreeMap, BTreeSet};

use labtether_agent_platform::gotime::rfc3339;
use labtether_protocol::{
    DockerComposeStack, DockerContainerInfo, DockerEngineInfo, DockerImageInfo, DockerMountInfo,
    DockerNetworkInfo, DockerPortMapping, DockerVolumeInfo,
};

use super::raw;

/// Go's `maxContainersPerHost`: past this many, the rest are left out and
/// every Compose stack is marked `incomplete_inventory`.
pub(crate) const MAX_CONTAINERS: usize = 500;

/// What the Hub was last sent: Go's `dockerInventorySnapshot`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Snapshot {
    pub engine: DockerEngineInfo,
    pub containers: BTreeMap<String, DockerContainerInfo>,
    pub images: BTreeMap<String, DockerImageInfo>,
    pub networks: BTreeMap<String, DockerNetworkInfo>,
    pub volumes: BTreeMap<String, DockerVolumeInfo>,
    pub compose: Vec<DockerComposeStack>,
}

impl Snapshot {
    /// Go's `dockerInventorySnapshotsEqual`.
    pub fn same_as(&self, other: &Self) -> bool {
        self.engine == other.engine
            && self.containers == other.containers
            && self.images == other.images
            && self.networks == other.networks
            && self.volumes == other.volumes
            && compose_equal(&self.compose, &other.compose)
    }
}

/// The containers past the limit are dropped, in the engine's order.
pub(crate) fn cap_containers(rows: &mut Vec<raw::Container>) -> bool {
    let incomplete = rows.len() > MAX_CONTAINERS;
    rows.truncate(MAX_CONTAINERS);
    incomplete
}

/// Go's `ContainerName`: the first name without one leading `/`.
pub(crate) fn container_name(names: &[String]) -> String {
    names
        .first()
        .map(|name| name.strip_prefix('/').unwrap_or(name).to_owned())
        .unwrap_or_default()
}

/// Go's `buildContainerInfoMap`: the containers by ID, and the IDs of
/// those running.
pub(crate) fn containers(
    rows: &[raw::Container],
) -> (BTreeMap<String, DockerContainerInfo>, BTreeSet<String>) {
    let mut by_id = BTreeMap::new();
    let mut running = BTreeSet::new();
    for row in rows {
        if row.state == "running" {
            running.insert(row.id.clone());
        }
        let mut ports: Vec<DockerPortMapping> = row
            .ports
            .iter()
            .filter(|port| port.public_port > 0)
            .map(|port| DockerPortMapping {
                host: port.public_port,
                container: port.private_port,
                protocol: port.r#type.to_lowercase(),
            })
            .collect();
        ports.sort_by(|a, b| {
            (a.host, a.container, &a.protocol).cmp(&(b.host, b.container, &b.protocol))
        });
        let mut mounts: Vec<DockerMountInfo> = row
            .mounts
            .iter()
            .map(|mount| DockerMountInfo {
                r#type: mount.r#type.clone(),
                source: mount.source.clone(),
                destination: mount.destination.clone(),
            })
            .collect();
        mounts.sort_by(|a, b| {
            (&a.destination, &a.source, &a.r#type).cmp(&(&b.destination, &b.source, &b.r#type))
        });
        let info = DockerContainerInfo {
            id: row.id.clone(),
            name: container_name(&row.names),
            image: row.image.clone(),
            state: row.state.clone(),
            status: row.status.clone(),
            created: rfc3339(row.created, 0),
            ports,
            networks: row.network_settings.networks.keys().cloned().collect(),
            labels: row.labels.clone(),
            mounts,
        };
        by_id.insert(row.id.clone(), info);
    }
    (by_id, running)
}

/// Go's `containerInfoMapToSlice`: by name, then ID.
pub(crate) fn container_list(
    by_id: &BTreeMap<String, DockerContainerInfo>,
) -> Vec<DockerContainerInfo> {
    let mut list: Vec<DockerContainerInfo> = by_id.values().cloned().collect();
    list.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    list
}

/// Go's `buildImageInfoMap`; tags sorted.
pub(crate) fn images(rows: &[raw::Image]) -> BTreeMap<String, DockerImageInfo> {
    rows.iter()
        .map(|row| {
            let mut tags = row.repo_tags.clone();
            tags.sort();
            let info = DockerImageInfo {
                id: row.id.clone(),
                tags,
                size: row.size,
                created: rfc3339(row.created, 0),
            };
            (row.id.clone(), info)
        })
        .collect()
}

/// Go's `buildNetworkInfoMap`.
pub(crate) fn networks(rows: &[raw::Network]) -> BTreeMap<String, DockerNetworkInfo> {
    rows.iter()
        .map(|row| {
            let info = DockerNetworkInfo {
                id: row.id.clone(),
                name: row.name.clone(),
                driver: row.driver.clone(),
                scope: row.scope.clone(),
            };
            (row.id.clone(), info)
        })
        .collect()
}

/// Go's `networkInfoMapToSlice`: by name, then ID.
pub(crate) fn network_list(by_id: &BTreeMap<String, DockerNetworkInfo>) -> Vec<DockerNetworkInfo> {
    let mut list: Vec<DockerNetworkInfo> = by_id.values().cloned().collect();
    list.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    list
}

/// Go's `buildVolumeInfoMap`, by name.
pub(crate) fn volumes(rows: &[raw::Volume]) -> BTreeMap<String, DockerVolumeInfo> {
    rows.iter()
        .map(|row| {
            let info = DockerVolumeInfo {
                name: row.name.clone(),
                driver: row.driver.clone(),
                mountpoint: row.mountpoint.clone(),
            };
            (row.name.clone(), info)
        })
        .collect()
}

/// Go's `diffContainerInfoMap`: new or changed containers sorted by name
/// then ID, and the IDs gone, sorted.
pub(crate) fn diff_containers(
    previous: &BTreeMap<String, DockerContainerInfo>,
    next: &BTreeMap<String, DockerContainerInfo>,
) -> (Vec<DockerContainerInfo>, Vec<String>) {
    let mut upserts: Vec<DockerContainerInfo> = next
        .iter()
        .filter(|(id, info)| previous.get(*id) != Some(*info))
        .map(|(_, info)| info.clone())
        .collect();
    upserts.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    let removals = previous
        .keys()
        .filter(|id| !next.contains_key(*id))
        .cloned()
        .collect();
    (upserts, removals)
}

/// Go's `composeStacksEqual`: the same count, and each stack of `b` found
/// by name in `a` with the same fields.
pub(crate) fn compose_equal(a: &[DockerComposeStack], b: &[DockerComposeStack]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let left: BTreeMap<&str, &DockerComposeStack> =
        a.iter().map(|stack| (stack.name.as_str(), stack)).collect();
    b.iter().all(|stack| {
        left.get(stack.name.as_str()).is_some_and(|other| {
            other.status == stack.status
                && other.config_file == stack.config_file
                && other.config_dir == stack.config_dir
                && other.selection_error == stack.selection_error
                && other.config_files == stack.config_files
                && other.containers == stack.containers
        })
    })
}

/// Go's `shouldFallbackToFull`: a full inventory is sent instead of a delta
/// when 200 or more containers changed, when more than half did, or when
/// the Compose stacks changed along with more than 100 containers.
pub(crate) fn full_instead_of_delta(
    changes: usize,
    previous: usize,
    compose_changed: bool,
) -> bool {
    changes >= 200
        || (previous != 0 && (changes * 2 > previous || (compose_changed && changes > 100)))
}
