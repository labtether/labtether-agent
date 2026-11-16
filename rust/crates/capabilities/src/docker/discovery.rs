//! `docker.discovery` and `docker.discovery.delta`: Go's
//! `refreshAndPublishFull` and `refreshAndPublishContainerDelta`
//! (`collector.go`).
//!
//! A full inventory (engine, containers, images, networks, volumes,
//! Compose stacks) goes out when none was sent on this connection, when
//! the agent's asset ID changed, when it differs from the last one sent,
//! or when the caller forces it (at start and every full-reconcile
//! period). A delta carries only the containers added, changed or gone,
//! and the Compose stacks when they changed; it falls back to a full
//! inventory when too much changed (see
//! [`super::inventory::full_instead_of_delta`]) or when a new connection
//! opened while the round read the engine. Nothing is read or sent
//! while no connection is open. A message that fails to send leaves the
//! last-sent state as it was, so the next round sends again.
//!
//! The discovery does not say it handles Compose actions: Go's
//! `compose_action_version` and `compose_endpoint_id` are left out, since
//! this agent answers no request that changes anything.

use std::collections::BTreeSet;
use std::sync::Mutex;

use labtether_agent_core::HubSender;
use labtether_protocol::{
    DockerComposeStack, DockerDiscoveryData, DockerDiscoveryDeltaData, DockerEngineInfo,
    MSG_DOCKER_DISCOVERY, MSG_DOCKER_DISCOVERY_DELTA, Message,
};
use serde::Serialize;

use super::compose;
use super::compose_memory::ComposeMemory;
use super::engine::{self, EngineApi, EngineError};
use super::inventory::{self, Snapshot};
use super::raw;
use super::stats::Running;

/// Why a round sent nothing it should have.
#[derive(Debug)]
pub(crate) enum RoundError {
    Engine(&'static str, EngineError),
    Send(String),
}

impl std::fmt::Display for RoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Engine(what, error) => write!(f, "{what}: {error}"),
            Self::Send(error) => f.write_str(error),
        }
    }
}

#[derive(Debug, Default)]
struct Published {
    snapshot: Snapshot,
    running: Running,
    /// Go's `hasPublishedFull` and `lastPublishedAssetID`, for the
    /// connection numbered `connection`.
    has_full: bool,
    asset_id: String,
    connection: u64,
}

/// The inventory state shared by the discovery, stats and event threads.
#[derive(Debug)]
pub(crate) struct Inventory {
    published: Mutex<Published>,
    memory: Mutex<ComposeMemory>,
}

fn send(sender: &dyn HubSender, kind: &str, payload: &impl Serialize) -> Result<(), RoundError> {
    let message =
        Message::with_data(kind, "", payload).map_err(|e| RoundError::Send(e.to_string()))?;
    sender
        .send(&message)
        .map_err(|e| RoundError::Send(e.to_string()))
}

impl Inventory {
    pub fn new(memory: ComposeMemory) -> Self {
        Self {
            published: Mutex::new(Published::default()),
            memory: Mutex::new(memory),
        }
    }

    fn published(&self) -> std::sync::MutexGuard<'_, Published> {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The running containers as last read, for the stats sampler.
    pub fn running(&self) -> Running {
        self.published().running.clone()
    }

    fn set_running(&self, ids: BTreeSet<String>) {
        let running = Running::new(ids);
        let mut published = self.published();
        if published.running != running {
            published.running = running;
        }
    }

    /// Go's `ResetPublishedState`, run by Go's reconnect callback: on a new
    /// connection the next round sends a full inventory. Returns the
    /// connection's number.
    fn note_connection(&self, sender: &dyn HubSender) -> u64 {
        let current = sender.connection();
        let mut published = self.published();
        if published.connection != current {
            published.connection = current;
            published.has_full = false;
            published.asset_id.clear();
        }
        current
    }

    /// Go's `composeStacks`: the live stacks merged with the memory.
    fn compose(&self, rows: &[raw::Container], incomplete: bool) -> Vec<DockerComposeStack> {
        let live = compose::infer(rows, incomplete);
        self.memory
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .merge(live, incomplete)
    }

    /// Go's `collectFullDiscovery`: the engine and the container list must
    /// be read; images, networks and volumes are left empty when not.
    fn collect(
        &self,
        api: &dyn EngineApi,
        host_id: &str,
    ) -> Result<(DockerDiscoveryData, Snapshot, BTreeSet<String>), RoundError> {
        let version = engine::version(api).map_err(|e| RoundError::Engine("version", e))?;
        let engine = DockerEngineInfo {
            version: version.version,
            api_version: version.api_version,
            os: version.os,
            arch: version.arch,
        };
        let mut rows = engine::containers(api).map_err(|e| RoundError::Engine("containers", e))?;
        let incomplete = inventory::cap_containers(&mut rows);
        let (containers, running) = inventory::containers(&rows);
        let mut snapshot = Snapshot {
            engine: engine.clone(),
            compose: self.compose(&rows, incomplete),
            containers,
            ..Snapshot::default()
        };
        let mut data = DockerDiscoveryData {
            host_id: host_id.to_owned(),
            engine,
            containers: inventory::container_list(&snapshot.containers),
            compose_stacks: snapshot.compose.clone(),
            ..DockerDiscoveryData::default()
        };
        if let Ok(rows) = engine::images(api) {
            snapshot.images = inventory::images(&rows);
            data.images = snapshot.images.values().cloned().collect();
        }
        if let Ok(rows) = engine::networks(api) {
            snapshot.networks = inventory::networks(&rows);
            data.networks = inventory::network_list(&snapshot.networks);
        }
        if let Ok(rows) = engine::volumes(api) {
            snapshot.volumes = inventory::volumes(&rows);
            data.volumes = snapshot.volumes.values().cloned().collect();
        }
        Ok((data, snapshot, running))
    }

    /// Go's `refreshAndPublishFull`: true when a full inventory was sent.
    pub fn refresh_full(
        &self,
        api: &dyn EngineApi,
        sender: &dyn HubSender,
        force: bool,
    ) -> Result<bool, RoundError> {
        if !sender.connected() {
            return Ok(false);
        }
        self.note_connection(sender);
        let host_id = sender.asset_id().trim().to_owned();
        let (data, snapshot, running) = self.collect(api, &host_id)?;
        let (unchanged, has_full) = {
            let published = self.published();
            let identity_changed = !published.asset_id.is_empty() && published.asset_id != host_id;
            (
                !identity_changed && published.snapshot.same_as(&snapshot),
                published.has_full,
            )
        };
        if unchanged && !force && has_full {
            self.set_running(running);
            return Ok(false);
        }
        if let Err(error) = send(sender, MSG_DOCKER_DISCOVERY, &data) {
            self.set_running(running);
            return Err(error);
        }
        self.set_running(running);
        let mut published = self.published();
        published.snapshot = snapshot;
        published.has_full = true;
        published.asset_id = host_id;
        Ok(true)
    }

    /// Go's `refreshAndPublishContainerDelta`: true when something was sent.
    pub fn refresh_delta(
        &self,
        api: &dyn EngineApi,
        sender: &dyn HubSender,
    ) -> Result<bool, RoundError> {
        if !sender.connected() {
            return Ok(false);
        }
        let connection = self.note_connection(sender);
        let host_id = sender.asset_id().trim().to_owned();
        let (has_full, last_asset, previous, previous_compose) = {
            let published = self.published();
            let snapshot = &published.snapshot;
            (
                published.has_full,
                published.asset_id.clone(),
                snapshot.containers.clone(),
                snapshot.compose.clone(),
            )
        };
        if !has_full || (!last_asset.is_empty() && last_asset != host_id) {
            return self.refresh_full(api, sender, true);
        }
        let mut rows = engine::containers(api).map_err(|e| RoundError::Engine("containers", e))?;
        let incomplete = inventory::cap_containers(&mut rows);
        let (next, running) = inventory::containers(&rows);
        let next_compose = self.compose(&rows, incomplete);
        let (upserts, removals) = inventory::diff_containers(&previous, &next);
        let compose_changed = !inventory::compose_equal(&previous_compose, &next_compose);
        let changes = upserts.len() + removals.len();
        if changes == 0 && !compose_changed {
            self.set_running(running);
            return Ok(false);
        }
        if inventory::full_instead_of_delta(changes, previous.len(), compose_changed) {
            return self.refresh_full(api, sender, false);
        }
        let delta = DockerDiscoveryDeltaData {
            host_id,
            upsert_containers: upserts,
            remove_container_ids: removals,
            replace_compose_stacks: compose_changed,
            compose_stacks: if compose_changed {
                next_compose.clone()
            } else {
                Vec::new()
            },
            ..DockerDiscoveryDeltaData::default()
        };
        // A new connection opened while this round read the engine: the
        // delta is against what the old one was sent, so the new one gets
        // a full inventory first, as after Go's reset.
        if sender.connection() != connection {
            return self.refresh_full(api, sender, true);
        }
        if let Err(error) = send(sender, MSG_DOCKER_DISCOVERY_DELTA, &delta) {
            self.set_running(running);
            return Err(error);
        }
        self.set_running(running);
        let mut published = self.published();
        published.snapshot.containers = next;
        published.snapshot.compose = next_compose;
        Ok(true)
    }
}
