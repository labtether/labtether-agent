//! The Docker Engine answers the inventory reads, the fields Go's
//! `container_types.go` keeps. As with Go's decoder, a missing field or a
//! `null` gives the zero value, unknown fields are ignored, and a value of
//! the wrong type fails the whole answer.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::{DeserializeOwned, Deserializer, IgnoredAny};

/// `null` reads as the zero value, as Go's decoder leaves the field unset.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Parses an engine answer.
pub(crate) fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(body)
}

/// A list answer: `null` is an empty list, as Go's `json.Unmarshal` into a
/// nil slice.
pub(crate) fn parse_list<T: DeserializeOwned>(body: &[u8]) -> Result<Vec<T>, serde_json::Error> {
    Ok(serde_json::from_slice::<Option<Vec<T>>>(body)?.unwrap_or_default())
}

/// `GET /containers/json?all=1`, one row.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Container {
    #[serde(rename = "Id", default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(rename = "Names", default, deserialize_with = "nullable")]
    pub names: Vec<String>,
    #[serde(rename = "Image", default, deserialize_with = "nullable")]
    pub image: String,
    #[serde(rename = "State", default, deserialize_with = "nullable")]
    pub state: String,
    #[serde(rename = "Status", default, deserialize_with = "nullable")]
    pub status: String,
    #[serde(rename = "Created", default, deserialize_with = "nullable")]
    pub created: i64,
    #[serde(rename = "Ports", default, deserialize_with = "nullable")]
    pub ports: Vec<Port>,
    #[serde(rename = "Labels", default, deserialize_with = "nullable")]
    pub labels: BTreeMap<String, String>,
    #[serde(rename = "Mounts", default, deserialize_with = "nullable")]
    pub mounts: Vec<Mount>,
    #[serde(rename = "NetworkSettings", default, deserialize_with = "nullable")]
    pub network_settings: NetworkSettings,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct NetworkSettings {
    /// Only the names are read; each value can be any JSON, as Go's
    /// `map[string]interface{}`.
    #[serde(rename = "Networks", default, deserialize_with = "nullable")]
    pub networks: BTreeMap<String, Ignored>,
}

/// A JSON value read and dropped.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Ignored;

impl<'de> Deserialize<'de> for Ignored {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer).map(|_| Self)
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Port {
    /// The host address of a published port; read by the web service page.
    #[serde(rename = "IP", default, deserialize_with = "nullable")]
    pub ip: String,
    #[serde(rename = "PrivatePort", default, deserialize_with = "nullable")]
    pub private_port: i64,
    #[serde(rename = "PublicPort", default, deserialize_with = "nullable")]
    pub public_port: i64,
    #[serde(rename = "Type", default, deserialize_with = "nullable")]
    pub r#type: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Mount {
    #[serde(rename = "Type", default, deserialize_with = "nullable")]
    pub r#type: String,
    #[serde(rename = "Source", default, deserialize_with = "nullable")]
    pub source: String,
    #[serde(rename = "Destination", default, deserialize_with = "nullable")]
    pub destination: String,
}

/// `GET /images/json`, one row.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Image {
    #[serde(rename = "Id", default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(rename = "RepoTags", default, deserialize_with = "nullable")]
    pub repo_tags: Vec<String>,
    #[serde(rename = "Size", default, deserialize_with = "nullable")]
    pub size: i64,
    #[serde(rename = "Created", default, deserialize_with = "nullable")]
    pub created: i64,
}

/// `GET /networks`, one row.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Network {
    #[serde(rename = "Id", default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(rename = "Name", default, deserialize_with = "nullable")]
    pub name: String,
    #[serde(rename = "Driver", default, deserialize_with = "nullable")]
    pub driver: String,
    #[serde(rename = "Scope", default, deserialize_with = "nullable")]
    pub scope: String,
}

/// `GET /volumes`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Volumes {
    #[serde(rename = "Volumes", default, deserialize_with = "nullable")]
    pub volumes: Vec<Volume>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Volume {
    #[serde(rename = "Name", default, deserialize_with = "nullable")]
    pub name: String,
    #[serde(rename = "Driver", default, deserialize_with = "nullable")]
    pub driver: String,
    #[serde(rename = "Mountpoint", default, deserialize_with = "nullable")]
    pub mountpoint: String,
}

/// `GET /version`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Version {
    #[serde(rename = "Version", default, deserialize_with = "nullable")]
    pub version: String,
    #[serde(rename = "ApiVersion", default, deserialize_with = "nullable")]
    pub api_version: String,
    #[serde(rename = "Os", default, deserialize_with = "nullable")]
    pub os: String,
    #[serde(rename = "Arch", default, deserialize_with = "nullable")]
    pub arch: String,
}

/// `GET /events`, one event.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Event {
    #[serde(rename = "Type", default, deserialize_with = "nullable")]
    pub r#type: String,
    #[serde(rename = "Action", default, deserialize_with = "nullable")]
    pub action: String,
    #[serde(rename = "Actor", default, deserialize_with = "nullable")]
    pub actor: Actor,
    #[serde(rename = "time", default, deserialize_with = "nullable")]
    pub time: i64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Actor {
    #[serde(rename = "ID", default, deserialize_with = "nullable")]
    pub id: String,
    #[serde(rename = "Attributes", default, deserialize_with = "nullable")]
    pub attributes: BTreeMap<String, String>,
}

/// `GET /containers/{id}/stats?stream=false`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct Stats {
    #[serde(default, deserialize_with = "nullable")]
    pub cpu_stats: CpuStats,
    #[serde(default, deserialize_with = "nullable")]
    pub precpu_stats: CpuStats,
    #[serde(default, deserialize_with = "nullable")]
    pub memory_stats: MemoryStats,
    #[serde(default, deserialize_with = "nullable")]
    pub networks: BTreeMap<String, NetworkStats>,
    #[serde(default, deserialize_with = "nullable")]
    pub blkio_stats: BlkioStats,
    #[serde(default, deserialize_with = "nullable")]
    pub pids_stats: PidsStats,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct CpuStats {
    #[serde(default, deserialize_with = "nullable")]
    pub cpu_usage: CpuUsage,
    #[serde(default, deserialize_with = "nullable")]
    pub system_cpu_usage: i64,
    /// Go reads it for `cpu_stats` only; `precpu_stats` leaves it unused.
    #[serde(default, deserialize_with = "nullable")]
    pub online_cpus: i64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct CpuUsage {
    #[serde(default, deserialize_with = "nullable")]
    pub total_usage: i64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct MemoryStats {
    #[serde(default, deserialize_with = "nullable")]
    pub usage: i64,
    #[serde(default, deserialize_with = "nullable")]
    pub limit: i64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct NetworkStats {
    #[serde(default, deserialize_with = "nullable")]
    pub rx_bytes: i64,
    #[serde(default, deserialize_with = "nullable")]
    pub tx_bytes: i64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct BlkioStats {
    #[serde(default, deserialize_with = "nullable")]
    pub io_service_bytes_recursive: Vec<BlkioEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct BlkioEntry {
    #[serde(default, deserialize_with = "nullable")]
    pub op: String,
    #[serde(default, deserialize_with = "nullable")]
    pub value: i64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct PidsStats {
    #[serde(default, deserialize_with = "nullable")]
    pub current: i64,
}
