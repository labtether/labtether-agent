//! `agent-config.json`, the file the Go agent writes for local and Hub
//! settings (`sysconfig/settings_file.go`). Only the keys this agent uses are
//! read; each is checked against the same rules as Go and dropped when bad.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::LogLevel;
use crate::docker::FileDocker;
use crate::env::parse_go_bool;
use crate::files::{self, MAX_STATE_FILE_BYTES};

pub(crate) const KEY_COLLECT_INTERVAL_SEC: &str = "collect_interval_sec";
pub(crate) const KEY_HEARTBEAT_INTERVAL_SEC: &str = "heartbeat_interval_sec";
pub(crate) const KEY_LOG_LEVEL: &str = "log_level";
pub(crate) const KEY_TLS_SKIP_VERIFY: &str = "tls_skip_verify";
pub(crate) const KEY_TLS_CA_FILE: &str = "tls_ca_file";
pub(crate) const KEY_DOCKER_ENABLED: &str = "docker_enabled";
pub(crate) const KEY_DOCKER_ENDPOINT: &str = "docker_endpoint";
pub(crate) const KEY_DOCKER_INTERVAL_SEC: &str = "docker_discovery_interval_sec";
pub(crate) const KEY_SERVICES_DOCKER_ENABLED: &str = "services_discovery_docker_enabled";

#[derive(Deserialize)]
struct RawFile {
    #[serde(default)]
    values: BTreeMap<String, String>,
}

/// The values found in the file, already checked.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FileValues {
    pub collect_interval_sec: Option<u64>,
    pub heartbeat_interval_sec: Option<u64>,
    pub log_level: Option<LogLevel>,
    pub tls_skip_verify: Option<bool>,
    /// Present means the file sets it, even to the empty string.
    pub tls_ca_file: Option<String>,
    pub docker: FileDocker,
    /// `services_discovery_docker_enabled`, read with Go's `ParseBool`.
    pub services_docker_enabled: Option<bool>,
}

/// Why the file was not used.
#[derive(Debug, thiserror::Error)]
pub enum SettingsFileError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: files::ReadError,
    },
    #[error("{path} is not valid JSON: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
}

/// Reads the file. A missing file gives no values, as in Go.
pub(crate) fn load(path: &Path) -> Result<FileValues, SettingsFileError> {
    let data = match files::read_bounded(path, MAX_STATE_FILE_BYTES) {
        Ok(data) => data,
        Err(error) if error.is_not_found() => return Ok(FileValues::default()),
        Err(source) => {
            return Err(SettingsFileError::Read {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let raw: RawFile =
        serde_json::from_slice(&data).map_err(|source| SettingsFileError::Parse {
            path: path.display().to_string(),
            source,
        })?;
    Ok(parse_values(&raw.values))
}

fn parse_values(values: &BTreeMap<String, String>) -> FileValues {
    let get = |key: &str| values.get(key).map(|value| value.trim());
    FileValues {
        collect_interval_sec: get(KEY_COLLECT_INTERVAL_SEC)
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|seconds| (2..=300).contains(seconds)),
        heartbeat_interval_sec: get(KEY_HEARTBEAT_INTERVAL_SEC)
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|seconds| (5..=600).contains(seconds)),
        log_level: get(KEY_LOG_LEVEL).and_then(LogLevel::parse),
        tls_skip_verify: get(KEY_TLS_SKIP_VERIFY).and_then(parse_go_bool),
        tls_ca_file: get(KEY_TLS_CA_FILE).map(str::to_owned),
        docker: FileDocker {
            enabled: get(KEY_DOCKER_ENABLED)
                .filter(|raw| !raw.is_empty())
                .map(str::to_owned),
            endpoint: get(KEY_DOCKER_ENDPOINT)
                .filter(|raw| !raw.is_empty())
                .map(str::to_owned),
            interval_sec: get(KEY_DOCKER_INTERVAL_SEC)
                .and_then(|raw| raw.parse::<u64>().ok())
                .filter(|seconds| (5..=3600).contains(seconds)),
        },
        services_docker_enabled: get(KEY_SERVICES_DOCKER_ENABLED).and_then(parse_go_bool),
    }
}
