//! Files in the state folder, ported from Go's `enrollment_state.go`,
//! `enroll.go` (token file) and `enrollment_token_consumed.go`.
//!
//! - `agent-token` (0600): the durable agent credential.
//! - `enrollment-state.json` (0600): the Hub's asset ID, group, addresses and
//!   the Hub origins the token was issued for.
//! - `consumed-enrollment-token.sha256` (0600): the digest of a one-use token
//!   whose file could not be removed, so it is never offered again.

use std::io;
use std::path::{Path, PathBuf};

use data_encoding::HEXLOWER;
use labtether_agent_config::files::{self, MAX_SECRET_FILE_BYTES, MAX_STATE_FILE_BYTES};
use labtether_agent_config::urls::{self, UrlKind};
use labtether_agent_config::{EnrollmentToken, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsutil::{self, PRIVATE};

const STATE_FILE: &str = "enrollment-state.json";
const CONSUMED_FILE: &str = "consumed-enrollment-token.sha256";
const STATE_VERSION: u32 = 1;

/// Why a state file was not used.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: files::ReadError,
    },
    #[error("cannot write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("{0} is not valid enrollment state")]
    Invalid(PathBuf),
    #[error("the enrollment state has an invalid asset ID")]
    AssetId,
    #[error("the enrollment state has an invalid Hub address: {0}")]
    Url(#[from] urls::UrlError),
}

/// `enrollment-state.json`, field for field as Go writes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentState {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub asset_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_ws_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_api_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_origins: Vec<String>,
}

/// Go's `validPersistedAssetID`.
pub fn valid_asset_id(asset_id: &str) -> bool {
    !asset_id.is_empty()
        && asset_id.len() <= 128
        && asset_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Go's `normalizeIssuedAgentToken`.
pub fn valid_issued_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 4096
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

/// Go's `mergeHubOrigins`.
pub fn merge_origins(existing: &[String], addresses: &[&str]) -> Vec<String> {
    let mut merged: Vec<String> = Vec::new();
    let candidates = existing
        .iter()
        .map(|origin| Some(origin.trim().to_owned()))
        .chain(addresses.iter().map(|address| urls::origin(address)));
    for origin in candidates.flatten() {
        if !origin.is_empty() && !merged.contains(&origin) {
            merged.push(origin);
        }
    }
    merged
}

/// Paths of the state files beside the token file.
#[derive(Debug, Clone)]
pub struct StateFiles {
    pub token: PathBuf,
    pub state: PathBuf,
    pub consumed: PathBuf,
    pub ca: PathBuf,
    allow_insecure: bool,
    /// Makes the next token write fail, to test the rollback.
    #[cfg(test)]
    pub(crate) fail_token_write: bool,
}

impl StateFiles {
    pub fn new(token_file: &Path, allow_insecure: bool) -> Self {
        let dir = token_file.parent().unwrap_or(Path::new("."));
        Self {
            token: token_file.to_owned(),
            state: dir.join(STATE_FILE),
            consumed: dir.join(CONSUMED_FILE),
            ca: dir.join("ca.crt"),
            allow_insecure,
            #[cfg(test)]
            fail_token_write: false,
        }
    }

    /// The saved token, or `None` when absent or empty.
    pub fn load_token(&self) -> Option<Secret> {
        files::read_trimmed(&self.token, MAX_SECRET_FILE_BYTES)
            .ok()
            .and_then(Secret::new)
    }

    /// Writes the token (0600) atomically.
    pub fn save_token(&self, token: &Secret) -> Result<(), StateError> {
        #[cfg(test)]
        if self.fail_token_write {
            return Err(StateError::Write {
                path: self.token.clone(),
                source: io::Error::other("injected failure"),
            });
        }
        let data = format!("{}\n", token.expose());
        fsutil::write_atomic(&self.token, data.as_bytes(), PRIVATE).map_err(|source| {
            StateError::Write {
                path: self.token.clone(),
                source,
            }
        })
    }

    /// Removes the token file (after a failed save, so no stale token stays).
    pub fn remove_token(&self) -> io::Result<()> {
        fsutil::remove_if_present(&self.token)
    }

    /// Go's `restoreEnrollmentState` read step. `Ok(None)` when absent.
    pub fn load_state(&self) -> Result<Option<EnrollmentState>, StateError> {
        let data = match files::read_bounded(&self.state, MAX_STATE_FILE_BYTES) {
            Ok(data) => data,
            Err(error) if error.is_not_found() => return Ok(None),
            Err(source) => {
                return Err(StateError::Read {
                    path: self.state.clone(),
                    source,
                });
            }
        };
        let state: EnrollmentState =
            serde_json::from_slice(&data).map_err(|_| StateError::Invalid(self.state.clone()))?;
        if state.version != STATE_VERSION || !valid_asset_id(state.asset_id.trim()) {
            return Err(StateError::Invalid(self.state.clone()));
        }
        urls::validate(
            &state.hub_ws_url,
            UrlKind::WebSocket,
            self.allow_insecure,
            false,
        )?;
        urls::validate(&state.hub_api_url, UrlKind::Api, self.allow_insecure, false)?;
        Ok(Some(state))
    }

    /// Go's `saveEnrollmentState`: normalizes, checks and writes (0600).
    pub fn save_state(&self, mut state: EnrollmentState) -> Result<(), StateError> {
        state.version = STATE_VERSION;
        state.asset_id = state.asset_id.trim().to_owned();
        state.group_id = state.group_id.map(|group| group.trim().to_owned());
        state.hub_ws_url =
            urls::normalize(&state.hub_ws_url, UrlKind::WebSocket, self.allow_insecure);
        state.hub_api_url = urls::normalize(&state.hub_api_url, UrlKind::Api, self.allow_insecure);
        if state.hub_api_url.is_empty() {
            state.hub_api_url = urls::api_from_ws(&state.hub_ws_url, self.allow_insecure);
        }
        if !valid_asset_id(&state.asset_id) {
            return Err(StateError::AssetId);
        }
        urls::validate(
            &state.hub_ws_url,
            UrlKind::WebSocket,
            self.allow_insecure,
            false,
        )?;
        urls::validate(&state.hub_api_url, UrlKind::Api, self.allow_insecure, false)?;
        state.token_origins = merge_origins(
            &state.token_origins,
            &[&state.hub_ws_url, &state.hub_api_url],
        );
        let data =
            serde_json::to_vec(&state).map_err(|_| StateError::Invalid(self.state.clone()))?;
        fsutil::write_atomic(&self.state, &data, PRIVATE).map_err(|source| StateError::Write {
            path: self.state.clone(),
            source,
        })
    }

    /// The token origins already recorded, for rewrites that keep the token.
    pub fn saved_origins(&self) -> Vec<String> {
        self.load_state()
            .ok()
            .flatten()
            .map(|state| state.token_origins)
            .unwrap_or_default()
    }

    fn digest(token: &Secret) -> String {
        HEXLOWER.encode(&Sha256::digest(token.expose().as_bytes()))
    }

    /// Go's `isConsumedEnrollmentToken`.
    pub fn is_consumed(&self, token: &Secret) -> bool {
        match files::read_trimmed(&self.consumed, MAX_SECRET_FILE_BYTES) {
            Ok(recorded) => constant_time_eq(recorded.as_bytes(), Self::digest(token).as_bytes()),
            Err(_) => false,
        }
    }

    /// Go's `discardConsumedEnrollmentToken`: removes a file-sourced one-use
    /// token after the Hub used it. A file that cannot be removed (a
    /// read-only mount) is recorded as used instead.
    pub fn discard_used_enrollment_token(
        &self,
        enrollment: &EnrollmentToken,
    ) -> Result<(), StateError> {
        let Some(path) = enrollment.file.as_deref() else {
            return Ok(());
        };
        match std::fs::remove_file(path) {
            Ok(()) => {
                log::info!("removed the used enrollment token file");
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                let data = format!("{}\n", Self::digest(&enrollment.token));
                fsutil::write_atomic(&self.consumed, data.as_bytes(), PRIVATE).map_err(
                    |source| StateError::Write {
                        path: self.consumed.clone(),
                        source,
                    },
                )?;
                log::warn!(
                    "could not remove the used enrollment token file ({error}); it is marked as used and will be ignored"
                );
                Ok(())
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
