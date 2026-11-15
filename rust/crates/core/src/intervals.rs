//! The collect and heartbeat intervals and the Hub's `config.update`,
//! ported from Go's `handleConfigUpdate` (`settings_ws_handler.go`) and
//! `config_persist.go`.
//!
//! Rules, as in Go: with remote overrides off nothing changes; an interval
//! chosen in the environment at start is kept; 0 goes back to the start
//! value; a collect interval of 2 to 300 s and a heartbeat interval of 5 to
//! 600 s are applied, anything else is ignored with a warning. Applied
//! overrides are saved in `applied-config.json` beside the token and
//! restored at start. The reply carries the intervals now in use.
//!
//! One difference: Go's loops only pick up an override above zero, so a
//! reset to 0 changed the reply but not the running timers until a restart.
//! Here the timers follow every change.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use labtether_agent_config::Settings;
use labtether_agent_config::files::{MAX_STATE_FILE_BYTES, read_bounded};
use labtether_protocol::{ConfigAppliedData, ConfigUpdateData};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::fsutil;

/// Go's bounds for a Hub override, in seconds.
pub const COLLECT_RANGE: std::ops::RangeInclusive<i64> = 2..=300;
pub const HEARTBEAT_RANGE: std::ops::RangeInclusive<i64> = 5..=600;
const FILE_NAME: &str = "applied-config.json";

/// The intervals the telemetry loop uses now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intervals {
    pub collect: Duration,
    pub heartbeat: Duration,
}

/// `applied-config.json`; zero means no override, as Go's `omitempty`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AppliedFile {
    #[serde(default, skip_serializing_if = "is_zero")]
    collect_interval_sec: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    heartbeat_interval_sec: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[derive(Debug)]
struct State {
    base: Intervals,
    collect_override: i64,
    heartbeat_override: i64,
}

impl State {
    fn current(&self) -> Intervals {
        let pick = |seconds: i64, base: Duration| match u64::try_from(seconds) {
            Ok(seconds) if seconds > 0 => Duration::from_secs(seconds),
            _ => base,
        };
        Intervals {
            collect: pick(self.collect_override, self.base.collect),
            heartbeat: pick(self.heartbeat_override, self.base.heartbeat),
        }
    }
}

/// The intervals, their start values and the rules for changing them.
#[derive(Debug)]
pub struct IntervalControl {
    state: Mutex<State>,
    sender: watch::Sender<Intervals>,
    collect_pinned: bool,
    heartbeat_pinned: bool,
    allow_remote: bool,
    file: PathBuf,
}

fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

impl IntervalControl {
    /// The start intervals, with saved Hub overrides restored when remote
    /// overrides are on and the interval is not pinned.
    pub fn new(settings: &Settings) -> Self {
        let base = Intervals {
            collect: settings.collect_interval,
            heartbeat: settings.heartbeat_interval,
        };
        let control = Self {
            state: Mutex::new(State {
                base,
                collect_override: 0,
                heartbeat_override: 0,
            }),
            sender: watch::Sender::new(base),
            collect_pinned: settings.collect_pinned,
            heartbeat_pinned: settings.heartbeat_pinned,
            allow_remote: settings.allow_remote_overrides,
            file: settings.state_dir().join(FILE_NAME),
        };
        control.restore();
        control
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn restore(&self) {
        if !self.allow_remote {
            if self.file.exists() {
                log::info!(
                    "remote overrides are off; the Hub's saved intervals in {} are not applied",
                    self.file.display()
                );
            }
            return;
        }
        let Ok(data) = read_bounded(&self.file, MAX_STATE_FILE_BYTES) else {
            return;
        };
        let saved: AppliedFile = match serde_json::from_slice(&data) {
            Ok(saved) => saved,
            Err(error) => {
                log::warn!("failed to parse {}: {error}", self.file.display());
                return;
            }
        };
        let mut state = self.lock();
        if COLLECT_RANGE.contains(&saved.collect_interval_sec) && !self.collect_pinned {
            state.collect_override = saved.collect_interval_sec;
            log::info!(
                "restored collect interval override: {}s",
                saved.collect_interval_sec
            );
        }
        if HEARTBEAT_RANGE.contains(&saved.heartbeat_interval_sec) && !self.heartbeat_pinned {
            state.heartbeat_override = saved.heartbeat_interval_sec;
            log::info!(
                "restored heartbeat interval override: {}s",
                saved.heartbeat_interval_sec
            );
        }
        self.sender.send_replace(state.current());
    }

    /// A receiver that sees every change.
    pub fn subscribe(&self) -> watch::Receiver<Intervals> {
        self.sender.subscribe()
    }

    /// The intervals in use, as the `config.applied` reply carries them.
    pub fn applied(&self) -> ConfigAppliedData {
        let current = self.lock().current();
        ConfigAppliedData {
            collect_interval_sec: seconds(current.collect),
            heartbeat_interval_sec: seconds(current.heartbeat),
        }
    }

    /// Applies a Hub update and returns the reply.
    pub fn apply(&self, update: &ConfigUpdateData) -> ConfigAppliedData {
        if !self.allow_remote {
            log::info!("ignoring config update because remote overrides are disabled");
            return self.applied();
        }
        let mut collect = update.collect_interval_sec;
        let mut heartbeat = update.heartbeat_interval_sec;
        if collect.is_some() && self.collect_pinned {
            log::info!("keeping the install-time collect interval");
            collect = None;
        }
        if heartbeat.is_some() && self.heartbeat_pinned {
            log::info!("keeping the install-time heartbeat interval");
            heartbeat = None;
        }
        let mut state = self.lock();
        let mut changed = false;
        if let Some(value) = collect {
            if value == 0 || COLLECT_RANGE.contains(&value) {
                state.collect_override = value;
                changed = true;
            } else {
                log::warn!("ignoring invalid collect interval {value} (must be 2-300)");
            }
        }
        if let Some(value) = heartbeat {
            if value == 0 || HEARTBEAT_RANGE.contains(&value) {
                state.heartbeat_override = value;
                changed = true;
            } else {
                log::warn!("ignoring invalid heartbeat interval {value} (must be 5-600)");
            }
        }
        if changed {
            self.sender.send_replace(state.current());
            save(&self.file, state.collect_override, state.heartbeat_override);
        }
        drop(state);
        self.applied()
    }
}

/// Go's `persistAppliedConfig`: the file holds the overrides, and goes away
/// when there are none.
fn save(path: &Path, collect: i64, heartbeat: i64) {
    if collect == 0 && heartbeat == 0 {
        if let Err(error) = fsutil::remove_if_present(path) {
            log::warn!("failed to remove {}: {error}", path.display());
        }
        return;
    }
    let file = AppliedFile {
        collect_interval_sec: collect,
        heartbeat_interval_sec: heartbeat,
    };
    let Ok(data) = serde_json::to_vec_pretty(&file) else {
        return;
    };
    if let Err(error) = fsutil::write_atomic(path, &data, fsutil::PRIVATE) {
        log::warn!("failed to save {}: {error}", path.display());
    }
}
