//! The Docker page against recorded Docker Engine answers (`testdata/engine`,
//! recorded on a lab host from containers made for the test, the lab
//! folder written as `@DIR@`) and against what the Go agent's own
//! collector sent for the same answers (`testdata/go/docker-steps.json`,
//! made by a Go program that runs the Go collector over the same
//! `testdata/scenario.json`). Each test names the fault it catches.

mod connector;
mod engine;
mod events;
mod scenario;
mod stats;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use labtether_agent_core::HubSender;
use labtether_agent_core::outbox::SendError;
use labtether_protocol::Message;
use serde::Deserialize;
use serde_json::{Value, json};

use super::engine::{EngineApi, EngineError};

pub(crate) const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/docker/tests/testdata");

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Fixture {
    #[serde(default)]
    pub status: u16,
    pub file: String,
    #[serde(default)]
    pub repeat: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Step {
    pub call: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub asset: String,
    pub online: Option<bool>,
    #[serde(default)]
    pub events: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Scenario {
    pub files: BTreeMap<String, String>,
    pub states: BTreeMap<String, BTreeMap<String, Fixture>>,
    pub steps: Vec<Step>,
}

pub(crate) fn scenario() -> Scenario {
    let text = std::fs::read_to_string(format!("{TESTDATA}/scenario.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A folder holding the scenario's files (the Compose project), removed on
/// drop; it stands for `@DIR@`.
pub(crate) struct Folder(pub PathBuf);

impl Folder {
    pub fn new(name: &str, files: &BTreeMap<String, String>) -> Self {
        // A Unix socket path holds at most 107 bytes; the lab runner's
        // temporary folder can be too long for one.
        let base = std::env::temp_dir();
        let base = if base.as_os_str().len() > 60 {
            PathBuf::from("/tmp")
        } else {
            base
        };
        let dir = base.join(format!("lt-docker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (path, body) in files {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        std::fs::create_dir_all(dir.join("state")).unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fixture's body as the engine stand-in serves it.
pub(crate) fn body(fixture: &Fixture, dir: &Path) -> Vec<u8> {
    let text = std::fs::read_to_string(format!("{TESTDATA}/engine/{}", fixture.file)).unwrap();
    let text = text.replace("@DIR@", &dir.display().to_string());
    if fixture.repeat == 0 {
        return text.into_bytes();
    }
    let rows: Vec<String> = (0..fixture.repeat)
        .map(|n| text.trim().replace("{n}", &format!("{n:03}")))
        .collect();
    format!("[{}]", rows.join(",")).into_bytes()
}

/// The engine answering from the scenario's current state.
pub(crate) struct FixtureEngine {
    pub states: BTreeMap<String, BTreeMap<String, Fixture>>,
    pub state: RefCell<String>,
    pub dir: PathBuf,
    pub asked: RefCell<Vec<String>>,
}

impl EngineApi for FixtureEngine {
    fn get(&self, path: &str) -> Result<Vec<u8>, EngineError> {
        self.asked.borrow_mut().push(path.to_owned());
        let state = self.state.borrow();
        let Some(fixture) = self.states[&*state].get(path) else {
            let body = r#"{"message":"no fixture"}"#.to_owned();
            return Err(EngineError::Status {
                path: path.into(),
                code: 404,
                body,
            });
        };
        let data = body(fixture, &self.dir);
        if fixture.status >= 300 {
            let body = String::from_utf8_lossy(&data).trim().to_owned();
            return Err(EngineError::Status {
                path: path.into(),
                code: fixture.status,
                body,
            });
        }
        Ok(data)
    }
}

/// A Hub that records what is sent; it can be offline, change the asset ID
/// and count connections.
pub(crate) struct Recorder {
    pub offline: AtomicBool,
    pub asset: Mutex<String>,
    pub connections: AtomicU64,
    pub sent: Mutex<Vec<Message>>,
}

impl Default for Recorder {
    fn default() -> Self {
        Self {
            offline: AtomicBool::new(false),
            asset: Mutex::new("nas01".into()),
            connections: AtomicU64::new(1),
            sent: Mutex::new(Vec::new()),
        }
    }
}

impl HubSender for Recorder {
    fn connected(&self) -> bool {
        !self.offline.load(Ordering::SeqCst)
    }
    fn asset_id(&self) -> String {
        self.asset.lock().unwrap().clone()
    }
    fn send(&self, message: &Message) -> Result<(), SendError> {
        if !self.connected() {
            return Err(SendError::Closed);
        }
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
    fn connection(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Recorder {
    /// What was sent since the last call, as `{type, data}`.
    pub fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.sent.lock().unwrap())
            .into_iter()
            .map(|m| json!({"type": m.r#type, "data": m.decode::<Value>().unwrap()}))
            .collect()
    }
}

/// compact.py's rule: a list of more than 20 items as count, first, last.
pub(crate) fn compact(value: &Value) -> Value {
    match value {
        Value::Array(items) if items.len() > 20 => json!({
            "count": items.len(),
            "first": compact(&items[0]),
            "last": compact(&items[items.len() - 1]),
        }),
        Value::Array(items) => Value::Array(items.iter().map(compact).collect()),
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), compact(v))).collect())
        }
        other => other.clone(),
    }
}

/// The wire differences the Hub reads alike: Go writes `null` for an empty
/// list or map and leaves some out where Rust writes `[]` or `{}`; both
/// are dropped. Numbers compare as numbers (Go writes `20`, Rust `20.0`).
/// Go's Compose action version and endpoint ID, which this agent leaves
/// out on purpose, are dropped from Go's side by the caller.
pub(crate) fn normalize(value: &Value) -> Value {
    match value {
        Value::Number(number) => json!(number.as_f64().unwrap()),
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), normalize(v)))
                .filter(|(_, v)| !matches!(v, Value::Null) && v != &json!([]) && v != &json!({}))
                .collect(),
        ),
        other => other.clone(),
    }
}
