//! The web service page against what the Go agent's own collector sent for
//! the same inputs: recorded Docker Engine answers (`testdata/engine`,
//! recorded on a lab host from containers made for the test, trimmed to
//! the fields Go reads), probe answers from a table, and Go's output for
//! them (`testdata/go/`, made by a Go test run in the Go package over the
//! same `testdata/scenario.json`). Each test names the fault it catches.

mod client;
mod registry;
mod steps;
mod timers;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use labtether_agent_core::HubSender;
use labtether_agent_core::outbox::SendError;
use labtether_protocol::Message;
use serde_json::Value;

use super::health::{Client, Method, Pending, Prober};
use crate::docker::engine::{EngineApi, EngineError};

pub(crate) const TESTDATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/webservices/tests/testdata"
);

pub(crate) fn method_name(method: Method) -> &'static str {
    match method {
        Method::Head => "HEAD",
        Method::Get => "GET",
    }
}

pub(crate) fn client_name(client: Client) -> &'static str {
    match client {
        Client::Secure => "secure",
        Client::Insecure => "insecure",
    }
}

/// Probe answers from a table (`"HEAD http://..."` to a status, or `null`
/// for no answer; a request not in it gets no answer), recording every
/// attempt as `client method url`.
#[derive(Default)]
pub(crate) struct TableProber {
    pub answers: Mutex<BTreeMap<String, Option<u16>>>,
    pub asked: Mutex<Vec<String>>,
}

impl TableProber {
    pub fn set(&self, answers: BTreeMap<String, Option<u16>>) {
        *self.answers.lock().unwrap() = answers;
    }

    /// The attempts since the last call, sorted (Go's checks run at once).
    pub fn take(&self) -> Vec<String> {
        let mut asked = std::mem::take(&mut *self.asked.lock().unwrap());
        asked.sort();
        asked
    }
}

impl Prober for TableProber {
    fn attempt<'a>(&'a self, client: Client, method: Method, url: &'a str) -> Pending<'a> {
        let key = format!("{} {url}", method_name(method));
        self.asked
            .lock()
            .unwrap()
            .push(format!("{} {key}", client_name(client)));
        let answer = self.answers.lock().unwrap().get(&key).copied().flatten();
        Box::pin(async move { answer })
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
    /// What was sent since the last call, as `(type, data)`.
    pub fn take(&self) -> Vec<(String, Value)> {
        std::mem::take(&mut *self.sent.lock().unwrap())
            .into_iter()
            .map(|m| (m.r#type.clone(), m.decode::<Value>().unwrap()))
            .collect()
    }
}

/// The engine's container list: a body, or an error status.
pub(crate) struct FixtureEngine {
    pub answer: Mutex<Result<Vec<u8>, u16>>,
    pub asked: Mutex<Vec<String>>,
}

impl FixtureEngine {
    pub fn new() -> Self {
        Self {
            answer: Mutex::new(Ok(b"[]".to_vec())),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl EngineApi for FixtureEngine {
    fn get(&self, path: &str) -> Result<Vec<u8>, EngineError> {
        self.asked.lock().unwrap().push(path.to_owned());
        if path != "/containers/json?all=1" {
            return Err(EngineError::Status {
                path: path.into(),
                code: 404,
                body: "no fixture".into(),
            });
        }
        match &*self.answer.lock().unwrap() {
            Ok(body) => Ok(body.clone()),
            Err(code) => Err(EngineError::Status {
                path: path.into(),
                code: *code,
                body: "docker temporarily unavailable".into(),
            }),
        }
    }
}
