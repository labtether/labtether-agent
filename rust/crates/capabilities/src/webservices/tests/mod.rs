//! The web service page against what the Go agent's own collector sent for
//! the same inputs: Docker Engine answers (`testdata/engine`, recorded on a
//! lab host from containers made for the test or written in its shape,
//! trimmed to the fields Go reads), probe answers from tables, and Go's
//! output for them (`testdata/go/`, made by a Go test run in the Go
//! package over the same `testdata/scenario.json`). Each test names the
//! fault it catches.

mod client;
mod pages;
mod registry;
mod scan;
mod steps;
mod timers;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use labtether_agent_core::HubSender;
use labtether_agent_core::outbox::SendError;
use labtether_protocol::Message;
use serde::Deserialize;
use serde_json::Value;

use super::health::{Client, Method, Pending, Prober};
use super::pages::{Fetching, MAX_BODY, Page};
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

/// One probe answer: a status with an empty page, or a page (`pad` bytes
/// of `x` before `body`; `unreadable` when the page cannot be read).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum Reply {
    Status(u16),
    Page {
        status: u16,
        #[serde(default)]
        body: String,
        #[serde(default)]
        pad: usize,
        #[serde(default)]
        location: String,
        #[serde(default)]
        unreadable: bool,
    },
}

impl Reply {
    fn status(&self) -> u16 {
        match self {
            Self::Status(status) | Self::Page { status, .. } => *status,
        }
    }

    /// The page as Go's probe reads it: its first 64 KiB.
    fn page(&self) -> Page {
        match self {
            Self::Status(status) => Page {
                status: *status,
                location: String::new(),
                body: Some(Vec::new()),
            },
            Self::Page {
                status,
                body,
                pad,
                location,
                unreadable,
            } => {
                let mut page = "x".repeat(*pad).into_bytes();
                page.extend_from_slice(body.as_bytes());
                page.truncate(MAX_BODY);
                Page {
                    status: *status,
                    location: location.clone(),
                    body: (!unreadable).then_some(page),
                }
            }
        }
    }
}

/// A service's answers by path (with its query), `*` for any other path;
/// `null` for no answer.
pub(crate) type Site = BTreeMap<String, Option<Reply>>;

/// Probe answers: an exact table (`"HEAD http://..."` to an answer or
/// `null`) first, then the sites by origin; anything else gets no answer.
/// Records every attempt as `client method url`: the port scan's GETs,
/// the recognition probes' GETs in order, the health checks apart. The
/// scan's checks are the GETs before the first page fetch or HEAD: the
/// scan ends before recognition (which only fetches pages) and the health
/// checks (which start with HEAD) begin.
pub(crate) struct TableProber {
    pub answers: Mutex<BTreeMap<String, Option<Reply>>>,
    pub sites: Mutex<BTreeMap<String, Site>>,
    pub scanned: Mutex<Vec<String>>,
    pub fetched: Mutex<Vec<String>>,
    pub attempted: Mutex<Vec<String>>,
    scanning: AtomicBool,
}

impl Default for TableProber {
    fn default() -> Self {
        Self {
            answers: Mutex::default(),
            sites: Mutex::default(),
            scanned: Mutex::default(),
            fetched: Mutex::default(),
            attempted: Mutex::default(),
            scanning: AtomicBool::new(true),
        }
    }
}

impl TableProber {
    pub fn set(&self, answers: BTreeMap<String, Option<Reply>>) {
        *self.answers.lock().unwrap() = answers;
    }

    pub fn set_sites(&self, sites: BTreeMap<String, Site>) {
        *self.sites.lock().unwrap() = sites;
    }

    /// The scan's checks since the last call sorted (Go runs 16 at
    /// once), the recognition requests in order and the health checks
    /// sorted (Go runs them at once).
    pub fn take(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut scanned = std::mem::take(&mut *self.scanned.lock().unwrap());
        let fetched = std::mem::take(&mut *self.fetched.lock().unwrap());
        let mut attempted = std::mem::take(&mut *self.attempted.lock().unwrap());
        self.scanning.store(true, Ordering::SeqCst);
        scanned.sort();
        attempted.sort();
        (scanned, fetched, attempted)
    }

    fn lookup(&self, method: Method, url: &str) -> Option<Reply> {
        let key = format!("{} {url}", method_name(method));
        if let Some(answer) = self.answers.lock().unwrap().get(&key) {
            return answer.clone();
        }
        let (scheme, rest) = url.split_once("://")?;
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let path = match &rest[end..] {
            "" => "/",
            path => path,
        };
        let sites = self.sites.lock().unwrap();
        let site = sites.get(&format!("{scheme}://{}", &rest[..end]))?;
        site.get(path).or_else(|| site.get("*")).cloned().flatten()
    }
}

impl Prober for TableProber {
    fn attempt<'a>(&'a self, client: Client, method: Method, url: &'a str) -> Pending<'a> {
        let entry = format!("{} {} {url}", client_name(client), method_name(method));
        if method == Method::Get && self.scanning.load(Ordering::SeqCst) {
            self.scanned.lock().unwrap().push(entry);
        } else {
            self.scanning.store(false, Ordering::SeqCst);
            self.attempted.lock().unwrap().push(entry);
        }
        let answer = self.lookup(method, url).map(|reply| reply.status());
        Box::pin(async move { answer })
    }

    fn fetch<'a>(&'a self, client: Client, url: &'a str) -> Fetching<'a> {
        self.scanning.store(false, Ordering::SeqCst);
        self.fetched
            .lock()
            .unwrap()
            .push(format!("{} GET {url}", client_name(client)));
        let page = self.lookup(Method::Get, url).map(|reply| reply.page());
        Box::pin(async move { page })
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
