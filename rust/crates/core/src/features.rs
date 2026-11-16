//! What the features crate hands the connection: the request handlers to
//! run off the read loop, and what the heartbeat tells the Hub about them.
//! `core` knows no feature; the binary builds a [`Features`] and passes it
//! to [`crate::Agent::start_with`].
//!
//! A handler is written against typed payloads with
//! [`Features::on_request`]: the request is decoded, the handler returns the
//! reply payload, and the reply goes out with the request's ID. No handler
//! builds a message by hand. As in Go, a request that does not decode is
//! logged and gets no reply.

use std::collections::BTreeMap;
use std::sync::Arc;

use labtether_protocol::{
    MSG_ALERT_NOTIFY, MSG_CONFIG_UPDATE, MSG_ENROLLMENT_APPROVED, MSG_ENROLLMENT_CHALLENGE,
    MSG_ENROLLMENT_REJECTED, MSG_PING, Message,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A handler run on a worker thread: the request in, the reply (if any) out.
pub type Work = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

/// Message types `core` handles itself; a feature cannot take them.
const CORE_TYPES: [&str; 6] = [
    MSG_ALERT_NOTIFY,
    MSG_PING,
    MSG_CONFIG_UPDATE,
    MSG_ENROLLMENT_CHALLENGE,
    MSG_ENROLLMENT_APPROVED,
    MSG_ENROLLMENT_REJECTED,
];

/// What the heartbeat says this agent can do: Go's `capabilities` list and
/// its `cap_*` and `*_backend` metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Advertised {
    pub capabilities: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

/// The request handlers and the advertisement of every feature in a build.
#[derive(Clone, Default)]
pub struct Features {
    work: Vec<(&'static str, Work)>,
    advertised: Advertised,
}

impl std::fmt::Debug for Features {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Features")
            .field("handles", &self.message_types())
            .field("advertised", &self.advertised)
            .finish()
    }
}

impl Features {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles `request` with `answer` and replies with a `reply` message
    /// whose ID is the request's `request_id` (Go replies with
    /// `req.RequestID`, not the envelope ID).
    ///
    /// # Panics
    /// When `request` already has a handler or is a type `core` handles: a
    /// build mistake the capability tests catch.
    pub fn on_request<Req, Rep>(
        &mut self,
        request: &'static str,
        reply: &'static str,
        request_id: fn(&Req) -> &str,
        answer: impl Fn(Req) -> Rep + Send + Sync + 'static,
    ) where
        Req: DeserializeOwned + 'static,
        Rep: Serialize,
    {
        assert!(
            !CORE_TYPES.contains(&request) && !self.handles(request),
            "{request} has two handlers"
        );
        let work: Work = Arc::new(move |message: &Message| {
            let decoded: Req = match message.decode() {
                Ok(decoded) => decoded,
                Err(error) => {
                    log::warn!("invalid {request} request: {error}");
                    return None;
                }
            };
            let id = request_id(&decoded).to_owned();
            let payload = answer(decoded);
            match Message::with_data(reply, &id, &payload) {
                Ok(message) => Some(message),
                Err(error) => {
                    log::warn!("failed to marshal {reply} response: {error}");
                    None
                }
            }
        });
        self.work.push((request, work));
    }

    /// Adds a heartbeat metadata key, such as `cap_network`.
    pub fn advertise(&mut self, key: &str, value: &str) {
        self.advertised
            .metadata
            .insert(key.to_owned(), value.to_owned());
    }

    /// Adds a name to the heartbeat's `capabilities` list.
    pub fn advertise_capability(&mut self, name: &str) {
        self.advertised.capabilities.push(name.to_owned());
    }

    pub fn handles(&self, request: &str) -> bool {
        self.work.iter().any(|(kind, _)| *kind == request)
    }

    /// The handler for `request`, for tests that call it directly.
    pub fn handler(&self, request: &str) -> Option<&Work> {
        self.work
            .iter()
            .find(|(kind, _)| *kind == request)
            .map(|(_, work)| work)
    }

    pub fn message_types(&self) -> Vec<&'static str> {
        self.work.iter().map(|(kind, _)| *kind).collect()
    }

    pub fn advertised(&self) -> &Advertised {
        &self.advertised
    }

    pub(crate) fn work(&self) -> impl Iterator<Item = &(&'static str, Work)> {
        self.work.iter()
    }
}
