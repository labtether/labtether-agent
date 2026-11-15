//! Incoming messages are handled through a registry keyed by message type,
//! in place of the Go agent's one dispatch function that takes every
//! manager. A feature adds its handlers here; this step registers only
//! ping and the enrollment messages.

use std::collections::{HashMap, HashSet};

use labtether_protocol::{
    MSG_ENROLLMENT_APPROVED, MSG_ENROLLMENT_CHALLENGE, MSG_ENROLLMENT_REJECTED, Message,
    is_known_message_type,
};

use crate::agent::Agent;
use crate::outbox::Outbox;

/// What the session does after a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// Close this socket and connect again (after enrollment approval).
    Reconnect,
}

/// What a handler can use.
pub struct Context<'a> {
    pub agent: &'a Agent,
    pub outbox: &'a Outbox,
}

pub type Handler = fn(&Message, &Context<'_>) -> Flow;

/// Handlers by message type.
pub struct Registry {
    handlers: HashMap<&'static str, Handler>,
    logged: HashSet<String>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            logged: HashSet::new(),
        }
    }

    pub fn register(&mut self, message_type: &'static str, handler: Handler) {
        self.handlers.insert(message_type, handler);
    }

    /// Runs the handler for `message`. A socket without a token accepts only
    /// the enrollment messages (Go's `inboundMessageAllowed`). A type with no
    /// handler is ignored and logged once at debug level.
    pub fn dispatch(&mut self, message: &Message, context: &Context<'_>) -> Flow {
        let kind = message.r#type.as_str();
        if context.outbox.is_pending_enrollment() && !allowed_while_pending(kind) {
            log::debug!("ignored {kind:?} on a pending enrollment socket");
            return Flow::Continue;
        }
        if let Some(handler) = self.handlers.get(kind) {
            return handler(message, context);
        }
        if self.logged.len() < 256 && self.logged.insert(kind.to_owned()) {
            if is_known_message_type(kind) {
                log::debug!("no handler for {kind:?} in this agent; ignored");
            } else {
                log::debug!("unknown message type {kind:?}; ignored");
            }
        }
        Flow::Continue
    }

    /// Message types already logged as ignored (for tests).
    pub fn ignored_types(&self) -> impl Iterator<Item = &str> {
        self.logged.iter().map(String::as_str)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

fn allowed_while_pending(kind: &str) -> bool {
    matches!(
        kind,
        MSG_ENROLLMENT_CHALLENGE | MSG_ENROLLMENT_APPROVED | MSG_ENROLLMENT_REJECTED
    )
}
