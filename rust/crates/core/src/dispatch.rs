//! Incoming messages are handled through a registry keyed by message type,
//! in place of the Go agent's one dispatch function that takes every
//! manager. Every message passes the same two checks first, in Go's order
//! (`receiveLoop`): a socket without a token accepts only the enrollment
//! messages, then the token check of [`crate::authorize`]. Only then is the
//! handler looked up, so a feature added later inherits both checks.
//!
//! Two kinds of handler: `core`'s own (ping, enrollment, `config.update`)
//! run inline on the read loop because they are quick; feature requests
//! run on a bounded set of worker threads (see [`crate::workers`]).

use std::collections::{HashMap, HashSet};

use labtether_protocol::{
    MSG_ENROLLMENT_APPROVED, MSG_ENROLLMENT_CHALLENGE, MSG_ENROLLMENT_REJECTED, Message,
    is_known_message_type,
};

use crate::agent::Agent;
use crate::authorize;
use crate::features::Work;
use crate::outbox::Outbox;

/// What the session does after a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// Close this socket and connect again (after enrollment approval).
    Reconnect,
    /// Close this socket: a request found every handler slot taken.
    Close,
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
    work: HashMap<&'static str, Work>,
    logged: HashSet<String>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            work: HashMap::new(),
            logged: HashSet::new(),
        }
    }

    pub fn register(&mut self, message_type: &'static str, handler: Handler) {
        self.handlers.insert(message_type, handler);
    }

    pub fn register_work(&mut self, message_type: &'static str, work: Work) {
        self.work.insert(message_type, work);
    }

    /// Checks `message` and runs its handler. A type with no handler is
    /// ignored and logged once at debug level.
    pub fn dispatch(&mut self, message: &Message, context: &Context<'_>) -> Flow {
        let kind = message.r#type.as_str();
        if context.outbox.is_pending_enrollment() && !allowed_while_pending(kind) {
            log::debug!("ignored {kind:?} on a pending enrollment socket");
            return Flow::Continue;
        }
        let required = authorize::required_for(kind);
        if !required.is_empty() {
            let token = context.agent.identity.snapshot().token;
            if !authorize::allows(token.as_ref().map(|t| t.expose()), required) {
                log::warn!("rejected {kind}: token lacks required capability");
                return Flow::Continue;
            }
        }
        if let Some(handler) = self.handlers.get(kind) {
            return handler(message, context);
        }
        if let Some(work) = self.work.get(kind) {
            return start_work(kind, work, message, context);
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

/// Runs `work` on a worker and queues its reply on this connection. A
/// handler whose connection closed before a worker picked it up does not
/// run (Go checks the sender's context the same way).
fn start_work(kind: &str, work: &Work, message: &Message, context: &Context<'_>) -> Flow {
    let work = work.clone();
    let message = message.clone();
    let outbox = context.outbox.clone();
    let started = context.agent.workers.try_spawn(kind, move || {
        if outbox.is_closed() {
            return;
        }
        if let Some(reply) = work(&message)
            && let Err(error) = outbox.send(&reply)
        {
            log::warn!(
                "failed to send {} for request {}: {error}",
                reply.r#type,
                reply.id
            );
        }
    });
    if started {
        return Flow::Continue;
    }
    log::warn!(
        "{kind}: {} requests are already running; closing the connection",
        context.agent.workers.limit()
    );
    Flow::Close
}

fn allowed_while_pending(kind: &str) -> bool {
    matches!(
        kind,
        MSG_ENROLLMENT_CHALLENGE | MSG_ENROLLMENT_APPROVED | MSG_ENROLLMENT_REJECTED
    )
}
