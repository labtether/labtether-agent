//! Features that send messages the Hub did not ask for, such as the log
//! stream. Go starts these as goroutines for the life of the agent, each
//! holding the transport as a `MessageSender` (`backends/log_handler.go`):
//! `Connected()`, `AssetID()` and a `Send` that waits until its frame is
//! written and fails when no connection is open.
//!
//! Here each producer runs on its own thread, started when the agent runs
//! and outside the request worker slots, so it never takes a slot from a
//! Hub request and never runs on the read loop. It sends through
//! [`HubSender`], which uses the connection open at the moment of the
//! call: a message is written on that connection or dropped, never kept
//! for a later one. When the agent stops, [`Stop`] tells every producer,
//! runs the hooks they set (to end a program they started) and the agent
//! waits a bounded time for them to return.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use labtether_protocol::Message;
use tokio::sync::oneshot;

use crate::agent::Agent;
use crate::outbox::SendError;

/// What a producer sends through: Go's `MessageSender`.
pub trait HubSender: Send + Sync {
    /// True while a connection with a token is open (Go's `Connected`).
    fn connected(&self) -> bool;
    /// The asset ID in use now (Go's `AssetID`).
    fn asset_id(&self) -> String;
    /// Sends `message` on the open connection and blocks until it is
    /// written; an error when no connection is open or it ends first.
    fn send(&self, message: &Message) -> Result<(), SendError>;
}

/// A producer: runs until it returns or [`Stop`] is set.
pub type Producer = Arc<dyn Fn(&dyn HubSender, &Stop) + Send + Sync>;

#[derive(Default)]
struct State {
    stopped: bool,
    next_hook: u64,
    hooks: Vec<(u64, Box<dyn FnOnce() + Send>)>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

/// The agent is stopping: Go's cancelled context for a producer.
#[derive(Clone, Default)]
pub struct Stop(Arc<Shared>);

impl std::fmt::Debug for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stop")
            .field("stopped", &self.is_stopped())
            .finish()
    }
}

impl Stop {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Sets the stop, wakes every waiter and runs the hooks once.
    pub fn stop(&self) {
        let hooks = {
            let mut state = self.state();
            if state.stopped {
                return;
            }
            state.stopped = true;
            std::mem::take(&mut state.hooks)
        };
        self.0.changed.notify_all();
        for (_, hook) in hooks {
            hook();
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.state().stopped
    }

    /// Waits up to `limit`; true when the stop was set (Go's
    /// `select` on `ctx.Done()` and `time.After`).
    pub fn wait(&self, limit: Duration) -> bool {
        let state = self.state();
        let (state, _) = self
            .0
            .changed
            .wait_timeout_while(state, limit, |state| !state.stopped)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.stopped
    }

    /// Runs `hook` when the stop is set, or now if it already is. Dropping
    /// the returned guard removes a hook that has not run.
    pub fn on_stop(&self, hook: impl FnOnce() + Send + 'static) -> OnStop {
        let mut state = self.state();
        if state.stopped {
            drop(state);
            hook();
            return OnStop(None);
        }
        let id = state.next_hook;
        state.next_hook += 1;
        state.hooks.push((id, Box::new(hook)));
        OnStop(Some((self.clone(), id)))
    }
}

/// Removes its hook when dropped.
#[must_use = "the hook is removed when this is dropped"]
pub struct OnStop(Option<(Stop, u64)>);

impl Drop for OnStop {
    fn drop(&mut self) {
        if let Some((stop, id)) = self.0.take() {
            stop.state().hooks.retain(|(hook, _)| *hook != id);
        }
    }
}

/// The agent's connections as a producer sees them.
struct Uplink(Arc<Agent>);

impl HubSender for Uplink {
    fn connected(&self) -> bool {
        self.0
            .link
            .borrow()
            .as_ref()
            .is_some_and(|outbox| !outbox.is_closed())
    }

    fn asset_id(&self) -> String {
        self.0.asset_id()
    }

    fn send(&self, message: &Message) -> Result<(), SendError> {
        // The connection open now; a reconnect while this waits does not
        // carry the message over.
        let outbox = self.0.link.borrow().clone();
        match outbox {
            Some(outbox) => outbox.send_and_wait(message),
            None => Err(SendError::Closed),
        }
    }
}

/// A running producer thread and the signal it sends when it returns.
pub(crate) struct Running {
    name: &'static str,
    done: oneshot::Receiver<()>,
}

/// Starts every producer of `agent` on its own thread.
pub(crate) fn start(agent: &Arc<Agent>, stop: &Stop) -> Vec<Running> {
    let mut running = Vec::new();
    for &(name, ref producer) in agent.features.producers() {
        let (finished, done) = oneshot::channel::<()>();
        let (producer, stop, uplink) = (producer.clone(), stop.clone(), Uplink(agent.clone()));
        let spawned = std::thread::Builder::new()
            .name(format!("producer-{name}"))
            .spawn(move || {
                let _finished = finished;
                if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    producer(&uplink, &stop);
                })) {
                    let text = panic
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_owned())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_default();
                    log::error!("{name}: panic recovered: {text}");
                }
            });
        match spawned {
            Ok(_) => running.push(Running { name, done }),
            Err(error) => log::error!("{name}: could not start: {error}"),
        }
    }
    running
}

/// Waits up to `limit` in all for the producers to return after the stop.
pub(crate) async fn join(running: Vec<Running>, limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    for producer in running {
        if tokio::time::timeout_at(deadline, producer.done)
            .await
            .is_err()
        {
            log::warn!("{}: still running {limit:?} after stop", producer.name);
        }
    }
}
