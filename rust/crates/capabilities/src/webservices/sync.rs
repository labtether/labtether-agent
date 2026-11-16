//! `webservice.sync`, the Services page's sync: Go's handler runs one
//! discovery cycle on a request worker (`command_handler.go`), waiting
//! first for a cycle in progress to end (the collector's lock), and sends
//! no reply. Here the worker asks the collector's thread for one cycle and
//! waits until that cycle has run, so it holds its worker slot as long as
//! Go's does; each request gets its own cycle, after the one in progress.
//! The periodic cycles keep their times. When the collector is not
//! running (it could not start, or the agent is stopping) the request
//! does nothing.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Instant;

use labtether_agent_core::{OnStop, Stop};

#[derive(Debug, Default)]
struct State {
    running: bool,
    /// Requests asked, cycles started for them, cycles finished for them.
    asked: u64,
    started: u64,
    served: u64,
}

/// What the collector's wait ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Woken {
    /// The deadline passed.
    Due,
    /// A sync cycle is wanted; run it, then call [`Requests::served`].
    Sync,
    Stopped,
}

/// The sync requests between the request workers and the collector.
#[derive(Debug, Default)]
pub(crate) struct Requests {
    state: Mutex<State>,
    changed: Condvar,
}

impl Requests {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A request worker's side: asks for one cycle and waits until it
    /// ran, or returns at once when the collector is not running.
    pub fn ask(&self) {
        let mut state = self.state();
        if !state.running {
            return;
        }
        state.asked += 1;
        let ticket = state.asked;
        self.changed.notify_all();
        while state.running && state.served < ticket {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// The collector takes requests while the returned guard lives and
    /// the agent runs.
    pub fn open(self: &Arc<Self>, stop: &Stop) -> Open {
        self.state().running = true;
        let requests = Arc::clone(self);
        let hook = stop.on_stop(move || requests.close());
        Open {
            requests: Arc::clone(self),
            _hook: hook,
        }
    }

    fn close(&self) {
        self.state().running = false;
        self.changed.notify_all();
    }

    /// The collector's wait: until `deadline`, a request, or the stop.
    pub fn wait(&self, deadline: Instant, stop: &Stop) -> Woken {
        let mut state = self.state();
        loop {
            if stop.is_stopped() || !state.running {
                return Woken::Stopped;
            }
            if state.started < state.asked {
                state.started += 1;
                return Woken::Sync;
            }
            let now = Instant::now();
            if now >= deadline {
                return Woken::Due;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .map_or_else(|poisoned| poisoned.into_inner().0, |(state, _)| state);
        }
    }

    /// One sync cycle has run.
    pub fn served(&self) {
        self.state().served += 1;
        self.changed.notify_all();
    }
}

/// While held, the collector takes sync requests; dropping it releases
/// every waiting request.
pub(crate) struct Open {
    requests: Arc<Requests>,
    _hook: OnStop,
}

impl Drop for Open {
    fn drop(&mut self) {
        self.requests.close();
    }
}
