//! Where request handlers run: on the runtime's blocking threads, at most
//! `limit` at a time, so reading `/proc` or waiting on a slow `statfs` never
//! holds up the connection's read loop, its pings or the heartbeat.
//!
//! The bound copies Go's `receiveLoop`: one pool of 20 slots for the life of
//! the agent, shared by every connection. A request that finds every slot
//! taken makes the Go agent close the connection it came on
//! (`launchConnectionHandler` calls `sender.Close()`), and so does this one.
//! A handler keeps its slot until it returns, even after its connection is
//! gone, as in Go; a handler whose connection closed before it started does
//! not run.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use tokio::sync::Semaphore;

/// The Go agent's `maxConcurrentHandlers`.
pub const GO_HANDLER_LIMIT: usize = 20;

/// A bounded set of request handler slots.
#[derive(Debug, Clone)]
pub struct Workers {
    slots: Arc<Semaphore>,
    limit: usize,
}

impl Workers {
    pub fn new(limit: usize) -> Self {
        let limit = limit.max(1);
        Self {
            slots: Arc::new(Semaphore::new(limit)),
            limit,
        }
    }

    /// Starts `job` on a blocking thread when a slot is free and returns
    /// true; returns false without running it when all slots are taken.
    /// A panic in `job` is logged and frees the slot, as Go's `safeHandler`
    /// recovers.
    pub fn try_spawn(&self, name: &str, job: impl FnOnce() + Send + 'static) -> bool {
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            return false;
        };
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            if let Err(panic) = catch_unwind(AssertUnwindSafe(job)) {
                let text = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                log::error!("handler[{name}]: panic recovered: {text}");
            }
        });
        true
    }

    /// Handlers running now.
    pub fn running(&self) -> usize {
        self.limit - self.slots.available_permits()
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}
