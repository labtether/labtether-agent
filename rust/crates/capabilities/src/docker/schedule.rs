//! The collector's timers and wake-ups: Go's `runDiscoveryManager`
//! (`collector.go`) and `runStats` (`collector_stats.go`).
//!
//! Discovery: a full inventory at start, a container round every
//! discovery interval, a forced full inventory every full-reconcile
//! period (ten intervals, 5 to 30 min), and a round soon after a Docker
//! event (350 ms after a container start, stop, die, destroy, create or
//! rename; 1.2 s after anything else, and after each timer). Every new
//! wake-up restarts that short wait, so a burst of events gives one round.
//! Stats: every half discovery interval (5 to 20 s), and after a
//! container event.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use labtether_agent_core::{HubSender, Stop};

use super::discovery::Inventory;
use super::engine::EngineApi;
use super::stats::{Sampler, poll_interval};

/// Go's `dockerDiscoveryDebounce` and `dockerDiscoveryImmediateDebounce`.
pub(crate) const DEBOUNCE: Duration = Duration::from_millis(1200);
pub(crate) const IMMEDIATE_DEBOUNCE: Duration = Duration::from_millis(350);
/// Go's buffer sizes for the two wake-up channels.
pub(crate) const DISCOVERY_QUEUE: usize = 32;
pub(crate) const STATS_QUEUE: usize = 4;

/// Go's `deriveDockerFullReconcileInterval`: ten intervals, 5 to 30 min.
pub(crate) fn full_reconcile_interval(interval: Duration) -> Duration {
    (interval * 10).clamp(Duration::from_secs(300), Duration::from_secs(1800))
}

/// Go's `dockerDiscoveryTrigger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Trigger {
    pub full: bool,
    pub immediate: bool,
}

/// What a wait ended with.
pub(crate) enum Woken<T> {
    Item(T),
    Timeout,
    Stopped,
}

/// A bounded wake-up queue: Go's buffered channel.
#[derive(Debug)]
pub(crate) struct Triggers<T> {
    queue: Mutex<VecDeque<T>>,
    changed: Condvar,
    capacity: usize,
}

impl<T> Triggers<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            changed: Condvar::new(),
            capacity,
        }
    }

    fn queue(&self) -> MutexGuard<'_, VecDeque<T>> {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Go's non-blocking send: dropped when the queue is full.
    pub fn push(&self, item: T) -> bool {
        let mut queue = self.queue();
        if queue.len() >= self.capacity {
            return false;
        }
        queue.push_back(item);
        self.changed.notify_all();
        true
    }

    /// Go's rule for a full inventory request on a full queue: the oldest
    /// waiting item makes room for it.
    pub fn push_or_replace(&self, item: T) {
        let mut queue = self.queue();
        if queue.len() >= self.capacity {
            queue.pop_front();
        }
        queue.push_back(item);
        self.changed.notify_all();
    }

    /// Wakes a waiter so it sees the stop.
    pub fn wake(&self) {
        let _queue = self.queue();
        self.changed.notify_all();
    }

    /// The next item, waiting until `deadline` (or for ever) or the stop.
    pub fn wait(&self, deadline: Option<Instant>, stop: &Stop) -> Woken<T> {
        let mut queue = self.queue();
        loop {
            if stop.is_stopped() {
                return Woken::Stopped;
            }
            if let Some(item) = queue.pop_front() {
                return Woken::Item(item);
            }
            let now = Instant::now();
            queue = match deadline {
                Some(deadline) if now >= deadline => return Woken::Timeout,
                Some(deadline) => self
                    .changed
                    .wait_timeout(queue, deadline - now)
                    .map_or_else(|poisoned| poisoned.into_inner().0, |(queue, _)| queue),
                None => self
                    .changed
                    .wait(queue)
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            };
        }
    }
}

/// Go's `discoveryTriggerCh` send (`queueDiscoveryTrigger`).
pub(crate) fn queue_discovery(triggers: &Triggers<Trigger>, trigger: Trigger) {
    if !triggers.push(trigger) && trigger.full {
        triggers.push_or_replace(trigger);
    }
}

/// Go's `time.Ticker`: fires every `period` from its start; a tick missed
/// while busy fires once, at once, and the next keeps the cadence.
#[derive(Debug)]
pub(crate) struct Ticker {
    period: Duration,
    pub next: Instant,
}

impl Ticker {
    pub fn new(period: Duration, now: Instant) -> Self {
        Self {
            period,
            next: now + period,
        }
    }

    pub fn due(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        while self.next <= now {
            self.next += self.period;
        }
        true
    }
}

/// The discovery thread: Go's `runDiscoveryManager`.
pub(crate) fn run_discovery(
    inventory: &Inventory,
    api: &dyn EngineApi,
    sender: &dyn HubSender,
    stop: &Stop,
    triggers: &Triggers<Trigger>,
    interval: Duration,
) {
    let start = Instant::now();
    let mut cheap = Ticker::new(interval, start);
    let mut full = Ticker::new(full_reconcile_interval(interval), start);
    let (mut pending_full, mut force, mut pending_container) = (true, true, false);
    let mut debounce = Some(start);
    loop {
        let now = Instant::now();
        let woken = if cheap.due(now) {
            Woken::Item(Trigger {
                full: false,
                immediate: false,
            })
        } else if full.due(now) {
            force = true;
            Woken::Item(Trigger {
                full: true,
                immediate: false,
            })
        } else if debounce.is_some_and(|at| now >= at) {
            Woken::Timeout
        } else {
            let wake = [Some(cheap.next), Some(full.next), debounce]
                .into_iter()
                .flatten()
                .min();
            match triggers.wait(wake, stop) {
                Woken::Timeout => continue,
                other => other,
            }
        };
        match woken {
            Woken::Stopped => return,
            Woken::Item(trigger) => {
                if trigger.full {
                    pending_full = true;
                } else {
                    pending_container = true;
                }
                let delay = if trigger.immediate {
                    IMMEDIATE_DEBOUNCE
                } else {
                    DEBOUNCE
                };
                debounce = Some(Instant::now() + delay);
            }
            Woken::Timeout => {
                debounce = None;
                if pending_full {
                    (pending_full, pending_container) = (false, false);
                    if let Err(error) = inventory.refresh_full(api, sender, force) {
                        log::info!("docker: full discovery refresh failed: {error}");
                    }
                    force = false;
                } else if pending_container {
                    pending_container = false;
                    if let Err(error) = inventory.refresh_delta(api, sender) {
                        log::info!("docker: container delta refresh failed: {error}");
                    }
                }
            }
        }
        if stop.is_stopped() {
            return;
        }
    }
}

/// The stats thread: Go's `runStats`.
pub(crate) fn run_stats(
    inventory: &Inventory,
    api: &dyn EngineApi,
    sender: &dyn HubSender,
    stop: &Stop,
    triggers: &Triggers<()>,
    interval: Duration,
) {
    let mut sampler = Sampler::new(interval);
    let mut ticker = Ticker::new(poll_interval(interval), Instant::now());
    loop {
        if !ticker.due(Instant::now()) {
            match triggers.wait(Some(ticker.next), stop) {
                Woken::Stopped => return,
                Woken::Timeout => continue,
                Woken::Item(()) => {}
            }
        }
        sampler.tick(api, sender, &inventory.running(), &Instant::now);
        if stop.is_stopped() {
            return;
        }
    }
}
