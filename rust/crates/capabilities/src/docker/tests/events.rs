//! What an engine event wakes, and the discovery queue's rules. What is
//! forwarded is compared with Go in `scenario.rs`.

use std::time::{Duration, Instant};

use labtether_agent_core::Stop;

use crate::docker::events::wake_for;
use crate::docker::raw::Event;
use crate::docker::schedule::{Trigger, Triggers, Woken, queue_discovery};

fn event(kind: &str, action: &str) -> Event {
    Event {
        r#type: kind.into(),
        action: action.into(),
        ..Event::default()
    }
}

fn drain(triggers: &Triggers<Trigger>) -> Vec<Trigger> {
    let stop = Stop::new();
    let mut out = Vec::new();
    while let Woken::Item(trigger) = triggers.wait(Some(Instant::now()), &stop) {
        out.push(trigger);
    }
    out
}

// Faults: a network, volume or image change wakes only a container round,
// so the Hub misses it until the next forced full inventory (5 min); a
// container start or stop waits the long 1.2 s instead of 350 ms, or an
// exec or health event waits the short one; a container event does not
// wake the stats; an unknown event wakes nothing (Go: Docker events are
// read as uppercase or padded alike).
#[test]
fn events_wake_discovery_and_stats_as_go() {
    let (discovery, stats) = (Triggers::new(32), Triggers::new(4));
    let quick = Trigger {
        full: false,
        immediate: true,
    };
    let slow = Trigger {
        full: false,
        immediate: false,
    };
    let full = Trigger {
        full: true,
        immediate: false,
    };
    for (kind, action, want, stat) in [
        ("container", "start", quick, true),
        (" Container ", "DIE", quick, true),
        ("container", "rename", quick, true),
        ("container", "exec_start: sh", slow, true),
        ("container", "health_status: healthy", slow, true),
        ("network", "connect", full, false),
        ("volume", "create", full, false),
        ("image", "tag", full, false),
        ("plugin", "enable", slow, false),
    ] {
        wake_for(&event(kind, action), &discovery, &stats);
        assert_eq!(drain(&discovery), [want], "{kind} {action}");
        let stop = Stop::new();
        let woke = matches!(stats.wait(Some(Instant::now()), &stop), Woken::Item(()));
        assert_eq!(woke, stat, "stats for {kind} {action}");
    }
}

// Fault: under a burst of events the queue drops a full-inventory request
// (Go: it then replaces the oldest waiting item), so a new network is
// missed; or the queue grows past Go's 32 (and the stats queue past 4).
#[test]
fn a_full_queue_keeps_a_full_inventory_request() {
    let triggers = Triggers::new(32);
    let slow = Trigger {
        full: false,
        immediate: false,
    };
    for _ in 0..40 {
        queue_discovery(&triggers, slow);
    }
    queue_discovery(
        &triggers,
        Trigger {
            full: true,
            immediate: false,
        },
    );
    let queued = drain(&triggers);
    assert_eq!(queued.len(), 32);
    assert!(queued.last().unwrap().full);
    let stats = Triggers::new(4);
    let kept = (0..10).filter(|_| stats.push(())).count();
    assert_eq!(kept, 4);
}

// Fault: a wait on the queue does not end when the agent stops (the
// thread outlives the stop).
#[test]
fn a_wait_ends_when_the_agent_stops() {
    let triggers = std::sync::Arc::new(Triggers::<Trigger>::new(4));
    let stop = Stop::new();
    let waker = std::sync::Arc::clone(&triggers);
    let _hook = stop.on_stop(move || waker.wake());
    let (done, ended) = std::sync::mpsc::channel();
    let (waiter, stopping) = (std::sync::Arc::clone(&triggers), stop.clone());
    // The wait runs on its own thread so a fault fails the test, not hangs it.
    std::thread::spawn(move || {
        let _ = done.send(matches!(waiter.wait(None, &stopping), Woken::Stopped));
    });
    std::thread::sleep(Duration::from_millis(100));
    stop.stop();
    let stopped = ended.recv_timeout(Duration::from_secs(5));
    assert_eq!(stopped, Ok(true), "the wait did not end with the stop");
}
