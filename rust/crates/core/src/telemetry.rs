//! The sampling and heartbeat loop, ported from Go's `collectLoop` and
//! `heartbeatLoop` (`runtime.go`).
//!
//! As in Go, the first sample is taken at start and the first heartbeat tick
//! follows it at once; then samples are taken every collect interval
//! (10 s) and the heartbeat ticks every heartbeat interval (20 s), whether
//! or not the Hub is connected. On each heartbeat tick, when connected, the
//! heartbeat goes out with the latest sample's metrics; then the latest
//! sample joins the telemetry buffer and the buffer is sent. Offline, the
//! sample only joins the buffer. On each connect a heartbeat goes out and
//! the buffer is sent.
//!
//! The loop runs on the agent's one runtime thread with one timer, set to
//! whichever of the two ticks comes first.

use std::time::Duration;

use labtether_agent_platform::{Sample, Sampler, SysPaths};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::agent::Agent;
use crate::intervals::Intervals;
use crate::outbox::{Outbox, SendError};
use crate::telemetry_buffer::TelemetryBuffer;

fn collect(sampler: &mut Sampler) -> Sample {
    let (sample, warning) = sampler.collect(std::time::Instant::now());
    if let Some(error) = warning {
        log::warn!(
            "collect warning: no temperature reading on this machine (logged once): {error}"
        );
    }
    sample
}

fn send_heartbeat(agent: &Agent, outbox: &Outbox, sample: &Sample) {
    let identity = agent.identity.snapshot();
    let Some(message) = agent.heartbeat.message(&identity, sample, &agent.stats) else {
        return;
    };
    match outbox.send(&message) {
        Ok(()) => {}
        Err(SendError::Full) => log::warn!("heartbeat dropped: the send queue is full"),
        Err(error) => log::debug!("heartbeat not sent: {error}"),
    }
}

fn flush(agent: &Agent, outbox: &Outbox, buffer: &mut TelemetryBuffer) {
    if buffer.is_empty() {
        return;
    }
    let asset_id = agent.identity.snapshot().asset_id;
    let done = buffer.flush(&asset_id, outbox);
    if let Some(error) = done.stopped {
        log::debug!("{} telemetry samples kept for later: {error}", buffer.len());
    }
}

/// The next tick after `due`, skipping ticks already missed (Go's ticker
/// drops them too).
fn next_tick(due: Instant, every: Duration, now: Instant) -> Instant {
    let next = due + every;
    if next <= now { now + every } else { next }
}

/// Runs until `shutdown` turns true.
pub(crate) async fn run(agent: &Agent, mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let mut sampler = Sampler::new(SysPaths::default());
    let mut buffer = TelemetryBuffer::new(agent.timing.telemetry_buffer);
    let mut link = agent.link.subscribe();
    let mut changes = agent.intervals.subscribe();
    let mut intervals: Intervals = *changes.borrow_and_update();

    let mut latest = collect(&mut sampler);
    let start = Instant::now();
    let (mut last_collect, mut last_heartbeat) = (start, start);
    let mut next_collect = start + intervals.collect;
    let mut next_heartbeat = start;
    let timer = sleep_until(start);
    tokio::pin!(timer);

    loop {
        timer.as_mut().reset(next_collect.min(next_heartbeat));
        tokio::select! {
            () = &mut timer => {
                let now = Instant::now();
                if now >= next_collect {
                    latest = collect(&mut sampler);
                    last_collect = now;
                    next_collect = next_tick(next_collect, intervals.collect, now);
                }
                if now >= next_heartbeat {
                    let outbox = link.borrow().clone();
                    if let Some(outbox) = &outbox {
                        send_heartbeat(agent, outbox, &latest);
                    }
                    buffer.push(latest);
                    if let Some(outbox) = &outbox {
                        flush(agent, outbox, &mut buffer);
                    }
                    last_heartbeat = now;
                    next_heartbeat = next_tick(next_heartbeat, intervals.heartbeat, now);
                }
            }
            Ok(()) = link.changed() => {
                let outbox = link.borrow_and_update().clone();
                if let Some(outbox) = outbox {
                    send_heartbeat(agent, &outbox, &latest);
                    flush(agent, &outbox, &mut buffer);
                }
            }
            Ok(()) = changes.changed() => {
                let now = Instant::now();
                let new = *changes.borrow_and_update();
                if new.collect != intervals.collect {
                    log::info!("collect interval updated to {:?}", new.collect);
                    next_collect = (last_collect + new.collect).max(now);
                }
                if new.heartbeat != intervals.heartbeat {
                    log::info!("heartbeat interval updated to {:?}", new.heartbeat);
                    next_heartbeat = (last_heartbeat + new.heartbeat).max(now);
                }
                intervals = new;
            }
            _ = shutdown.changed() => return,
        }
    }
}
