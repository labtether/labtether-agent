//! Reconnect behaviour against a stand-in Hub, with the short test timing:
//! backoff 50 ms doubling to 400 ms, a 2 s wait after three refused
//! credentials, ping every 100 ms and a 600 ms pong deadline.

mod common;

use std::time::Duration;

use common::setup::{TestDir, fast_timing, settings, start, write};
use common::{Event, Hub};
use tokio::time::Instant;

const WAIT: Duration = Duration::from_secs(10);

fn agent_dir(name: &str, token: &str) -> TestDir {
    let dir = TestDir::new(name);
    write(&dir.path("agent-token"), token);
    dir
}

// Fault: after the Hub drops the socket (restart, network change) the agent
// stays offline instead of connecting again.
#[tokio::test]
async fn dropped_connection_reconnects() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    let dir = agent_dir("drop", "agent-token");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    hub.wait_connected(WAIT).await;
    hub.wait_message("heartbeat", WAIT).await;
    // Longer than min_stable_session (1 s in the test timing), so the drop
    // ends a stable session and the backoff starts from the base again.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    hub.drop_connections();
    hub.wait_for(WAIT, |e| matches!(e, Event::Closed { .. }).then_some(()))
        .await;
    let dropped_at = Instant::now();
    hub.wait_connected(Duration::from_secs(3)).await;
    assert!(
        dropped_at.elapsed() < Duration::from_millis(500),
        "a stable session that drops reconnects at once"
    );
    // A fresh heartbeat follows on the new connection.
    hub.wait_message("heartbeat", WAIT).await;
    running.stop().await;
}

// Fault: a half-open connection (Hub gone, no FIN) is never noticed, so the
// agent looks connected while the Hub shows it offline.
#[tokio::test]
async fn missed_pong_closes_the_connection() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    hub.behaviour().stall = true;
    let dir = agent_dir("pong", "agent-token");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    hub.wait_connected(WAIT).await;
    let first = Instant::now();
    hub.wait_connected(Duration::from_secs(5)).await;
    let gap = first.elapsed();
    assert!(
        gap >= Duration::from_millis(550),
        "closed only after the pong deadline, got {gap:?}"
    );
    assert!(
        gap < Duration::from_secs(3),
        "closed soon after the pong deadline, got {gap:?}"
    );
    hub.behaviour().stall = false;
    hub.drop_connections();
    running.stop().await;
}

// Fault: a revoked agent hammers the Hub, or never backs off to the long
// wait after the third refusal in a row.
#[tokio::test]
async fn repeated_refused_credentials_lead_to_the_long_wait() {
    let mut hub = Hub::start(None).await;
    let dir = agent_dir("auth", "revoked-token");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    let mut times = Vec::new();
    while times.len() < 4 {
        hub.wait_for(WAIT, |e| matches!(e, Event::Refused { .. }).then_some(()))
            .await;
        times.push(Instant::now());
    }
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps[0] < Duration::from_millis(500),
        "first retry is short: {gaps:?}"
    );
    assert!(
        gaps[1] < Duration::from_millis(500),
        "second retry is short: {gaps:?}"
    );
    assert!(
        gaps[1] >= gaps[0].saturating_sub(Duration::from_millis(20)),
        "the wait grows: {gaps:?}"
    );
    assert!(
        gaps[2] >= Duration::from_millis(1900),
        "the long wait follows the third refusal: {gaps:?}"
    );
    running.stop().await;
}

// Fault: a Hub that accepts the socket and closes it at once (two agents
// sharing one asset ID, a proxy that drops upgrades) gets a tight loop of TLS
// handshakes, because a successful connect resets the wait. Short sessions
// must back off like failed connects: 50 ms doubling to 400 ms here.
#[tokio::test]
async fn sessions_closed_at_once_back_off_instead_of_looping() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    hub.behaviour().close_at_once = true;
    let dir = agent_dir("storm", "agent-token");
    let running = start(settings(&dir, &hub.ws_url(), &[]), fast_timing())
        .await
        .unwrap();
    let mut times = vec![];
    let window = Instant::now();
    while let Some(event) = hub.next_event(Duration::from_millis(500)).await {
        if matches!(event, Event::Connected { .. }) {
            times.push(Instant::now());
        }
        if window.elapsed() > Duration::from_secs(3) {
            break;
        }
    }
    running.stop().await;
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    // The waits 50, 100, 200, then 400 ms (plus up to a quarter of jitter)
    // allow about 10 connections in 3 s; a tight loop makes hundreds.
    assert!(
        (4..=14).contains(&times.len()),
        "{} connections in 3 s: {gaps:?}",
        times.len()
    );
    assert!(
        gaps.iter().all(|gap| *gap >= Duration::from_millis(45)),
        "every reconnect waits: {gaps:?}"
    );
    assert!(
        gaps[3..]
            .iter()
            .all(|gap| *gap >= Duration::from_millis(350)),
        "the wait grows to the cap: {gaps:?}"
    );
}
