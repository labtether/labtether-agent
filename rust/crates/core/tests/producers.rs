//! A feature that sends messages the Hub did not ask for (a producer),
//! against the stand-in Hub: Go's `LogManager` sends through the transport
//! and waits until each frame is written, and gets an error when no
//! connection is open. The producer here is a made-up one the test steers.

mod common;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, Instant};

use common::setup::{TestDir, fast_timing, settings, start_with, write};
use common::{Event, Hub};
use labtether_agent_core::outbox::SendError;
use labtether_agent_core::{Features, HubSender, Stop};
use labtether_protocol::{DiskListData, DiskListedData, MSG_DISK_LIST, MSG_DISK_LISTED, Message};
use serde_json::{Value, json};
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(10);
const KIND: &str = "test.produced";

enum Order {
    /// Once connected, send messages `from..to`, each padded to `pad` bytes.
    Send { from: u64, to: u64, pad: usize },
    /// Once not connected, send messages `from..to`.
    SendOffline { from: u64, to: u64 },
    /// Once connected, send padded messages from `from` on until one fails
    /// (300 at most).
    UntilError { from: u64, pad: usize },
}

/// Waits up to 5 s until `connected()` is `want`.
fn wait_until(sender: &dyn HubSender, stop: &Stop, want: bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while sender.connected() != want
        && Instant::now() < deadline
        && !stop.wait(Duration::from_millis(10))
    {}
}

/// What one send gave, and how long it took.
#[derive(Debug)]
struct Outcome {
    seq: u64,
    result: Result<(), SendError>,
    took: Duration,
}

fn message(seq: u64, pad: usize) -> Message {
    let data = json!({"seq": seq, "pad": "x".repeat(pad)});
    Message::with_data(KIND, "", &data).unwrap()
}

fn send(
    sender: &dyn HubSender,
    seq: u64,
    pad: usize,
    out: &mpsc::UnboundedSender<Outcome>,
) -> bool {
    let started = Instant::now();
    let result = sender.send(&message(seq, pad));
    let failed = result.is_err();
    let _ = out.send(Outcome {
        seq,
        result,
        took: started.elapsed(),
    });
    !failed
}

/// Features with one producer that follows the test's orders, and a
/// `disk.list` handler.
fn steered(
    returned: Arc<AtomicBool>,
) -> (
    Features,
    std_mpsc::Sender<Order>,
    mpsc::UnboundedReceiver<Outcome>,
) {
    let (orders, order_rx) = std_mpsc::channel::<Order>();
    let (out, outcomes) = mpsc::unbounded_channel();
    let order_rx = Mutex::new(order_rx);
    let mut features = Features::new();
    features.on_request(
        MSG_DISK_LIST,
        MSG_DISK_LISTED,
        |r: &DiskListData| r.request_id.as_str(),
        |request: DiskListData| DiskListedData {
            request_id: request.request_id,
            ..DiskListedData::default()
        },
    );
    features.on_start("steered", move |sender: &dyn HubSender, stop: &Stop| {
        let orders = order_rx.lock().unwrap();
        while !stop.is_stopped() {
            match orders.recv_timeout(Duration::from_millis(20)) {
                Ok(Order::Send { from, to, pad }) => {
                    wait_until(sender, stop, true);
                    for seq in from..to {
                        send(sender, seq, pad, &out);
                    }
                }
                Ok(Order::SendOffline { from, to }) => {
                    wait_until(sender, stop, false);
                    for seq in from..to {
                        send(sender, seq, 0, &out);
                    }
                }
                Ok(Order::UntilError { from, pad }) => {
                    wait_until(sender, stop, true);
                    let mut seq = from;
                    // At most 300, so a send that never fails cannot
                    // fill memory.
                    while seq < from + 300 && send(sender, seq, pad, &out) {
                        seq += 1;
                    }
                }
                Err(_) => {}
            }
        }
        returned.store(true, Ordering::SeqCst);
    });
    (features, orders, outcomes)
}

async fn start(
    hub: &Hub,
    name: &str,
    workers: usize,
    queue: usize,
    features: Features,
) -> (common::setup::Running, TestDir) {
    hub.behaviour().accepted_tokens.insert("agent-token".into());
    let dir = TestDir::new(name);
    write(&dir.path("agent-token"), "agent-token");
    let mut timing = fast_timing();
    timing.request_workers = workers;
    timing.send_queue = queue;
    timing.read_deadline = Duration::from_secs(5);
    let running = start_with(settings(&dir, &hub.ws_url(), &[]), timing, features)
        .await
        .unwrap();
    (running, dir)
}

/// Sequence numbers of produced messages the Hub reads in `limit`, and
/// whether a `kind` message came too.
async fn collect(
    hub: &mut Hub,
    limit: Duration,
    until: impl Fn(&[u64]) -> bool,
) -> (Vec<(usize, u64)>, Vec<Value>) {
    let (mut seqs, mut others) = (Vec::new(), Vec::new());
    let deadline = tokio::time::Instant::now() + limit;
    while !until(&seqs.iter().map(|(_, s)| *s).collect::<Vec<_>>()) {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match hub.next_event(left).await {
            Some(Event::Message { id, message }) if message["type"] == KIND => {
                seqs.push((id, message["data"]["seq"].as_u64().unwrap()));
            }
            Some(Event::Message { message, .. }) => others.push(message),
            Some(_) => {}
            None => break,
        }
    }
    (seqs, others)
}

// Faults: a producer's send does not wait for a slow socket and drops what
// does not fit the queue (Go's send waits, so a slow Hub still gets every
// message, in order); a producer runs on the read loop (no pong while it
// floods) or in a request worker slot (with one slot, the disk request
// finds it taken and the connection is closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_waits_for_a_slow_socket_and_leaves_the_read_loop_free() {
    let mut hub = Hub::start(None).await;
    // A slow Hub: the agent's socket fills and its writes wait.
    hub.behaviour().read_pause = Duration::from_millis(2);
    let (features, orders, mut outcomes) = steered(Arc::default());
    let (running, _dir) = start(&hub, "flood", 1, 64, features).await;
    hub.wait_connected(WAIT).await;
    orders
        .send(Order::Send {
            from: 0,
            to: 400,
            pad: 64 * 1024,
        })
        .unwrap();
    hub.send_to_agents(&json!({"type": "ping"}));
    hub.send_to_agents(&json!({"type": "disk.list", "data": {"request_id": "d1"}}));
    let (seqs, others) = collect(&mut hub, WAIT, |seqs| seqs.len() == 400).await;
    let got: Vec<u64> = seqs.iter().map(|(_, seq)| *seq).collect();
    assert_eq!(got, (0..400).collect::<Vec<_>>(), "lost or out of order");
    assert!(
        seqs.iter().all(|(id, _)| *id == seqs[0].0),
        "a reconnect happened"
    );
    for _ in 0..400 {
        assert_eq!(outcomes.recv().await.unwrap().result, Ok(()));
    }
    let mut others = others;
    let more = collect(&mut hub, Duration::from_secs(2), |_| false).await.1;
    others.extend(more);
    assert!(others.iter().any(|m| m["type"] == "pong"), "no pong");
    assert!(
        others.iter().any(|m| m["type"] == "disk.listed"),
        "no disk reply"
    );
    running.stop().await;
}

// Faults: on a Hub that stops reading, a send gives up at once with a full
// queue instead of waiting as Go does, or waits without end; or a message
// whose send failed is kept and sent on the next connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_send_waits_then_fails_and_is_never_resent() {
    let mut hub = Hub::start(None).await;
    hub.behaviour().stall = true;
    let (features, orders, mut outcomes) = steered(Arc::default());
    let (running, _dir) = start(&hub, "stall", 20, 64, features).await;
    hub.wait_connected(WAIT).await;
    orders
        .send(Order::UntilError {
            from: 0,
            pad: 1024 * 1024,
        })
        .unwrap();
    let mut failed = None;
    while failed.is_none() {
        let outcome = tokio::time::timeout(WAIT, outcomes.recv())
            .await
            .unwrap()
            .unwrap();
        match outcome.result {
            // This socket stalls; the next one need not, so a message
            // kept from it would arrive there.
            Ok(()) => hub.behaviour().stall = false,
            Err(error) => {
                assert_eq!(error, SendError::Closed, "gave up instead of waiting");
                // It waited for the write timeout (500 ms here), not longer.
                assert!(
                    outcome.took >= Duration::from_millis(300),
                    "took {:?}",
                    outcome.took
                );
                assert!(
                    outcome.took < Duration::from_secs(4),
                    "took {:?}",
                    outcome.took
                );
                failed = Some(outcome.seq);
            }
        }
    }
    let failed = failed.unwrap();
    if hub.behaviour().stall {
        // The first send failed: no healthy socket yet.
        hub.behaviour().stall = false;
        hub.drop_connections();
    }
    let deadline = tokio::time::Instant::now() + WAIT;
    // The next socket that is not stalled: one that sends a heartbeat.
    let fresh = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match hub.next_event(left).await.expect("no new connection") {
            Event::Message { id, message } if message["type"] == "heartbeat" => break id,
            Event::Message { message, .. } if message["type"] == KIND => {
                panic!("a produced message came after the stall: {message}")
            }
            _ => {}
        }
    };
    orders
        .send(Order::Send {
            from: 1000,
            to: 1001,
            pad: 0,
        })
        .unwrap();
    let (seqs, _) = collect(&mut hub, WAIT, |seqs| seqs.contains(&1000)).await;
    assert_eq!(
        seqs,
        [(fresh, 1000)],
        "message {failed} or another old one came again"
    );
    running.stop().await;
}

// Faults: with no connection open, a send waits for the next one or keeps
// the message for it (Go's send fails at once with "not connected"), or
// `connected` stays true.
#[tokio::test]
async fn offline_sends_fail_at_once_and_are_not_kept() {
    let mut hub = Hub::start(None).await;
    let (features, orders, mut outcomes) = steered(Arc::default());
    let (running, _dir) = start(&hub, "offline", 20, 64, features).await;
    hub.wait_connected(WAIT).await;
    hub.behaviour().refuse_upgrade = true;
    hub.drop_connections();
    hub.wait_for(WAIT, |e| matches!(e, Event::Closed { .. }).then_some(()))
        .await;
    orders.send(Order::SendOffline { from: 0, to: 3 }).unwrap();
    for _ in 0..3 {
        let outcome = tokio::time::timeout(WAIT, outcomes.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.result, Err(SendError::Closed));
        assert!(
            outcome.took < Duration::from_millis(500),
            "waited {:?}",
            outcome.took
        );
    }
    hub.behaviour().refuse_upgrade = false;
    hub.wait_connected(WAIT).await;
    orders
        .send(Order::Send {
            from: 10,
            to: 11,
            pad: 0,
        })
        .unwrap();
    let (seqs, _) = collect(&mut hub, WAIT, |seqs| seqs.contains(&10)).await;
    let got: Vec<u64> = seqs.iter().map(|(_, seq)| *seq).collect();
    assert_eq!(got, [10], "an offline message was kept");
    running.stop().await;
}

// Faults: stopping the agent does not tell its producers (the thread keeps
// going after the agent stopped), or stopping waits on them forever.
#[tokio::test]
async fn stopping_the_agent_stops_its_producers() {
    let hub = Hub::start(None).await;
    let returned = Arc::new(AtomicBool::new(false));
    let (features, _orders, _outcomes) = steered(returned.clone());
    let (running, _dir) = start(&hub, "stop", 20, 64, features).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!returned.load(Ordering::SeqCst));
    running.stop().await;
    assert!(returned.load(Ordering::SeqCst), "the producer still runs");
}
