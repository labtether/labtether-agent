//! Unit tests for the telemetry buffer and the heartbeat's metric keys.

use labtether_agent_platform::Sample;
use labtether_protocol::Message;

use crate::heartbeat::{HeartbeatTemplate, LinkStats};
use crate::outbox::{Outbox, Outgoing, SendError};
use crate::telemetry_buffer::TelemetryBuffer;

fn sample(cpu: f64) -> Sample {
    Sample {
        cpu_percent: cpu,
        ..Sample::default()
    }
}

fn drain_cpu(queue: &mut tokio::sync::mpsc::Receiver<Outgoing>) -> Vec<f64> {
    let mut out = Vec::new();
    while let Ok(Outgoing::Text(text)) = queue.try_recv() {
        let message: Message = serde_json::from_str(&text).unwrap();
        assert_eq!(message.r#type, "telemetry");
        let data: serde_json::Value = message.decode().unwrap();
        assert_eq!(data["asset_id"], "nas01");
        out.push(data["cpu_percent"].as_f64().unwrap());
    }
    out
}

// Fault: samples taken offline are lost, kept without limit, or replayed
// out of order; Go keeps the newest 60 and sends them oldest first.
#[test]
fn buffer_keeps_the_newest_samples_and_replays_them_in_order() {
    let mut buffer = TelemetryBuffer::new(60);
    for cpu in 1..=64 {
        buffer.push(sample(f64::from(cpu)));
    }
    assert_eq!(buffer.len(), 60);
    let (outbox, mut queue) = Outbox::new(64, false);
    let done = buffer.flush("nas01", &outbox);
    assert_eq!((done.sent, done.stopped), (60, None));
    let expected: Vec<f64> = (5..=64).map(f64::from).collect();
    assert_eq!(drain_cpu(&mut queue), expected);
    assert!(buffer.is_empty());
}

// Fault: replaying the buffer grows the connection's send queue past its
// bound, or drops what did not fit instead of keeping it for later.
#[test]
fn replay_never_overfills_the_send_queue_and_keeps_the_rest() {
    let mut buffer = TelemetryBuffer::new(60);
    for cpu in 1..=60 {
        buffer.push(sample(f64::from(cpu)));
    }
    let (outbox, mut queue) = Outbox::new(8, false);
    let done = buffer.flush("nas01", &outbox);
    assert_eq!((done.sent, done.stopped), (8, Some(SendError::Full)));
    assert_eq!(outbox.queued(), 8, "the queue holds no more than its bound");
    assert_eq!(buffer.len(), 52, "what did not fit is kept");
    assert_eq!(
        drain_cpu(&mut queue),
        (1..=8).map(f64::from).collect::<Vec<_>>()
    );
    buffer.flush("nas01", &outbox);
    assert_eq!(
        drain_cpu(&mut queue),
        (9..=16).map(f64::from).collect::<Vec<_>>()
    );
}

// Fault: a sample with a value JSON cannot hold (NaN, infinity) blocks every
// sample behind it, or is sent as null and stored as zero by the Hub.
#[test]
fn a_sample_that_cannot_be_encoded_is_dropped_alone() {
    let mut buffer = TelemetryBuffer::new(60);
    buffer.push(sample(f64::NAN));
    buffer.push(Sample {
        temp_celsius: Some(f64::INFINITY),
        ..sample(1.0)
    });
    buffer.push(Sample {
        net_rx_bytes_per_sec: f64::NEG_INFINITY,
        ..sample(2.0)
    });
    buffer.push(sample(21.0));
    let (outbox, mut queue) = Outbox::new(8, false);
    let done = buffer.flush("nas01", &outbox);
    assert_eq!((done.sent, done.discarded), (1, 3));
    assert_eq!(drain_cpu(&mut queue), vec![21.0]);
}

// Fault: the heartbeat's metric keys or number format differ from Go's, so
// the Hub (which reads these exact keys) shows no CPU, memory or disk.
#[test]
fn heartbeat_metrics_use_the_go_keys_and_two_decimals() {
    let template = HeartbeatTemplate::from_parts("agent", Default::default());
    let stats = LinkStats::default();
    let measured = Sample {
        cpu_percent: 12.346,
        memory_percent: 50.0,
        disk_percent: 79.567,
        net_rx_bytes_per_sec: 1024.0,
        net_tx_bytes_per_sec: 0.004,
        temp_celsius: None,
        ..Sample::default()
    };
    let meta = template.metadata(&measured, &stats);
    for (key, want) in [
        ("cpu_percent", "12.35"),
        ("cpu_used_percent", "12.35"),
        ("memory_percent", "50.00"),
        ("memory_used_percent", "50.00"),
        ("disk_percent", "79.57"),
        ("disk_used_percent", "79.57"),
        ("network_rx_bytes_per_sec", "1024.00"),
        ("network_tx_bytes_per_sec", "0.00"),
        ("agent_reconnect_count", "0"),
    ] {
        assert_eq!(meta.get(key).map(String::as_str), Some(want), "{key}");
    }
    assert!(
        !meta.contains_key("temp_celsius"),
        "no sensor: no temperature keys"
    );
    assert!(meta.contains_key("disk_root_available_bytes"));
    let warm = template.metadata(
        &Sample {
            temp_celsius: Some(41.5),
            ..measured
        },
        &stats,
    );
    assert_eq!(warm["temp_celsius"], "41.50");
    assert_eq!(warm["temperature_celsius"], "41.50");
}
