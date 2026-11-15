//! One open connection: a writer task that owns the socket's send side and
//! pings every 25 s, and a read loop that closes the connection when no pong
//! arrives within 60 s (Go's `pingLoop`, read deadline and `receiveLoop`).

use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use labtether_protocol::Message;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval, interval_at, sleep_until};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as Frame;

use crate::agent::Agent;
use crate::connection::Connection;
use crate::dispatch::{Context, Flow};
use crate::handlers;
use crate::net::HubStream;
use crate::outbox::{Outbox, Outgoing, SendError};

pub(crate) type Sink = SplitSink<WebSocketStream<HubStream>, Frame>;

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The agent is stopping.
    Shutdown,
    /// The Hub closed the socket or the read failed.
    Closed,
    /// No pong (or other frame that resets the deadline) in time.
    MissedPong,
    /// A frame could not be written in time, or the writer stopped.
    WriteFailed,
    /// A message from the Hub was not valid JSON.
    BadMessage,
    /// Enrollment was approved; connect again with the new token.
    Reconnect,
}

async fn send_frame(sink: &mut Sink, frame: Frame, limit: Duration) -> bool {
    matches!(
        tokio::time::timeout(limit, sink.send(frame)).await,
        Ok(Ok(()))
    )
}

/// Owns the send side: queued messages, then pings on a fixed interval.
pub(crate) async fn writer(
    mut sink: Sink,
    mut queue: mpsc::Receiver<Outgoing>,
    ping_every: Duration,
    write_timeout: Duration,
) {
    let mut ping = interval_at(Instant::now() + ping_every, ping_every);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            item = queue.recv() => match item {
                Some(Outgoing::Text(text)) => {
                    if !send_frame(&mut sink, Frame::text(text), write_timeout).await {
                        return;
                    }
                }
                Some(Outgoing::Close) | None => {
                    let _ = send_frame(&mut sink, Frame::Close(None), write_timeout).await;
                    return;
                }
            },
            _ = ping.tick() => {
                if !send_frame(&mut sink, Frame::Ping(Default::default()), write_timeout).await {
                    log::warn!("ping send failed");
                    return;
                }
            }
        }
    }
}

/// Queues one heartbeat. A full queue drops it; the next one follows.
fn send_heartbeat(agent: &Agent, outbox: &Outbox) {
    let Some(message) = agent.heartbeat.message(&agent.identity.snapshot()) else {
        return;
    };
    match outbox.send(&message) {
        Ok(()) => {}
        Err(SendError::Full) => log::warn!("heartbeat dropped: the send queue is full"),
        Err(error) => log::debug!("heartbeat not sent: {error}"),
    }
}

fn handle_text(
    text: &str,
    registry: &mut crate::dispatch::Registry,
    context: &Context<'_>,
) -> Option<SessionEnd> {
    let message: Message = match serde_json::from_str(text) {
        Ok(message) => message,
        Err(_) => {
            log::warn!("receive error: a message from the Hub is not valid JSON");
            return Some(SessionEnd::BadMessage);
        }
    };
    match registry.dispatch(&message, context) {
        Flow::Continue => None,
        Flow::Reconnect => Some(SessionEnd::Reconnect),
    }
}

/// Runs one connection until it ends.
pub async fn run(
    agent: &Agent,
    connection: Connection,
    shutdown: &mut watch::Receiver<bool>,
) -> SessionEnd {
    let timing = &agent.timing;
    let (sink, mut stream) = connection.stream.split();
    let (outbox, queue) = Outbox::new(timing.send_queue, connection.pending_enrollment);
    let mut writer_task = tokio::spawn(writer(
        sink,
        queue,
        timing.ping_interval,
        timing.write_timeout,
    ));
    let mut registry = handlers::registry();
    let context = Context {
        agent,
        outbox: &outbox,
    };

    let deadline = sleep_until(Instant::now() + timing.read_deadline);
    tokio::pin!(deadline);
    let mut heartbeat = interval(agent.settings.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let end = loop {
        tokio::select! {
            frame = stream.next() => match frame {
                Some(Ok(Frame::Text(text))) => {
                    if let Some(end) = handle_text(text.as_str(), &mut registry, &context) {
                        break end;
                    }
                }
                Some(Ok(Frame::Binary(bytes))) => {
                    let text = String::from_utf8_lossy(&bytes);
                    if let Some(end) = handle_text(&text, &mut registry, &context) {
                        break end;
                    }
                }
                Some(Ok(Frame::Pong(_))) => deadline.as_mut().reset(Instant::now() + timing.read_deadline),
                Some(Ok(Frame::Ping(_) | Frame::Frame(_))) => {}
                Some(Ok(Frame::Close(_))) | None => break SessionEnd::Closed,
                Some(Err(error)) => {
                    log::warn!("receive error: {error}");
                    break SessionEnd::Closed;
                }
            },
            () = &mut deadline => {
                log::warn!("no pong from the Hub within {:?}; closing the connection", timing.read_deadline);
                break SessionEnd::MissedPong;
            }
            _ = heartbeat.tick(), if !outbox.is_pending_enrollment() => send_heartbeat(agent, &outbox),
            _ = &mut writer_task => break SessionEnd::WriteFailed,
            _ = shutdown.changed() => break SessionEnd::Shutdown,
        }
    };

    if !writer_task.is_finished() {
        outbox.close();
        if tokio::time::timeout(timing.write_timeout, &mut writer_task)
            .await
            .is_err()
        {
            writer_task.abort();
        }
    }
    end
}
