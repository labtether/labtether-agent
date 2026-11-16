//! One open connection: a writer task that owns the socket's send side and
//! pings every 25 s, and a read loop that closes the connection when no pong
//! arrives within 60 s (Go's `pingLoop`, read deadline and `receiveLoop`).
//! While a connection with a token is open, its send queue is shared with
//! the telemetry loop, which sends the heartbeat and telemetry.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use labtether_protocol::Message;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as Frame;

use crate::agent::Agent;
use crate::connection::Connection;
use crate::dispatch::{Context, Flow};
use crate::handlers;
use crate::heartbeat::LinkStats;
use crate::net::HubStream;
use crate::outbox::{Outbox, Outgoing};

pub(crate) type Sink = SplitSink<WebSocketStream<HubStream>, Frame>;

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The agent is stopping.
    Shutdown,
    /// The Hub closed the socket or the read failed.
    Closed,
    /// No pong in time. Only a pong resets the deadline, as in Go.
    MissedPong,
    /// A frame could not be written in time, or the writer stopped.
    WriteFailed,
    /// A message from the Hub was not valid JSON.
    BadMessage,
    /// Enrollment was approved; connect again with the new token.
    Reconnect,
    /// A request found every handler slot taken; Go closes the connection.
    Overloaded,
}

async fn send_frame(sink: &mut Sink, frame: Frame, limit: Duration) -> bool {
    matches!(
        tokio::time::timeout(limit, sink.send(frame)).await,
        Ok(Ok(()))
    )
}

/// Owns the send side: queued messages, then pings on a fixed interval.
/// Each message written counts in `stats.sent`.
pub(crate) async fn writer(
    mut sink: Sink,
    mut queue: mpsc::Receiver<Outgoing>,
    ping_every: Duration,
    write_timeout: Duration,
    stats: Arc<LinkStats>,
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
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                }
                // Not written when its sender has given up waiting.
                Some(Outgoing::Waited(text, waiter)) => {
                    if waiter.start() {
                        if !send_frame(&mut sink, Frame::text(text), write_timeout).await {
                            return;
                        }
                        stats.sent.fetch_add(1, Ordering::Relaxed);
                        waiter.written();
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
    context.agent.stats.received.fetch_add(1, Ordering::Relaxed);
    match registry.dispatch(&message, context) {
        Flow::Continue => None,
        Flow::Reconnect => Some(SessionEnd::Reconnect),
        Flow::Close => Some(SessionEnd::Overloaded),
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
    let (outbox, queue) = Outbox::new(
        timing.send_queue,
        connection.pending_enrollment,
        timing.write_timeout,
    );
    let mut writer_task = tokio::spawn(writer(
        sink,
        queue,
        timing.ping_interval,
        timing.write_timeout,
        agent.stats.clone(),
    ));
    if !connection.pending_enrollment {
        agent.link.send_replace(Some(outbox.clone()));
    }
    let mut registry = handlers::registry(&agent.features);
    let context = Context {
        agent,
        outbox: &outbox,
    };

    let deadline = sleep_until(Instant::now() + timing.read_deadline);
    tokio::pin!(deadline);

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
            _ = &mut writer_task => break SessionEnd::WriteFailed,
            _ = shutdown.changed() => break SessionEnd::Shutdown,
        }
    };

    agent.link.send_replace(None);
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
