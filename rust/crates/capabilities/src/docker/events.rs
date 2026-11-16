//! `docker.events`: Go's `runEventLoop`, `forwardEvent` and
//! `queueDiscoveryForEvent` (`events.go`). Every engine event is sent to
//! the Hub as it comes and wakes the discovery (and, for a container, the
//! stats) thread. While no connection is open the stream is not read; an
//! event that arrives then is dropped and the stream is opened again. A
//! stream that ends is opened again after 1 s, doubling to 30 s; an event
//! resets the wait.

use std::time::Duration;

use labtether_agent_core::{HubSender, Stop};
use labtether_protocol::{DockerEventActor, DockerEventData, MSG_DOCKER_EVENTS, Message};

use super::engine::{Blocking, EngineError};
use super::raw::Event;
use super::schedule::{Trigger, Triggers, queue_discovery};

/// Go's `eventReconnectMin`, `eventReconnectMax`, `eventDisconnectedPoll`.
pub(crate) const RECONNECT_MIN: Duration = Duration::from_secs(1);
pub(crate) const RECONNECT_MAX: Duration = Duration::from_secs(30);
pub(crate) const DISCONNECTED_POLL: Duration = Duration::from_secs(5);

/// Go's `queueDiscoveryForEvent`.
pub(crate) fn wake_for(event: &Event, discovery: &Triggers<Trigger>, stats: &Triggers<()>) {
    let kind = event.r#type.trim().to_lowercase();
    let action = event.action.trim().to_lowercase();
    match kind.as_str() {
        "container" => {
            let immediate = matches!(
                action.as_str(),
                "start" | "stop" | "die" | "destroy" | "create" | "rename"
            );
            queue_discovery(
                discovery,
                Trigger {
                    full: false,
                    immediate,
                },
            );
            stats.push(());
        }
        // Images, networks and volumes are read on the full inventory.
        "image" | "network" | "volume" => {
            queue_discovery(
                discovery,
                Trigger {
                    full: true,
                    immediate: false,
                },
            );
        }
        // Any other event may still mean something changed.
        _ => queue_discovery(
            discovery,
            Trigger {
                full: false,
                immediate: false,
            },
        ),
    }
}

/// Go's `forwardEvent`.
pub(crate) fn forward(sender: &dyn HubSender, event: Event) {
    if !sender.connected() {
        return;
    }
    let data = DockerEventData {
        host_id: sender.asset_id().trim().to_owned(),
        r#type: event.r#type,
        action: event.action,
        actor: DockerEventActor {
            id: event.actor.id,
            attributes: event.actor.attributes,
        },
        timestamp: event.time,
    };
    let sent = Message::with_data(MSG_DOCKER_EVENTS, "", &data)
        .map_err(|error| error.to_string())
        .and_then(|message| sender.send(&message).map_err(|error| error.to_string()));
    if let Err(error) = sent {
        log::info!("docker: failed to send event: {error}");
    }
}

/// How one stream ended.
enum End {
    Reconnect,
    Stopped,
}

fn read_stream(
    engine: &Blocking,
    sender: &dyn HubSender,
    discovery: &Triggers<Trigger>,
    stats: &Triggers<()>,
    backoff: &mut Duration,
) -> End {
    let mut stream = match engine.run(engine.socket.events()) {
        Ok(stream) => stream,
        Err(EngineError::Stopped) => return End::Stopped,
        Err(error) => {
            log::info!("docker: event stream error: {error}");
            return End::Reconnect;
        }
    };
    loop {
        match engine.run(stream.next()) {
            Ok(Some(event)) => {
                if !sender.connected() {
                    return End::Reconnect;
                }
                *backoff = RECONNECT_MIN;
                wake_for(&event, discovery, stats);
                forward(sender, event);
            }
            Ok(None) => {
                log::info!("docker: event stream error: EOF");
                return End::Reconnect;
            }
            Err(EngineError::Stopped) => return End::Stopped,
            Err(error) => {
                log::info!("docker: event stream error: {error}");
                return End::Reconnect;
            }
        }
    }
}

/// The event thread: Go's `runEventLoop`.
pub(crate) fn run(
    engine: &Blocking,
    sender: &dyn HubSender,
    stop: &Stop,
    discovery: &Triggers<Trigger>,
    stats: &Triggers<()>,
) {
    let mut backoff = RECONNECT_MIN;
    while !stop.is_stopped() {
        if !sender.connected() {
            if stop.wait(DISCONNECTED_POLL) {
                return;
            }
            continue;
        }
        if let End::Stopped = read_stream(engine, sender, discovery, stats, &mut backoff) {
            return;
        }
        if stop.is_stopped() {
            return;
        }
        log::info!("docker: event stream disconnected, reconnecting in {backoff:?}");
        if stop.wait(backoff) {
            return;
        }
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}
