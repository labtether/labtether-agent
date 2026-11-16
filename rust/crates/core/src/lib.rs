//! The LabTether Rust agent's connection to the Hub: device key, TLS trust,
//! enrollment, the WebSocket, reconnect, the token check and dispatch of
//! Hub messages, bounded request workers, producers that send on their own,
//! heartbeat, telemetry and the Hub's interval changes. Features (the device pages) live in the
//! `labtether-agent-capabilities` crate and reach this one as a
//! [`Features`] value.
//!
//! Ported from the Go agent in `internal/agentcore`; see `rust/README.md`.

#![forbid(unsafe_code)]

mod agent;
pub mod alerts;
pub mod authorize;
pub mod backoff;
pub mod connection;
pub mod credential;
mod der;
pub mod dispatch;
pub mod enroll;
mod features;
mod flow;
mod fsutil;
mod handlers;
pub mod heartbeat;
pub mod identity;
pub mod intervals;
pub mod link_status;
mod net;
pub mod offers;
pub mod outbox;
mod post;
pub mod producers;
mod reconnect;
mod session;
pub mod state;
pub mod status;
mod telemetry;
pub mod telemetry_buffer;
pub mod timing;
pub mod tls;
pub mod workers;

pub use agent::{Agent, StartError};
pub use features::{Advertised, Connectors, Features, Work};
pub use producers::{HubSender, OnStop, Producer, Stop};
pub use timing::Timing;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_telemetry;
