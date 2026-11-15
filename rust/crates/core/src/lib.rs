//! The LabTether Rust agent's connection to the Hub: device key, TLS trust,
//! enrollment, the WebSocket, reconnect, message dispatch, heartbeat,
//! telemetry and the Hub's interval changes.
//!
//! Ported from the Go agent in `internal/agentcore`; see `rust/README.md`.

#![forbid(unsafe_code)]

mod agent;
pub mod backoff;
pub mod connection;
pub mod credential;
mod der;
pub mod dispatch;
pub mod enroll;
mod flow;
mod fsutil;
mod handlers;
pub mod heartbeat;
pub mod identity;
pub mod intervals;
mod net;
pub mod outbox;
mod post;
mod reconnect;
mod session;
pub mod state;
mod telemetry;
pub mod telemetry_buffer;
pub mod timing;
pub mod tls;

pub use agent::{Agent, StartError};
pub use timing::Timing;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_telemetry;
