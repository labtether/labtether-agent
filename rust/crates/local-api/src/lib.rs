//! The agent's local HTTP API, ported from the Go agent's local server
//! (`internal/agentcore/runtime.go`, `local_status.go`, `metrics.go` and
//! `internal/servicehttp`). The macOS and Windows apps start the agent as a
//! child process and poll `GET /agent/status` here.
//!
//! Pages, as in Go: `/agent/status`, `/agent/info`, `/agent/telemetry` and
//! `/metrics` need the bearer token when one is set; `/healthz`, `/readyz`
//! and `/version` never do. The status body follows the protocol repo's
//! local agent contract (`localagent/status.v1.schema.json`).
//!
//! The agent's state comes through [`Source`], a read-only view; `core`
//! knows nothing of HTTP. A local API problem is logged and never stops the
//! agent.

#![forbid(unsafe_code)]

pub mod body;
pub mod gojson;
pub mod gotime;
pub mod metrics;
pub mod router;
pub mod server;

use std::sync::Arc;

use labtether_agent_config::{LocalApiSettings, LocalAuth};
use labtether_agent_core::Agent;
use labtether_agent_core::status::StatusView;
use tokio::sync::watch;

use crate::body::LocalFacts;
use crate::router::Router;
pub use crate::server::Limits;

/// Where the pages read the agent's state.
pub trait Source: Send + Sync + 'static {
    fn status_view(&self) -> StatusView;
}

impl Source for Agent {
    fn status_view(&self) -> StatusView {
        Agent::status_view(self)
    }
}

/// Runs the local API until `shutdown` turns true. With the API off (a
/// non-loopback bind without a token, or a token file that cannot be read)
/// it logs Go's reason once and returns.
pub async fn run(
    name: &str,
    settings: &LocalApiSettings,
    source: Arc<dyn Source>,
    shutdown: watch::Receiver<bool>,
) {
    run_with(name, settings, source, Limits::default(), shutdown).await;
}

/// [`run`] with other limits (tests use short ones).
pub async fn run_with(
    name: &str,
    settings: &LocalApiSettings,
    source: Arc<dyn Source>,
    limits: Limits,
    shutdown: watch::Receiver<bool>,
) {
    let token = match &settings.auth {
        LocalAuth::Off(reason) => {
            log::warn!("{name}: local API is off: {reason}");
            return;
        }
        LocalAuth::Open { remote: true } => {
            log::warn!(
                "{name}: WARNING: non-loopback local API binding is unauthenticated (LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED=true)"
            );
            None
        }
        LocalAuth::Open { remote: false } => None,
        LocalAuth::Token(token) => Some(token.clone()),
    };
    let local = LocalFacts {
        port: settings.port.clone(),
        bind_address: settings.bind_address.clone(),
        auth_enabled: settings.auth_enabled(),
    };
    let make = |listening_since| Router {
        name: name.to_owned(),
        token: token.clone(),
        local: local.clone(),
        app_version: settings.app_version.clone(),
        listening_since,
        source: source.clone(),
    };
    server::serve(
        name,
        &settings.bind_address,
        &settings.port,
        limits,
        make,
        shutdown,
    )
    .await;
}
