//! The LabTether Rust agent's features, one module per device page. Each
//! module has a `register` function that adds its Hub request handlers to
//! a [`Features`] value (with [`Features::on_request`]) and says what the
//! heartbeat advertises for it (with [`Features::advertise`]). The binary
//! passes the result to `Agent::start_with`; `core` knows no feature.
//!
//! Adding a page: write `src/<page>.rs` with
//! `pub fn register(features: &mut Features, settings: &Settings)`, put
//! its platform reads in `labtether-agent-platform`, and add one line to
//! [`PAGES`]. The token check and the worker bound in `core` apply to it
//! without further code. `tests/advertised.rs` fails when a page's
//! advertisement and handlers do not match; add a row to its table when a
//! page brings a new `cap_*` value.

#![forbid(unsafe_code)]

mod disks;
mod network;
mod processes;

use labtether_agent_config::Settings;
use labtether_agent_core::Features;

/// One registration function per page, in no particular order.
pub const PAGES: &[fn(&mut Features, &Settings)] =
    &[disks::register, network::register, processes::register];

/// Every feature in this build.
pub fn all(settings: &Settings) -> Features {
    let mut features = Features::new();
    for register in PAGES {
        register(&mut features, settings);
    }
    features
}

#[cfg(test)]
mod tests;
