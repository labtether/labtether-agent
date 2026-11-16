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
//! page brings a new `cap_*` value. A page that starts a program goes in
//! [`COMMAND_PAGES`] instead and is also given the [`Commands`] it must
//! start programs through.
//!
//! On macOS the agent is the monitoring edition the Mac App Store app
//! bundles: it runs in the App Sandbox and starts no program. Only the pages
//! that work there are built in: disks and network interfaces. The process
//! list is Linux only (the sandbox refuses `/bin/ps`, and macOS has no
//! `/proc`); `tests/macos_pages.rs` holds that line.

#![forbid(unsafe_code)]

mod commands;
#[cfg(target_os = "linux")]
mod cron;
mod disks;
mod network;
#[cfg(target_os = "linux")]
mod packages;
#[cfg(target_os = "linux")]
mod processes;
#[cfg(target_os = "linux")]
mod services;
#[cfg(target_os = "linux")]
mod users;

use labtether_agent_config::Settings;
use labtether_agent_core::Features;

pub use commands::Commands;

/// One registration function per page, in no particular order.
pub const PAGES: &[fn(&mut Features, &Settings)] = &[
    disks::register,
    network::register,
    #[cfg(target_os = "linux")]
    processes::register,
];

/// The pages that start programs, each given the command rules. Linux
/// only: the macOS edition starts no program.
#[cfg(target_os = "linux")]
pub const COMMAND_PAGES: &[fn(&mut Features, &Settings, &Commands)] = &[
    cron::register,
    packages::register,
    services::register,
    users::register,
];

/// Every feature in this build.
pub fn all(settings: &Settings, commands: &Commands) -> Features {
    let mut features = Features::new();
    for register in PAGES {
        register(&mut features, settings);
    }
    #[cfg(target_os = "linux")]
    for register in COMMAND_PAGES {
        register(&mut features, settings, commands);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = commands;
    features
}

#[cfg(test)]
mod tests;
