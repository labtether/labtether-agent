//! The LabTether Rust agent's features, one module per device page. Each
//! module has a `register` function that adds its Hub request handlers to
//! a [`Features`] value (with [`Features::on_request`]); registering a
//! handler advertises the Hub's word for it (`cap_disks=list`, ...), and a
//! page adds only host keys such as `service_backend` itself (with
//! [`Features::advertise`]). The binary passes the result to
//! `Agent::start_with`; `core` knows no feature.
//!
//! A page registers its handler only where it answers: without `systemctl`
//! there is no services list, so the Hub does not offer it.
//!
//! Adding a page: write `src/<page>.rs` with
//! `pub fn register(features: &mut Features, settings: &Settings)`, put
//! its platform reads in `labtether-agent-platform`, and add one line to
//! [`PAGES`]. The token check and the worker bound in `core` apply to it
//! without further code. A request with no row in `core`'s `offers.rs`
//! cannot be registered: add the Hub's word there, and to the table in
//! `tests/advertised.rs`. A page that starts a program goes in
//! [`COMMAND_PAGES`] instead and is also given the [`Commands`] it must
//! start programs through. A page that sends messages the Hub did not ask
//! for adds a producer with [`Features::on_start`] (the logs page's live
//! stream).
//!
//! On macOS the agent is the monitoring edition the Mac App Store app
//! bundles (`agent_edition=monitoring`): it runs in the App Sandbox and
//! starts no program. Only the pages that work there are built in: disks
//! and network interfaces. The process list is Linux only (the sandbox
//! refuses `/bin/ps`, and macOS has no `/proc`); `tests/macos_pages.rs`
//! holds that line. Linux sends no edition: the Hub and the console show
//! none for an agent without the key.

#![forbid(unsafe_code)]

mod commands;
#[cfg(target_os = "linux")]
mod cron;
mod disks;
#[cfg(target_os = "linux")]
mod logs;
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
    logs::register,
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
    #[cfg(target_os = "macos")]
    features.monitoring_edition();
    features
}

#[cfg(test)]
mod tests;
