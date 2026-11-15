//! The LabTether Rust agent for Linux: reads its settings once, builds its
//! features, starts the Hub connection and stops cleanly on SIGTERM or
//! Ctrl-C.

#![forbid(unsafe_code)]

mod logger;

use std::process::ExitCode;

use labtether_agent_config::{ConfigWarning, Environment, HostFacts};
use labtether_agent_core::{Agent, Timing};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

/// Set at build time with `LABTETHER_AGENT_VERSION=...`; else the crate version.
const VERSION: &str = match option_env!("LABTETHER_AGENT_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// The kernel's host name, as Go's `os.Hostname` reads it on Linux.
fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .map(|name| name.trim().to_owned())
        .unwrap_or_default()
}

fn log_warning(warning: &ConfigWarning) {
    match warning {
        ConfigWarning::SettingsFile(error) => log::warn!("agent-config.json not used: {error}"),
        ConfigWarning::EnrollmentTokenFile { path, error } => {
            log::warn!(
                "cannot read the enrollment token file {}: {error}",
                path.display()
            )
        }
        ConfigWarning::UnknownLogLevel(raw) => {
            log::warn!("unknown LABTETHER_LOG_LEVEL {raw:?}; using info")
        }
    }
}

async fn wait_for_signal() {
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("labtether-agent-rs {VERSION}");
        return ExitCode::SUCCESS;
    }
    let host = HostFacts {
        hostname: hostname(),
        version: VERSION.to_owned(),
    };
    let loaded = match labtether_agent_config::load(&Environment::from_process(), &host) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("labtether-agent-rs: {error}");
            return ExitCode::FAILURE;
        }
    };
    logger::init(loaded.settings.log_level);
    loaded.warnings.iter().for_each(log_warning);
    if loaded.settings.allow_insecure_transport {
        log::warn!("insecure transport is allowed (LABTETHER_ALLOW_INSECURE_TRANSPORT=true)");
    }
    log::info!(
        "labtether-agent-rs {VERSION} starting as {}",
        loaded.settings.asset_id
    );

    let features = labtether_agent_capabilities::all(&loaded.settings);
    let agent = match Agent::start_with(loaded.settings, Timing::default(), features).await {
        Ok(agent) => agent,
        Err(error) => {
            log::error!("cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (shutdown, receiver) = watch::channel(false);
    let run = tokio::spawn(agent.run(receiver));
    wait_for_signal().await;
    log::info!("stopping");
    let _ = shutdown.send(true);
    let _ = run.await;
    ExitCode::SUCCESS
}
