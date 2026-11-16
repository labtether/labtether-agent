//! Settings for the local API and the parent-process watch, read once at
//! start. Ported from the Go agent's `runtime.go`
//! (`resolveAgentLocalBindAddress`, `resolveAgentLocalAuth`,
//! `isLoopbackBindAddress`), `config.go` (`AGENT_PORT`),
//! `servicehttp.go` (`APP_VERSION`) and
//! `cmd/labtether-agent/parent_lifetime.go` (`LABTETHER_PARENT_PID`).
//!
//! Go reads the local token when the local API starts, a moment after the
//! rest of its settings; the apps write the token file before they start
//! the agent, so reading it here once is the same.

use std::net::IpAddr;
use std::path::Path;

use crate::env::Environment;
use crate::files::{self, MAX_SECRET_FILE_BYTES};
use crate::secret::Secret;

/// Go's default `AGENT_PORT` for the agent binary (`cmd/labtether-agent`).
pub const DEFAULT_PORT: &str = "8090";
/// Go's default bind address.
pub const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1";

const ENV_BIND: &str = "LABTETHER_AGENT_LOCAL_BIND_ADDRESS";
const ENV_TOKEN: &str = "LABTETHER_AGENT_LOCAL_AUTH_TOKEN";
const ENV_TOKEN_FILE: &str = "LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE";
const ENV_ALLOW_UNAUTHENTICATED: &str = "LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED";

/// Who may call the local API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAuth {
    /// Every path except `/healthz`, `/readyz` and `/version` needs
    /// `Authorization: Bearer <token>`.
    Token(Secret),
    /// No token. `remote` is true when a non-loopback bind was allowed
    /// without one by `LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED=true`.
    Open { remote: bool },
    /// The local API stays off; the text is Go's reason, for the log.
    Off(String),
}

/// The local API's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalApiSettings {
    /// `AGENT_PORT` as text, as Go keeps it (the status page shows it).
    pub port: String,
    /// `LABTETHER_AGENT_LOCAL_BIND_ADDRESS`, trimmed, default `127.0.0.1`.
    pub bind_address: String,
    pub auth: LocalAuth,
    /// `APP_VERSION`, else `dev`: what Go's `/version` reports. Not the
    /// agent version.
    pub app_version: String,
}

impl LocalApiSettings {
    /// Go's `localAuthEnabled`: the API runs and needs a token.
    pub fn auth_enabled(&self) -> bool {
        matches!(self.auth, LocalAuth::Token(_))
    }
}

/// Go's `isLoopbackBindAddress`.
pub fn is_loopback_bind_address(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "" | "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    match normalized.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => ip
            .to_ipv4_mapped()
            .map_or(ip.is_loopback(), |v4| v4.is_loopback()),
        Err(_) => false,
    }
}

/// Go's `resolveAgentLocalAuth`: the token variable, then the token file,
/// then open on loopback, then open with the explicit allow variable, else
/// off.
fn auth(env: &Environment, bind_address: &str) -> LocalAuth {
    if let Some(token) = env.get(ENV_TOKEN).and_then(Secret::new) {
        return LocalAuth::Token(token);
    }
    if let Some(path) = env.get(ENV_TOKEN_FILE) {
        match files::read_trimmed(Path::new(path), MAX_SECRET_FILE_BYTES) {
            Ok(text) => {
                if let Some(token) = Secret::new(text) {
                    return LocalAuth::Token(token);
                }
            }
            Err(error) => {
                return LocalAuth::Off(format!("failed to load {ENV_TOKEN_FILE}: {error}"));
            }
        }
    }
    if is_loopback_bind_address(bind_address) {
        return LocalAuth::Open { remote: false };
    }
    if env.bool_or(ENV_ALLOW_UNAUTHENTICATED, false) {
        return LocalAuth::Open { remote: true };
    }
    LocalAuth::Off(format!(
        "non-loopback local API binding requires {ENV_TOKEN} or {ENV_ALLOW_UNAUTHENTICATED}=true"
    ))
}

/// Reads the local API settings.
pub fn load(env: &Environment) -> LocalApiSettings {
    let bind_address = env.get_or(ENV_BIND, DEFAULT_BIND_ADDRESS).to_owned();
    LocalApiSettings {
        port: env.get_or("AGENT_PORT", DEFAULT_PORT).to_owned(),
        auth: auth(env, &bind_address),
        bind_address,
        app_version: env
            .raw("APP_VERSION")
            .filter(|value| !value.is_empty())
            .unwrap_or("dev")
            .to_owned(),
    }
}

/// `LABTETHER_PARENT_PID`, parsed with Go's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentPid {
    /// Unset or blank: no watch.
    Unset,
    /// A positive process ID. The binary refuses its own.
    Pid(i32),
    /// Not a positive whole number. The agent refuses to start, as Go does.
    Invalid,
}

/// Go's `parseConfiguredParentPID` without the own-PID check, which needs
/// the process. Go's `strconv.Atoi` takes an optional sign and leading
/// zeros, as Rust's parser does. A value above the largest process ID the
/// system call takes is refused here; Go would pass it on truncated.
pub fn parent_pid(env: &Environment) -> ParentPid {
    match env.get("LABTETHER_PARENT_PID") {
        None => ParentPid::Unset,
        Some(raw) => match raw.parse::<i64>() {
            Ok(pid) if pid > 0 => i32::try_from(pid).map_or(ParentPid::Invalid, ParentPid::Pid),
            _ => ParentPid::Invalid,
        },
    }
}

/// Variables the macOS or Windows app sets that this agent does not use
/// (see `rust/README.md` for why each is safe to ignore for now).
pub const IGNORED_APP_VARIABLES: &[&str] = &[
    "LABTETHER_AUTO_UPDATE",
    "LABTETHER_OUTBOUND_ALLOW_LOOPBACK",
    // Read on Linux, where the Docker page sends the inventory.
    #[cfg(target_os = "macos")]
    "LABTETHER_DOCKER_ENABLED",
    #[cfg(target_os = "macos")]
    "LABTETHER_DOCKER_SOCKET",
    #[cfg(target_os = "macos")]
    "LABTETHER_DOCKER_DISCOVERY_INTERVAL",
    "LABTETHER_FILES_ROOT_MODE",
    // Read on Linux, where the logs page streams the system log.
    #[cfg(target_os = "macos")]
    "LABTETHER_LOG_STREAM_ENABLED",
    "LABTETHER_WEBRTC_ENABLED",
    "LABTETHER_WEBRTC_STUN_URL",
    "LABTETHER_WEBRTC_TURN_URL",
    "LABTETHER_WEBRTC_TURN_USER",
    "LABTETHER_WEBRTC_TURN_PASS_FILE",
    "LABTETHER_CAPTURE_FPS",
    "LABTETHER_SERVICES_DISCOVERY_DOCKER_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_PROXY_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_PROXY_TRAEFIK_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_PROXY_CADDY_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_PROXY_NPM_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_INCLUDE_LISTENING",
    "LABTETHER_SERVICES_DISCOVERY_PORT_SCAN_PORTS",
    "LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_ENABLED",
    "LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_CIDRS",
    "LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_PORTS",
    "LABTETHER_SERVICES_DISCOVERY_LAN_SCAN_MAX_HOSTS",
];

/// The ignored app variables that are set, for one debug line at start.
pub fn ignored_variables_set(env: &Environment) -> Vec<&'static str> {
    IGNORED_APP_VARIABLES
        .iter()
        .copied()
        .filter(|name| env.raw(name).is_some())
        .collect()
}
