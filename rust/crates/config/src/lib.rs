//! Settings for the LabTether Rust agent.
//!
//! Ported from the Go agent's `LoadConfig` (`internal/agentcore/config.go`)
//! for the settings the connect step needs. Everything is read once into one
//! [`Settings`] value that is passed down; nothing reads the environment
//! later.
//!
//! Precedence, as in Go:
//!
//! - Hub-managed settings (`heartbeat_interval_sec`, `log_level`): the
//!   environment wins over `agent-config.json`, so an install-time choice is
//!   never replaced by a value saved from an earlier Hub push.
//! - Local-only TLS settings (`tls_ca_file`, `tls_skip_verify`): the file wins
//!   when it holds the key, because the local `settings set` command writes
//!   them there after install.

#![forbid(unsafe_code)]

mod env;
pub mod files;
mod secret;
mod settings_file;
pub mod urls;

use std::path::{Path, PathBuf};
use std::time::Duration;

pub use env::{Environment, parse_duration_or, parse_go_bool};
pub use secret::Secret;
pub use settings_file::SettingsFileError;
use urls::UrlKind;

/// Where the Go agent keeps its state on Linux.
pub const DEFAULT_STATE_DIR: &str = "/etc/labtether";
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(20);
const LOW_POWER_HEARTBEAT: Duration = Duration::from_secs(120);
const MIN_HEARTBEAT: Duration = Duration::from_secs(5);
const MAX_HEARTBEAT: Duration = Duration::from_secs(600);

/// Log verbosity, the values Go's `log_level` setting accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    /// Parses a level, ignoring case.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// How the agent trusts the Hub's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    /// A CA certificate trusted in addition to the system roots (or alone,
    /// with `ca_only`). Includes `ca.crt` saved at enrollment.
    pub ca_file: Option<PathBuf>,
    /// Opt-in: skip certificate checks. A configured CA overrides it.
    pub skip_verify: bool,
    /// `LABTETHER_TLS_CA_ONLY`: trust only `ca_file`. A value that is not a
    /// boolean counts as on, and start fails with [`ConfigError`].
    pub ca_only: bool,
}

/// A one-use enrollment token and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentToken {
    pub token: Secret,
    /// Set when the token was read from `LABTETHER_ENROLLMENT_TOKEN_FILE`;
    /// that file is removed once the Hub has used the token.
    pub file: Option<PathBuf>,
}

/// Every setting the agent uses, read once at start.
#[derive(Debug, Clone)]
pub struct Settings {
    pub name: String,
    pub asset_id: String,
    pub source: String,
    pub group_id: String,
    pub hostname: String,
    pub version: String,
    /// Normalized WebSocket address (`LABTETHER_WS_URL`), may be empty.
    pub ws_url: String,
    /// Normalized API address (`LABTETHER_API_BASE_URL`), may be empty.
    pub api_url: String,
    pub allow_insecure_transport: bool,
    /// `LABTETHER_API_TOKEN`. A saved token is read from `token_file` later.
    pub api_token: Option<Secret>,
    pub token_file: PathBuf,
    pub enrollment: Option<EnrollmentToken>,
    pub settings_file: PathBuf,
    pub device_key_file: PathBuf,
    pub device_public_key_file: PathBuf,
    pub device_fingerprint_file: PathBuf,
    pub tls: TlsSettings,
    pub heartbeat_interval: Duration,
    pub log_level: LogLevel,
}

impl Settings {
    /// The folder that holds the token and the agent's other state files.
    pub fn state_dir(&self) -> &Path {
        self.token_file.parent().unwrap_or_else(|| Path::new("."))
    }
}

/// Facts about the host and build that the settings fall back on.
#[derive(Debug, Clone)]
pub struct HostFacts {
    pub hostname: String,
    pub version: String,
}

/// A setting that could not be used. Start goes on; the agent logs these.
#[derive(Debug)]
pub enum ConfigWarning {
    SettingsFile(SettingsFileError),
    EnrollmentTokenFile {
        path: PathBuf,
        error: files::ReadError,
    },
    UnknownLogLevel(String),
}

/// A setting that stops the agent at start.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("LABTETHER_TLS_CA_ONLY must be true or false, not {0:?}")]
    CaOnlyNotBoolean(String),
}

/// The settings and any warnings to log once logging is set up.
#[derive(Debug)]
pub struct Loaded {
    pub settings: Settings,
    pub warnings: Vec<ConfigWarning>,
}

fn path_or(env: &Environment, key: &str, default_name: &str) -> PathBuf {
    env.get(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(DEFAULT_STATE_DIR).join(default_name))
}

fn load_enrollment(
    env: &Environment,
    warnings: &mut Vec<ConfigWarning>,
) -> Option<EnrollmentToken> {
    if let Some(token) = env.get("LABTETHER_ENROLLMENT_TOKEN").and_then(Secret::new) {
        return Some(EnrollmentToken { token, file: None });
    }
    let path = PathBuf::from(env.get("LABTETHER_ENROLLMENT_TOKEN_FILE")?);
    match files::read_trimmed(&path, files::MAX_SECRET_FILE_BYTES) {
        Ok(raw) => Secret::new(raw).map(|token| EnrollmentToken {
            token,
            file: Some(path),
        }),
        Err(error) => {
            if !error.is_not_found() {
                warnings.push(ConfigWarning::EnrollmentTokenFile { path, error });
            }
            None
        }
    }
}

fn ca_only(env: &Environment) -> Result<bool, ConfigError> {
    match env.get("LABTETHER_TLS_CA_ONLY") {
        None => Ok(false),
        Some(raw) => {
            parse_go_bool(raw).ok_or_else(|| ConfigError::CaOnlyNotBoolean(raw.to_owned()))
        }
    }
}

/// Reads the settings from `env`, `agent-config.json` and the token files.
pub fn load(env: &Environment, host: &HostFacts) -> Result<Loaded, ConfigError> {
    let mut warnings = Vec::new();
    let allow_insecure = env.bool_or("LABTETHER_ALLOW_INSECURE_TRANSPORT", false);
    let hostname = host.hostname.trim().to_owned();
    let asset_id = env
        .get("AGENT_ASSET_ID")
        .map(str::to_owned)
        .or_else(|| (!hostname.is_empty()).then(|| hostname.clone()))
        .unwrap_or_else(|| "labtether-agent-local".to_owned());

    let low_power = env.bool_or("LABTETHER_LOW_POWER_MODE", false);
    let heartbeat_default = if low_power {
        LOW_POWER_HEARTBEAT
    } else {
        DEFAULT_HEARTBEAT
    };
    let heartbeat_env = env.get("AGENT_HEARTBEAT_INTERVAL");
    let mut heartbeat_interval = parse_duration_or(
        heartbeat_env,
        heartbeat_default,
        MIN_HEARTBEAT,
        MAX_HEARTBEAT,
    );
    let heartbeat_pinned = heartbeat_env.is_some() || low_power;

    let level_env = env.get("LABTETHER_LOG_LEVEL");
    let mut log_level = match level_env {
        None => LogLevel::Info,
        Some(raw) => LogLevel::parse(raw).unwrap_or_else(|| {
            warnings.push(ConfigWarning::UnknownLogLevel(raw.to_owned()));
            LogLevel::Info
        }),
    };

    let token_file = path_or(env, "LABTETHER_TOKEN_FILE", "agent-token");
    let settings_file = path_or(env, "LABTETHER_AGENT_SETTINGS_FILE", "agent-config.json");
    let mut tls = TlsSettings {
        ca_file: env.get("LABTETHER_TLS_CA_FILE").map(PathBuf::from),
        skip_verify: env.bool_or("LABTETHER_TLS_SKIP_VERIFY", false),
        ca_only: ca_only(env)?,
    };

    match settings_file::load(&settings_file) {
        Ok(file) => {
            if let Some(raw) = file.tls_ca_file {
                tls.ca_file = Some(raw).filter(|raw| !raw.is_empty()).map(PathBuf::from);
            }
            if let Some(skip) = file.tls_skip_verify {
                tls.skip_verify = skip;
            }
            if let (Some(seconds), false) = (file.heartbeat_interval_sec, heartbeat_pinned) {
                heartbeat_interval = Duration::from_secs(seconds);
            }
            if let (Some(level), None) = (file.log_level, level_env) {
                log_level = level;
            }
        }
        Err(error) => warnings.push(ConfigWarning::SettingsFile(error)),
    }

    // The CA saved at enrollment is used when no CA is configured.
    if tls.ca_file.is_none() {
        let saved = token_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("ca.crt");
        if saved.exists() {
            tls.ca_file = Some(saved);
        }
    }

    let settings = Settings {
        name: env.get_or("AGENT_NAME", "labtether-agent").to_owned(),
        asset_id,
        source: env.get_or("AGENT_SOURCE", "agent").to_owned(),
        group_id: env.get_or("AGENT_GROUP_ID", "").to_owned(),
        hostname,
        version: env
            .get_or("LABTETHER_AGENT_VERSION", &host.version)
            .to_owned(),
        ws_url: urls::normalize(
            env.get_or("LABTETHER_WS_URL", ""),
            UrlKind::WebSocket,
            allow_insecure,
        ),
        api_url: urls::normalize(
            env.get_or("LABTETHER_API_BASE_URL", ""),
            UrlKind::Api,
            allow_insecure,
        ),
        allow_insecure_transport: allow_insecure,
        api_token: env.get("LABTETHER_API_TOKEN").and_then(Secret::new),
        token_file,
        enrollment: load_enrollment(env, &mut warnings),
        settings_file,
        device_key_file: path_or(env, "LABTETHER_DEVICE_KEY_FILE", "device-key"),
        device_public_key_file: path_or(env, "LABTETHER_DEVICE_PUBLIC_KEY_FILE", "device-key.pub"),
        device_fingerprint_file: path_or(
            env,
            "LABTETHER_DEVICE_FINGERPRINT_FILE",
            "device-fingerprint",
        ),
        tls,
        heartbeat_interval,
        log_level,
    };
    Ok(Loaded { settings, warnings })
}

#[cfg(test)]
mod tests;
