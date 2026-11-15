//! Settings for the command rules in `labtether-agent-security`.
//!
//! The Go agent reads these variables each time it checks a command
//! (`internal/securityruntime/command.go`). Here they are read once at start;
//! the names, defaults and parsing are Go's. The default lists themselves
//! belong to the security crate: `None` below means "Go's default list".

use std::path::Path;

use crate::{Environment, gopath};

pub const ENV_EXEC_ALLOWLIST_MODE: &str = "LABTETHER_EXEC_ALLOWLIST_MODE";
pub const ENV_EXEC_ALLOWLIST_ACCEPT_RISK: &str = "LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK";
pub const ENV_EXEC_ALLOWED_BINARIES: &str = "LABTETHER_EXEC_ALLOWED_BINARIES";
pub const ENV_EXEC_BLOCKED_BINARIES: &str = "LABTETHER_EXEC_BLOCKED_BINARIES";
pub const ENV_SHELL_ALLOWLIST_MODE: &str = "LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE";
pub const ENV_SHELL_ALLOWLIST_ACCEPT_RISK: &str = "LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK";
pub const ENV_SHELL_ALLOWLIST_PREFIXES: &str = "LABTETHER_SHELL_COMMAND_ALLOWLIST_PREFIXES";
pub const ENV_SHELL_BLOCKED_SUBSTRINGS: &str = "LABTETHER_SHELL_COMMAND_BLOCKED_SUBSTRINGS";

/// Every policy variable, in Go's order.
pub const COMMAND_POLICY_ENV: [&str; 8] = [
    ENV_EXEC_ALLOWLIST_MODE,
    ENV_EXEC_ALLOWLIST_ACCEPT_RISK,
    ENV_EXEC_ALLOWED_BINARIES,
    ENV_EXEC_BLOCKED_BINARIES,
    ENV_SHELL_ALLOWLIST_MODE,
    ENV_SHELL_ALLOWLIST_ACCEPT_RISK,
    ENV_SHELL_ALLOWLIST_PREFIXES,
    ENV_SHELL_BLOCKED_SUBSTRINGS,
];

/// The command policy switches and lists, as set at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSecuritySettings {
    /// `LABTETHER_EXEC_ALLOWLIST_MODE`, on unless a Go boolean says false.
    pub exec_allowlist_mode: bool,
    /// `LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK`, needed to turn the list off.
    pub exec_allowlist_accept_risk: bool,
    /// `LABTETHER_EXEC_ALLOWED_BINARIES`; `None` keeps the default list.
    pub exec_allowed_binaries: Option<Vec<String>>,
    /// `LABTETHER_EXEC_BLOCKED_BINARIES`; empty when unset.
    pub exec_blocked_binaries: Vec<String>,
    /// `LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE`, on by default.
    pub shell_allowlist_mode: bool,
    /// `LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK`.
    pub shell_allowlist_accept_risk: bool,
    /// `LABTETHER_SHELL_COMMAND_ALLOWLIST_PREFIXES`; `None` keeps the default.
    pub shell_allowlist_prefixes: Option<Vec<String>>,
    /// `LABTETHER_SHELL_COMMAND_BLOCKED_SUBSTRINGS`; `None` keeps the default.
    pub shell_blocked_substrings: Option<Vec<String>>,
    /// The agent's own credential and state locations, which allowlisted
    /// readers (`cat`, `grep`, ...) may not read. Go's `agentSecretPaths`;
    /// blank and relative entries are dropped by the security crate.
    pub secret_paths: Vec<String>,
}

/// The agent files whose locations feed [`CommandSecuritySettings::secret_paths`].
pub struct AgentFiles<'a> {
    pub token_file: &'a Path,
    pub settings_file: &'a Path,
    pub device_key_file: &'a Path,
}

impl CommandSecuritySettings {
    /// Reads the policy variables and the secret locations.
    pub fn from_env(env: &Environment, files: &AgentFiles<'_>) -> Self {
        Self {
            exec_allowlist_mode: env.bool_or(ENV_EXEC_ALLOWLIST_MODE, true),
            exec_allowlist_accept_risk: env.bool_or(ENV_EXEC_ALLOWLIST_ACCEPT_RISK, false),
            exec_allowed_binaries: env.csv(ENV_EXEC_ALLOWED_BINARIES),
            exec_blocked_binaries: env.csv(ENV_EXEC_BLOCKED_BINARIES).unwrap_or_default(),
            shell_allowlist_mode: env.bool_or(ENV_SHELL_ALLOWLIST_MODE, true),
            shell_allowlist_accept_risk: env.bool_or(ENV_SHELL_ALLOWLIST_ACCEPT_RISK, false),
            shell_allowlist_prefixes: env.csv(ENV_SHELL_ALLOWLIST_PREFIXES),
            shell_blocked_substrings: env.csv(ENV_SHELL_BLOCKED_SUBSTRINGS),
            secret_paths: agent_secret_paths(env, files),
        }
    }
}

/// Go's `agentSecretPaths` (`internal/agentcore/command_secret_paths.go`):
/// the token, enrollment token, settings, device key and TURN password
/// files, `$HOME/.labtether`, the local API token file, and the token's
/// folder when its name contains "labtether".
fn agent_secret_paths(env: &Environment, files: &AgentFiles<'_>) -> Vec<String> {
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let trimmed = |key: &str| env.get(key).unwrap_or("").to_owned();
    // Go's configDir: os.UserHomeDir reads HOME untrimmed; unset or empty
    // gives an error and so an empty entry.
    let config_dir = match env.raw("HOME") {
        Some(home) if !home.is_empty() => gopath::join(&[home, ".labtether"]),
        _ => String::new(),
    };
    let token = text(files.token_file);
    let mut paths = vec![
        token.clone(),
        trimmed("LABTETHER_ENROLLMENT_TOKEN_FILE"),
        text(files.settings_file),
        text(files.device_key_file),
        trimmed("LABTETHER_WEBRTC_TURN_PASS_FILE"),
        config_dir,
        trimmed("LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE"),
    ];
    let token = token.trim();
    if !token.is_empty() {
        let folder = gopath::dir(token);
        if gopath::base(&folder).to_lowercase().contains("labtether") {
            paths.push(folder);
        }
    }
    paths
}
