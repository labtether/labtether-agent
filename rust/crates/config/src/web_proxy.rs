//! The reverse-proxy source's settings, as the Go agent reads them:
//!
//! - the switches in `LoadConfig` (`config.go`, `settings_env_pins.go`):
//!   `LABTETHER_SERVICES_DISCOVERY_PROXY_ENABLED` (on; Go's older
//!   `LABTETHER_PROXY_DISABLED` wins when set: off for `true`, `1` or `on`)
//!   and `_PROXY_TRAEFIK_ENABLED`, `_CADDY_ENABLED`, `_NPM_ENABLED` (on),
//!   with their `services_discovery_proxy_*` keys in `agent-config.json`
//!   used only when the environment does not set them;
//! - the providers' addresses and logins, read as their constructors read
//!   them (`proxy/traefik.go`, `caddy.go`, `npm.go`): `LABTETHER_TRAEFIK_URL`,
//!   `_USER`, `_PASSWORD`, `LABTETHER_CADDY_URL`, `LABTETHER_NPM_URL`,
//!   `_EMAIL`, `_PASSWORD`;
//! - the outbound rules every NPM request passes (`securityruntime`):
//!   `LABTETHER_ALLOW_INSECURE_TRANSPORT`, `LABTETHER_OUTBOUND_ALLOWED_SCHEMES`,
//!   `_ALLOWLIST_MODE`, `_ALLOWED_HOSTS`, `_ALLOW_PRIVATE`, `_ALLOW_LOOPBACK`.

use crate::env::{Environment, parse_go_bool};
use crate::secret::Secret;

const ENABLED_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PROXY_ENABLED";
const DISABLED_VARIABLE: &str = "LABTETHER_PROXY_DISABLED";
const TRAEFIK_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PROXY_TRAEFIK_ENABLED";
const CADDY_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PROXY_CADDY_ENABLED";
const NPM_VARIABLE: &str = "LABTETHER_SERVICES_DISCOVERY_PROXY_NPM_ENABLED";

/// Go's `ServicesDiscoveryProxy*` settings and the providers' own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxySettings {
    pub enabled: bool,
    pub traefik: bool,
    pub caddy: bool,
    pub npm: bool,
    /// `LABTETHER_TRAEFIK_URL` without trailing `/` (Go trims nothing else).
    pub traefik_url: String,
    /// Basic auth, sent only when both are set (exactly as written).
    pub traefik_user: String,
    pub traefik_password: Option<Secret>,
    /// `LABTETHER_CADDY_URL` without trailing `/`.
    pub caddy_url: String,
    /// `LABTETHER_NPM_URL` trimmed, without trailing `/`.
    pub npm_url: String,
    /// Go's `allowInsecureTransportOptIn`: a found NPM is read over http
    /// when `LABTETHER_ALLOW_INSECURE_TRANSPORT` is `true`, `1` or `yes`
    /// (any case), else https.
    pub npm_http: bool,
    /// NPM's login, exactly as written.
    pub npm_email: String,
    pub npm_password: Option<Secret>,
    pub outbound: OutboundSettings,
}

/// Go's outbound rules (`securityruntime/outbound.go`), read once: Go reads
/// the same variables at each request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundSettings {
    /// `LABTETHER_ALLOW_INSECURE_TRANSPORT`: http and ws allowed.
    pub allow_insecure: bool,
    /// Go's `effectiveAllowedOutboundSchemes`: the list (https and wss by
    /// default), plus http and ws when insecure transport is allowed.
    pub schemes: Vec<String>,
    pub allowlist_mode: bool,
    /// `LABTETHER_OUTBOUND_ALLOWED_HOSTS` items, trimmed.
    pub allowed_hosts: Vec<String>,
    /// `None` when not set: Go then allows private addresses for https
    /// and wss only. An unreadable value counts as set and false, as Go's
    /// `parseBoolEnvWithPresence`.
    pub allow_private: Option<bool>,
    pub allow_loopback: bool,
}

/// The `services_discovery_proxy_*` values found in `agent-config.json`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FileProxy {
    pub enabled: Option<bool>,
    pub traefik: Option<bool>,
    pub caddy: Option<bool>,
    pub npm: Option<bool>,
}

/// A switch: the environment when it sets any of `names` (Go's pins),
/// else the file's value, else the environment's reading (`fallback` when
/// unset or unreadable).
fn switch(env: &Environment, names: &[&str], from_env: bool, file: Option<bool>) -> bool {
    let pinned = names.iter().any(|name| env.get(name).is_some());
    match (pinned, file) {
        (false, Some(value)) => value,
        _ => from_env,
    }
}

/// Go's `os.Getenv` with the trailing `/` removed (`strings.TrimRight`).
fn url_without_slash(env: &Environment, name: &str) -> String {
    env.raw(name).unwrap_or("").trim_end_matches('/').to_owned()
}

pub(crate) fn load(env: &Environment, file: &FileProxy) -> ProxySettings {
    let mut enabled = env.bool_or(ENABLED_VARIABLE, true);
    if let Some(raw) = env.get(DISABLED_VARIABLE) {
        enabled =
            !(raw.eq_ignore_ascii_case("true") || raw == "1" || raw.eq_ignore_ascii_case("on"));
    }
    let provider =
        |name: &str, value: Option<bool>| switch(env, &[name], env.bool_or(name, true), value);
    ProxySettings {
        enabled: switch(
            env,
            &[ENABLED_VARIABLE, DISABLED_VARIABLE],
            enabled,
            file.enabled,
        ),
        traefik: provider(TRAEFIK_VARIABLE, file.traefik),
        caddy: provider(CADDY_VARIABLE, file.caddy),
        npm: provider(NPM_VARIABLE, file.npm),
        traefik_url: url_without_slash(env, "LABTETHER_TRAEFIK_URL"),
        traefik_user: env.raw("LABTETHER_TRAEFIK_USER").unwrap_or("").to_owned(),
        traefik_password: env
            .raw("LABTETHER_TRAEFIK_PASSWORD")
            .and_then(Secret::exact),
        caddy_url: url_without_slash(env, "LABTETHER_CADDY_URL"),
        npm_url: env
            .raw("LABTETHER_NPM_URL")
            .unwrap_or("")
            .trim()
            .trim_end_matches('/')
            .to_owned(),
        npm_http: env
            .raw("LABTETHER_ALLOW_INSECURE_TRANSPORT")
            .map(|raw| raw.trim().to_lowercase())
            .is_some_and(|raw| matches!(raw.as_str(), "true" | "1" | "yes")),
        npm_email: env.raw("LABTETHER_NPM_EMAIL").unwrap_or("").to_owned(),
        npm_password: env.raw("LABTETHER_NPM_PASSWORD").and_then(Secret::exact),
        outbound: outbound(env),
    }
}

/// The settings from the environment alone (no `agent-config.json`).
pub fn from_environment(env: &Environment) -> ProxySettings {
    load(env, &FileProxy::default())
}

fn outbound(env: &Environment) -> OutboundSettings {
    let allow_insecure = env.bool_or("LABTETHER_ALLOW_INSECURE_TRANSPORT", false);
    let mut schemes = env
        .csv("LABTETHER_OUTBOUND_ALLOWED_SCHEMES")
        .unwrap_or_else(|| vec!["https".to_owned(), "wss".to_owned()]);
    if allow_insecure {
        for scheme in ["http", "ws"] {
            if !schemes
                .iter()
                .any(|s| s.trim().eq_ignore_ascii_case(scheme))
            {
                schemes.push(scheme.to_owned());
            }
        }
    }
    OutboundSettings {
        allow_insecure,
        schemes,
        allowlist_mode: env.bool_or("LABTETHER_OUTBOUND_ALLOWLIST_MODE", false),
        allowed_hosts: env
            .csv("LABTETHER_OUTBOUND_ALLOWED_HOSTS")
            .unwrap_or_default(),
        allow_private: env
            .get("LABTETHER_OUTBOUND_ALLOW_PRIVATE")
            .map(|raw| parse_go_bool(raw).unwrap_or(false)),
        allow_loopback: env.bool_or("LABTETHER_OUTBOUND_ALLOW_LOOPBACK", false),
    }
}
