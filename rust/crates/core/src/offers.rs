//! The words the Hub reads to decide what it sends this agent. The agent
//! sends `agent_capability_mode=explicit`, so the Hub sends it only the
//! requests it advertises and answers every other one itself with 422
//! `agent_unsupported` (Hub `internal/agentcaps/agentcaps.go`,
//! `messageNeeds`). The word for a request comes from [`request_word`] when
//! its handler is registered ([`crate::Features::on_message`]): a page that
//! is registered advertises its word, and nothing else can.
//!
//! The Hub's other words are not here: the heartbeat's `capabilities` list
//! (`terminal`, `files`, `desktop`, `webrtc`, `power`) and `cap_wol`,
//! `cap_ssh_keys`, `cap_docker`, `cap_commands`, `cap_settings` and
//! `cap_updates`. This agent answers none of those requests, so a handler
//! for one cannot be registered until its row is added from the Hub's
//! table, and the `capabilities` list stays empty.

use labtether_protocol::{
    MSG_CRON_LIST, MSG_DISK_LIST, MSG_JOURNAL_QUERY, MSG_NETWORK_ACTION, MSG_NETWORK_LIST,
    MSG_PACKAGE_ACTION, MSG_PACKAGE_LIST, MSG_PROCESS_KILL, MSG_PROCESS_LIST, MSG_SERVICE_ACTION,
    MSG_SERVICE_LIST, MSG_USERS_LIST, MSG_WEBSERVICE_SYNC,
};

/// The key that tells the Hub the advertisement is complete, and its only
/// value the Hub acts on.
pub const MODE_KEY: &str = "agent_capability_mode";
pub const MODE_EXPLICIT: &str = "explicit";

/// The key naming a limited build, and the one value the Hub reports. The
/// console shows it as "Monitoring only"; it does not change what the Hub
/// sends.
pub const EDITION_KEY: &str = "agent_edition";
pub const EDITION_MONITORING: &str = "monitoring";

/// `(request, metadata key, token)`: the token in the key's comma list the
/// Hub needs before it sends the request.
const REQUEST_WORDS: &[(&str, &str, &str)] = &[
    (MSG_DISK_LIST, "cap_disks", "list"),
    (MSG_PROCESS_LIST, "cap_processes", "list"),
    (MSG_PROCESS_KILL, "cap_processes", "kill"),
    (MSG_SERVICE_LIST, "cap_services", "list"),
    (MSG_SERVICE_ACTION, "cap_services", "action"),
    (MSG_NETWORK_LIST, "cap_network", "list"),
    (MSG_NETWORK_ACTION, "cap_network", "action"),
    (MSG_PACKAGE_LIST, "cap_packages", "list"),
    (MSG_PACKAGE_ACTION, "cap_packages", "action"),
    (MSG_CRON_LIST, "cap_schedules", "list"),
    (MSG_USERS_LIST, "cap_users", "list"),
    (MSG_JOURNAL_QUERY, "cap_logs", "query"),
    (MSG_WEBSERVICE_SYNC, "cap_web_services", "sync"),
];

/// Tokens that make the Hub send nothing, so no handler stands behind
/// them: `stored` (the Hub reads the logs it keeps) and `stream` (the Hub
/// takes the `log.batch` messages the agent sends on its own).
const NO_REQUEST_TOKENS: &[(&str, &str)] = &[("cap_logs", "stored"), ("cap_logs", "stream")];

/// The `(key, token)` the Hub needs before it sends `request`, if the
/// Hub's rule has a row for it.
pub fn request_word(request: &str) -> Option<(&'static str, &'static str)> {
    REQUEST_WORDS
        .iter()
        .find(|(kind, _, _)| *kind == request)
        .map(|(_, key, token)| (*key, *token))
}

/// Whether `token` in `key` is one the Hub sends no request for.
pub fn is_no_request_token(key: &str, token: &str) -> bool {
    NO_REQUEST_TOKENS.contains(&(key, token))
}

/// Keys only the advertisement itself may set: a `cap_*` key holds the
/// words of registered handlers, and the mode and edition say what the
/// words mean.
pub(crate) fn is_reserved_key(key: &str) -> bool {
    key.starts_with("cap_") || key == MODE_KEY || key == EDITION_KEY
}
