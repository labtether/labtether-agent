//! The Packages page's lists: `package.list`, ported from Go's
//! `HandlePackageList` (`internal/agentcore/backends/package_handler.go`).
//! The request's `inventory` picks the installed list (empty or
//! `installed`) or the upgradable list (`upgradable`, echoed in the reply
//! so the Hub can tell this agent reads the field). Unlike the other pages,
//! Go answers a request it cannot use: one that does not decode, a missing
//! or too long request ID, an envelope ID that differs from it, or an
//! unknown inventory each get an error reply.
//!
//! Advertised as Go's Linux agent does, without the action part:
//! `cap_packages=list` and `package_backend=<tool>` for the first package
//! manager in the agent's `PATH` (else `dpkg-query` or `rpm`); Go says
//! `list,action` for a manager. With no tool the list is not registered,
//! no `cap_packages` is sent (Go sends `""` and still answers) and
//! `package_backend=none`. `package.action` is not in this agent.

mod lists;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_security::CommandPolicy;
use labtether_protocol::{
    MSG_PACKAGE_LIST, MSG_PACKAGE_LISTED, Message, PackageInfo, PackageInventory, PackageListedData,
};
use serde_json::Value;

use crate::Commands;

use labtether_agent_platform::tool_output::packages::Package;
use labtether_agent_platform::tool_output::upgradable::Upgrade;
use lists::{detect_backend, list_installed, list_upgradable};

/// Go's `MaxPackageInventoryPayloadBytes`: a larger reply is replaced by
/// an error.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 512;

pub fn register(features: &mut Features, _settings: &Settings, commands: &Commands) {
    let policy = Arc::clone(&commands.policy);
    let Some(backend) = detect_backend(policy.search_path()) else {
        features.advertise("package_backend", "none");
        return;
    };
    features.on_message(MSG_PACKAGE_LIST, move |message| {
        Some(handle(message, &policy, lists::UPGRADABLE_TIMEOUT))
    });
    features.advertise("package_backend", backend);
}

/// Go's `packageListRequestWire`. A JSON `null` payload is an empty
/// request, as Go reads it; a field that is neither a string nor `null`
/// fails, as in Go.
fn decode(message: &Message) -> Result<(String, String), String> {
    let raw = message.data.as_deref().ok_or("no payload")?;
    let value: Value = serde_json::from_str(raw.get()).map_err(|e| e.to_string())?;
    let field = |map: &serde_json::Map<String, Value>, key: &str| match map.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(other) => Err(format!("{key} is {other}, not a string")),
    };
    match value {
        Value::Null => Ok((String::new(), String::new())),
        Value::Object(map) => Ok((field(&map, "request_id")?, field(&map, "inventory")?)),
        other => Err(format!("payload is {other}, not an object")),
    }
}

fn reply(
    id: &str,
    inventory: &str,
    packages: Vec<PackageInfo>,
    error: String,
) -> PackageListedData {
    PackageListedData {
        request_id: id.trim().to_owned(),
        inventory: PackageInventory::from(inventory),
        packages,
        error,
    }
}

/// The length of the JSON Go's `json.Marshal` writes for `data`: serde
/// writes `<`, `>`, `&`, U+2028 and U+2029 as they are, Go escapes them.
pub(crate) fn go_json_len(data: &PackageListedData) -> usize {
    let text = serde_json::to_string(data).unwrap_or_default();
    let extra: usize = text
        .chars()
        .map(|c| match c {
            '<' | '>' | '&' => 5,
            '\u{2028}' | '\u{2029}' => 3,
            _ => 0,
        })
        .sum();
    text.len() + extra
}

/// Go's size rule: a reply over [`MAX_PAYLOAD_BYTES`] goes out with no
/// packages and an error instead (the inventory echo kept).
fn bounded(mut data: PackageListedData) -> PackageListedData {
    if go_json_len(&data) > MAX_PAYLOAD_BYTES {
        data.packages = Vec::new();
        data.error = format!("package inventory response exceeds {MAX_PAYLOAD_BYTES} bytes");
    }
    data
}

fn send(data: PackageListedData) -> Message {
    let data = bounded(data);
    let id = data.request_id.clone();
    Message::with_data(MSG_PACKAGE_LISTED, &id, &data).unwrap_or_else(|error| {
        log::warn!("package: failed to marshal package.listed response: {error}");
        Message::bare(MSG_PACKAGE_LISTED, &id)
    })
}

fn error_reply(id: &str, error: &str) -> Message {
    send(reply(id, "", Vec::new(), error.to_owned()))
}

/// The reply to one `package.list` message.
pub(crate) fn handle(message: &Message, policy: &CommandPolicy, timeout: Duration) -> Message {
    let envelope = message.id.trim();
    let (request_id, inventory) = match decode(message) {
        Ok(decoded) => decoded,
        Err(error) => {
            log::warn!("package: invalid package.list request: {error}");
            return error_reply(envelope, "invalid package inventory request");
        }
    };
    let mut request_id = request_id.trim();
    if request_id.is_empty() {
        request_id = envelope;
    }
    if request_id.is_empty() || request_id.len() > MAX_REQUEST_ID_BYTES {
        return error_reply(envelope, "invalid package inventory request id");
    }
    if !envelope.is_empty() && envelope != request_id {
        return error_reply(envelope, "package inventory request id mismatch");
    }
    let inventory = inventory.trim().to_lowercase();
    match inventory.as_str() {
        "" | "installed" => answer_installed(request_id, list_installed(policy)),
        "upgradable" => answer_upgradable(request_id, list_upgradable(policy, timeout)),
        _ => send(reply(
            request_id,
            &inventory,
            Vec::new(),
            "invalid package inventory".into(),
        )),
    }
}

/// The installed-list reply: no inventory echo, as Go's.
pub(crate) fn answer_installed(request_id: &str, list: Result<Vec<Package>, String>) -> Message {
    match list {
        Ok(rows) => {
            let packages = rows
                .into_iter()
                .map(|row| PackageInfo {
                    name: row.name,
                    version: row.version,
                    available_version: String::new(),
                    status: row.status,
                })
                .collect();
            send(reply(request_id, "", packages, String::new()))
        }
        Err(error) => {
            log::warn!("package: failed to collect packages: {error}");
            send(reply(request_id, "", Vec::new(), error))
        }
    }
}

/// The upgradable-list reply, always echoing `upgradable`.
pub(crate) fn answer_upgradable(request_id: &str, list: Result<Vec<Upgrade>, String>) -> Message {
    let (packages, error) = match list {
        Ok(rows) => (
            rows.into_iter()
                .map(|row| PackageInfo {
                    name: row.name,
                    version: row.version,
                    available_version: row.available_version,
                    status: "upgradable".into(),
                })
                .collect(),
            String::new(),
        ),
        Err(error) => {
            log::warn!("package: failed to collect upgradable packages: {error}");
            (Vec::new(), error)
        }
    };
    send(reply(request_id, "upgradable", packages, error))
}
