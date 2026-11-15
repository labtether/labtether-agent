//! The token check every Hub message passes before its handler, ported from
//! Go's `requiredCapabilitiesForMessage` (`command_authorization.go`) and
//! `TokenAllowsAnyCapability` / `ExtractTokenCapabilities`
//! (`remoteaccess/exec_ws.go`).
//!
//! An agent token shaped like a JWT may carry capability claims; then a
//! message whose type needs a capability is dropped unless the token holds
//! one of the listed names. An opaque token (the Hub's `atok_...` tokens)
//! carries none, so nothing is checked, as in Go. The whole Go table is
//! here, so a feature added later is covered without touching this file.
//!
//! Not ported yet: the `power.result` refusal Go sends when it drops a
//! `power.action` (there is no power feature).

use std::collections::HashSet;

use data_encoding::{BASE64URL, BASE64URL_NOPAD, Encoding};
use serde_json::Value;

const SETTINGS: &[&str] = &["agent.settings.apply", "agent.settings", "settings.apply"];
const TERMINAL: &[&str] = &["agent.terminal", "terminal.connect", "terminal"];
const DESKTOP: &[&str] = &["agent.desktop", "desktop.connect", "desktop"];
const FILES: &[&str] = &["agent.files", "files.manage", "files"];
const SSH_KEYS: &[&str] = &["agent.ssh_keys", "ssh_keys.manage", "ssh_keys"];
const WOL: &[&str] = &["agent.network.manage", "network.manage", "agent.operations"];
const POWER: &[&str] = &["agent.power", "power.manage", "agent.operations"];
const PROCESSES: &[&str] = &["agent.processes", "processes.manage", "agent.operations"];
const SERVICES: &[&str] = &["agent.services", "services.manage", "agent.operations"];
const NETWORK: &[&str] = &["agent.network", "network.manage", "agent.operations"];
const UPDATE: &[&str] = &["agent.update.apply", "update.apply", "agent.update"];
const INSPECT: &[&str] = &["agent.inspect", "agent.operations", "operations.read"];
const DOCKER: &[&str] = &["agent.docker", "docker.manage", "agent.operations"];

/// Go's `requiredCapabilitiesForMessage`, rule for rule and in its order.
pub fn required_for(kind: &str) -> &'static [&'static str] {
    let starts = |prefix: &str| kind.starts_with(prefix);
    match kind {
        "config.update" | "agent.settings.apply" => SETTINGS,
        _ if starts("terminal.") => TERMINAL,
        _ if starts("desktop.") || starts("webrtc.") || starts("clipboard.") => DESKTOP,
        _ if starts("file.") => FILES,
        _ if starts("ssh_key.") => SSH_KEYS,
        "wol.send" => WOL,
        "power.action" => POWER,
        _ if starts("process.") => PROCESSES,
        _ if starts("service.") => SERVICES,
        _ if starts("network.") => NETWORK,
        _ if starts("package.") || starts("update.") => UPDATE,
        _ if starts("cron.") || starts("users.") || starts("disk.") || starts("journal.") => {
            INSPECT
        }
        _ if starts("docker.") => DOCKER,
        "webservice.sync" => SERVICES,
        _ => &[],
    }
}

/// Go's base64 decoders ignore bits after the last whole byte; so does this.
fn lenient(encoding: &Encoding) -> Encoding {
    let mut spec = encoding.specification();
    spec.check_trailing_bits = false;
    spec.encoding().unwrap_or_else(|_| encoding.clone())
}

/// Go's `collectClaimValues`: strings split on commas and white space,
/// lowercased; lists walked; other values ignored.
fn collect(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::String(text) => {
            for part in text.split([',', ' ', '\t', '\n', '\r']) {
                let part = part.trim().to_lowercase();
                if !part.is_empty() {
                    out.insert(part);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
        _ => {}
    }
}

/// Go's `ExtractTokenCapabilities`: the claims of a three-part token, or
/// `None` when it is not one or carries no claims.
pub fn token_capabilities(token: &str) -> Option<HashSet<String>> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    let [_, payload, _] = parts[..] else {
        return None;
    };
    let raw = lenient(&BASE64URL_NOPAD)
        .decode(payload.as_bytes())
        .or_else(|_| lenient(&BASE64URL).decode(payload.as_bytes()))
        .ok()?;
    // Go's decoder turns bytes that are not UTF-8 into U+FFFD and goes on.
    let Ok(Value::Object(claims)) = serde_json::from_str(&String::from_utf8_lossy(&raw)) else {
        return None;
    };
    let mut out = HashSet::new();
    for key in [
        "capabilities",
        "capability",
        "scope",
        "scopes",
        "scp",
        "permissions",
    ] {
        if let Some(value) = claims.get(key) {
            collect(value, &mut out);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Whether a message needing one of `required` may run with `token`: an
/// empty requirement, no token, or a token without claims allows it
/// (Go's `checked == false`); otherwise one listed name must be claimed.
pub fn allows(token: Option<&str>, required: &[&str]) -> bool {
    if required.is_empty() {
        return true;
    }
    let Some(claims) = token.and_then(token_capabilities) else {
        return true;
    };
    required
        .iter()
        .any(|name| claims.contains(&name.trim().to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(payload: &[u8]) -> String {
        format!("header.{}.signature", BASE64URL_NOPAD.encode(payload))
    }

    // Fault: a page's message type maps to the wrong claims, so a token
    // without the right claim reads it (or one with it is refused). The
    // rows are Go's `requiredCapabilitiesForMessage`.
    #[test]
    fn message_types_need_go_claims() {
        assert_eq!(required_for("disk.list"), INSPECT);
        assert_eq!(required_for("process.list"), PROCESSES);
        assert_eq!(required_for("process.kill"), PROCESSES);
        assert_eq!(required_for("network.list"), NETWORK);
        assert_eq!(required_for("network.action"), NETWORK);
        assert_eq!(required_for("wol.send"), WOL);
        assert_eq!(required_for("config.update"), SETTINGS);
        assert_eq!(required_for("update.request"), UPDATE);
        assert_eq!(required_for("webservice.sync"), SERVICES);
        assert_eq!(required_for("terminal.probe"), TERMINAL);
        assert!(required_for("ping").is_empty());
        assert!(required_for("enrollment.challenge").is_empty());
    }

    // Fault: claims are read from the wrong keys, not split on commas and
    // spaces, not lowercased, nested lists are skipped, or a payload that
    // is not UTF-8 makes the token count as opaque (allowing everything,
    // where Go reads it and enforces).
    #[test]
    fn claims_are_read_like_go() {
        let claims = token_capabilities(&token(
            br#"{"scope":"Agent.Inspect,files terminal","permissions":[["agent.docker"]],"other":["x"]}"#,
        ))
        .unwrap();
        for name in ["agent.inspect", "files", "terminal", "agent.docker"] {
            assert!(claims.contains(name), "{name} missing from {claims:?}");
        }
        assert!(!claims.contains("x"));
        let padded = format!("h.{}.s", BASE64URL.encode(br#"{"scp":"agent.inspect"}"#));
        assert!(token_capabilities(&padded).is_some());
        let not_utf8 = token(b"{\"capabilities\":[\"agent.terminal\"],\"n\":\"\xff\"}");
        assert!(!allows(Some(&not_utf8), INSPECT));
        assert!(token_capabilities("atok_123_456").is_none());
        assert!(token_capabilities(&token(b"[\"agent.inspect\"]")).is_none());
        assert!(token_capabilities(&token(br#"{"capabilities":[]}"#)).is_none());
    }

    // Fault: an opaque token or no token is refused (the Hub's tokens are
    // opaque; Go skips the check), or a claim-bearing token without the
    // claim is allowed.
    #[test]
    fn opaque_tokens_are_not_checked() {
        assert!(allows(Some("atok_123_456"), INSPECT));
        assert!(allows(None, INSPECT));
        assert!(allows(
            Some(&token(br#"{"capabilities":"agent.terminal"}"#)),
            &[]
        ));
        assert!(!allows(
            Some(&token(br#"{"capabilities":"agent.terminal"}"#)),
            INSPECT
        ));
        assert!(allows(
            Some(&token(br#"{"capabilities":"OPERATIONS.READ"}"#)),
            INSPECT
        ));
    }
}
