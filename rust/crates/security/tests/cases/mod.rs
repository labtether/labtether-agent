//! Reads the case files the Go tests also read
//! (`internal/securityruntime/testdata`) and builds a policy from a case's
//! variables, the way the agent builds it at start.

// Each test file uses part of this module.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use labtether_agent_config::command_security::{AgentFiles, COMMAND_POLICY_ENV};
use labtether_agent_config::{CommandSecuritySettings, Environment};
use labtether_agent_security::CommandPolicy;
use serde::de::DeserializeOwned;

pub const ALLOW: &str = "allow";

pub fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../internal/securityruntime/testdata")
        .join(name)
}

pub fn load<T: DeserializeOwned>(name: &str) -> T {
    let path = testdata(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("decode {}: {e}", path.display()))
}

/// A policy from a case's variables, with exactly `protect` as the agent's
/// own protected paths (as Go's tests call `SetProtectedReadPaths`).
pub fn policy(
    env: &BTreeMap<String, String>,
    protect: &[String],
    extra: &[(&str, &str)],
) -> CommandPolicy {
    for key in env.keys() {
        assert!(
            COMMAND_POLICY_ENV.contains(&key.as_str()),
            "unknown policy variable {key}"
        );
    }
    let environment = Environment::from_pairs(
        env.iter().map(|(k, v)| (k.clone(), v.clone())).chain(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        ),
    );
    let files = AgentFiles {
        token_file: Path::new("/nonexistent/agent-token"),
        settings_file: Path::new("/nonexistent/agent-config.json"),
        device_key_file: Path::new("/nonexistent/device-key"),
    };
    let mut settings = CommandSecuritySettings::from_env(&environment, &files);
    settings.secret_paths = protect.to_vec();
    CommandPolicy::new(&settings, &environment)
}

/// `{tmp}`, `{state}` (holding `agent-token`) and `{link}` (a symlink to
/// `{state}`), removed on drop.
pub struct CasePaths {
    root: PathBuf,
    pairs: [(&'static str, String); 3],
}

impl CasePaths {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "lt-security-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("agent-token"), "x").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let text = |path: &Path| path.to_str().unwrap().to_owned();
        let pairs = [
            ("{state}", text(&state)),
            ("{link}", text(&link)),
            ("{tmp}", text(&root)),
        ];
        Self { root, pairs }
    }

    pub fn replace(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (placeholder, value) in &self.pairs {
            out = out.replace(placeholder, value);
        }
        out
    }
}

impl Drop for CasePaths {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A failure line when `result` does not match `want` ("allow" or Go's
/// exact error text).
pub fn mismatch<E: std::fmt::Display>(
    label: &str,
    result: Result<(), E>,
    want: &str,
) -> Option<String> {
    match (result, want == ALLOW) {
        (Ok(()), true) => None,
        (Err(error), true) => Some(format!(
            "{label}: refused with {:?}, want allowed",
            error.to_string()
        )),
        (Ok(()), false) => Some(format!("{label}: allowed, want {want:?}")),
        (Err(error), false) if error.to_string() == want => None,
        (Err(error), false) => Some(format!(
            "{label}: error {:?}, want {want:?}",
            error.to_string()
        )),
    }
}

/// Fails with every mismatch listed.
pub fn assert_none(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} case(s) differ from Go:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
