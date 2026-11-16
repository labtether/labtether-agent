//! Go's `ValidateExecBinary` and `ValidateShellCommand`, over settings read
//! once at start instead of the environment at check time.

use std::collections::HashSet;
use std::path::PathBuf;

use labtether_agent_config::{CommandSecuritySettings, Environment, gopath};
use labtether_agent_platform::look_path;

use crate::child_env::sanitized_child_env;
use crate::error::Refusal;
use crate::lists::{
    DEFAULT_ALLOWED_EXEC_BINARIES, DEFAULT_SHELL_ALLOWLIST_PREFIXES,
    DEFAULT_SHELL_BLOCKED_SUBSTRINGS, DEFAULT_SHELL_BLOCKED_TOKENS,
};
use crate::parse::{
    contains_command_token, normalize_executable_name, normalize_shell_command, parse_command_line,
    shell_rule_matches,
};
use crate::readonly::{clean_protected_paths, validate_read_only_command};

/// The command rules in force, built once at start and passed to whatever
/// starts a command. [`CommandPolicy::run`] is the only way the agent starts
/// a process.
#[derive(Debug, Clone)]
pub struct CommandPolicy {
    exec_allowlist_mode: bool,
    exec_accept_risk: bool,
    exec_allowed: HashSet<String>,
    exec_blocked: HashSet<String>,
    shell_allowlist_mode: bool,
    shell_accept_risk: bool,
    shell_prefixes: Vec<String>,
    shell_blocked_substrings: Vec<String>,
    protected_read_paths: Vec<String>,
    pub(crate) child_env: Vec<(String, String)>,
    /// The agent's `PATH`, exactly as set, for finding a bare program name.
    pub(crate) search_path: String,
}

fn name_set<'a>(names: impl Iterator<Item = &'a str>) -> HashSet<String> {
    names
        .map(normalize_executable_name)
        .filter(|name| !name.is_empty())
        .collect()
}

fn owned(list: &Option<Vec<String>>, default: &[&str]) -> Vec<String> {
    match list {
        Some(items) => items.clone(),
        None => default.iter().map(|item| (*item).to_owned()).collect(),
    }
}

impl CommandPolicy {
    /// Builds the policy from the settings and the environment captured at
    /// start (the child environment is taken from it once, here).
    pub fn new(settings: &CommandSecuritySettings, env: &Environment) -> Self {
        let allowed = owned(
            &settings.exec_allowed_binaries,
            DEFAULT_ALLOWED_EXEC_BINARIES,
        );
        Self {
            exec_allowlist_mode: settings.exec_allowlist_mode,
            exec_accept_risk: settings.exec_allowlist_accept_risk,
            exec_allowed: name_set(allowed.iter().map(String::as_str)),
            exec_blocked: name_set(settings.exec_blocked_binaries.iter().map(String::as_str)),
            shell_allowlist_mode: settings.shell_allowlist_mode,
            shell_accept_risk: settings.shell_allowlist_accept_risk,
            shell_prefixes: owned(
                &settings.shell_allowlist_prefixes,
                DEFAULT_SHELL_ALLOWLIST_PREFIXES,
            ),
            shell_blocked_substrings: owned(
                &settings.shell_blocked_substrings,
                DEFAULT_SHELL_BLOCKED_SUBSTRINGS,
            ),
            protected_read_paths: clean_protected_paths(&settings.secret_paths),
            child_env: sanitized_child_env(env),
            search_path: env.raw("PATH").unwrap_or("").to_owned(),
        }
    }

    /// The agent's `PATH` as set at start: where a bare program name is
    /// found, as Go's `exec.LookPath` finds it.
    pub fn search_path(&self) -> &str {
        &self.search_path
    }

    /// The environment every started command gets.
    pub fn child_env(&self) -> &[(String, String)] {
        &self.child_env
    }

    /// Go's `ValidateExecBinary`: the blocked list first, then the
    /// allowlist (or its accept-risk switch), then, while the allowlist is
    /// on, the path rule of [`CommandPolicy::resolve_exec_program`].
    pub fn validate_exec_binary(&self, name: &str) -> Result<(), Refusal> {
        self.resolve_exec_program(name).map(|_| ())
    }

    /// Go's `resolveExecProgram`: the exec rules, and for a program given
    /// with a folder the file to start. That path must be the same file
    /// (after resolving links) that a lookup of its bare name in the
    /// agent's `PATH` finds, and the command then starts the file `PATH`
    /// gives, so a link swapped after the check cannot change what runs.
    /// `None` for a bare name, or when the allowlist is off.
    pub(crate) fn resolve_exec_program(&self, name: &str) -> Result<Option<PathBuf>, Refusal> {
        let (normalized, check_path) = self.validate_exec_name(name)?;
        // A backslash counts as a folder, as in the name rules.
        if !check_path || !name.contains(['/', '\\']) {
            return Ok(None);
        }
        if !gopath::is_abs(name) {
            return Err(Refusal::ExecNotFullPath(name.to_owned()));
        }
        let not_path = || Refusal::ExecNotPathProgram(name.to_owned(), normalized.clone());
        let found = look_path(&gopath::base(name), &self.search_path).map_err(|_| not_path())?;
        match (std::fs::canonicalize(name), std::fs::canonicalize(&found)) {
            (Ok(given), Ok(want)) if given == want => Ok(Some(found)),
            _ => Err(not_path()),
        }
    }

    /// Go's `validateExecName`: the program's name against the blocked list
    /// and the allowlist. The flag is false when the allowlist is off with
    /// accept-risk; then the folder is not checked either.
    fn validate_exec_name(&self, name: &str) -> Result<(String, bool), Refusal> {
        let normalized = normalize_executable_name(name);
        if normalized.is_empty() {
            return Err(Refusal::CommandRequired);
        }
        if self.exec_blocked.contains(&normalized) {
            return Err(Refusal::ExecBlocked(normalized));
        }
        if !self.exec_allowlist_mode {
            if !self.exec_accept_risk {
                return Err(Refusal::ExecAllowlistOffWithoutRisk(normalized));
            }
            return Ok((normalized, false));
        }
        if self.exec_allowed.contains(&normalized) {
            return Ok((normalized, true));
        }
        Err(Refusal::ExecNotAllowlisted(normalized))
    }

    /// Go's `ValidateShellCommand`: parse, blocked substrings, blocked
    /// words, then the allowlist rules and the read-only rules. Returns the
    /// program and arguments.
    pub fn validate_shell_command(&self, command: &str) -> Result<Vec<String>, Refusal> {
        let args = parse_command_line(command)?;
        let normalized = normalize_shell_command(&args.join(" "));

        for blocked in &self.shell_blocked_substrings {
            let token = normalize_shell_command(blocked);
            if !token.is_empty() && normalized.contains(&token) {
                return Err(Refusal::SafetyBlocked);
            }
        }
        for token in DEFAULT_SHELL_BLOCKED_TOKENS {
            let token = token.trim().to_lowercase();
            if !token.is_empty() && contains_command_token(&normalized, &token) {
                return Err(Refusal::SafetyBlocked);
            }
        }

        if !self.shell_allowlist_mode {
            if !self.shell_accept_risk {
                return Err(Refusal::ShellAllowlistOffWithoutRisk);
            }
            return Ok(args);
        }
        for rule in &self.shell_prefixes {
            if shell_rule_matches(&args, rule)? {
                validate_read_only_command(&args, &self.protected_read_paths)?;
                return Ok(args);
            }
        }
        Err(Refusal::NotInAllowlist)
    }
}
