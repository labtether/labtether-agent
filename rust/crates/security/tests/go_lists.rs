//! Reads the Go source of `internal/securityruntime` and compares its
//! default lists, limits and variable names with this crate's.
//!
//! Risk: an entry is added to or removed from a Go default list (say a new
//! allowed program or a new protected path) and not here, so the two agents
//! allow different commands while both test suites stay green.

#![cfg(target_os = "linux")]

use labtether_agent_config::command_security::COMMAND_POLICY_ENV;
use labtether_agent_security::lists;

fn go_source(file: &str) -> String {
    let path = format!(
        "{}/../../../internal/securityruntime/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn quoted(line: &str) -> Vec<String> {
    assert!(!line.contains('\\'), "escapes are not handled: {line}");
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The quoted strings between `header` and the closing `}` line. With
/// `keys`, only the first string of each line (a map key).
fn go_block(source: &str, header: &str, keys: bool) -> Vec<String> {
    let mut lines = source
        .lines()
        .skip_while(|line| line.trim() != header)
        .skip(1);
    let mut out = Vec::new();
    for line in lines.by_ref() {
        let line = line.trim();
        if line == "}" {
            return out;
        }
        if line.starts_with("//") {
            continue;
        }
        let strings = quoted(line);
        out.extend(if keys {
            strings.into_iter().take(1).collect()
        } else {
            strings
        });
    }
    panic!("block not found or not closed: {header}");
}

fn go_product(source: &str, name: &str) -> usize {
    let line = source
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(name) && line.contains('='))
        .unwrap_or_else(|| panic!("{name} not found"));
    let expr = line.split('=').nth(1).unwrap();
    expr.split('*')
        .map(|part| part.trim().parse::<usize>().unwrap())
        .product()
}

fn assert_same(name: &str, go: Vec<String>, rust: &[&str]) {
    assert!(!go.is_empty(), "{name}: nothing read from the Go source");
    assert_eq!(go, rust, "{name} differs from the Go source");
}

#[test]
fn default_lists_match_the_go_source() {
    let command = go_source("command.go");
    let readonly = go_source("command_readonly.go");
    let child = go_source("child_env.go");
    assert_same(
        "allowed binaries",
        go_block(
            &command,
            "var defaultAllowedExecBinaries = []string{",
            false,
        ),
        lists::DEFAULT_ALLOWED_EXEC_BINARIES,
    );
    assert_same(
        "shell prefixes",
        go_block(
            &command,
            "var defaultShellAllowlistPrefixes = []string{",
            false,
        ),
        lists::DEFAULT_SHELL_ALLOWLIST_PREFIXES,
    );
    assert_same(
        "blocked substrings",
        go_block(
            &command,
            "var defaultShellBlockedSubstrings = []string{",
            false,
        ),
        lists::DEFAULT_SHELL_BLOCKED_SUBSTRINGS,
    );
    assert_same(
        "blocked tokens",
        go_block(&command, "var defaultShellBlockedTokens = []string{", false),
        lists::DEFAULT_SHELL_BLOCKED_TOKENS,
    );
    assert_same(
        "journalctl options",
        go_block(
            &readonly,
            "var journalctlChangingOptions = []string{",
            false,
        ),
        lists::JOURNALCTL_CHANGING_OPTIONS,
    );
    assert_same(
        "journalctl read options named like changing ones",
        go_block(
            &readonly,
            "var journalctlReadOptionsLikeChanging = []string{",
            false,
        ),
        lists::JOURNALCTL_READ_OPTIONS_LIKE_CHANGING,
    );
    assert_same(
        "protected read paths",
        go_block(
            &readonly,
            "var builtinProtectedReadPaths = []string{",
            false,
        ),
        lists::BUILTIN_PROTECTED_READ_PATHS,
    );
    assert_same(
        "child environment",
        go_block(&child, "var allowedChildEnv = map[string]struct{}{", true),
        lists::ALLOWED_CHILD_ENV,
    );
}

#[test]
fn interpreters_limits_and_variable_names_match_the_go_source() {
    let parse = go_source("command_parse.go");
    let after = parse
        .split("func isCommandInterpreter")
        .nth(1)
        .expect("isCommandInterpreter");
    let case_line = after
        .lines()
        .find(|line| line.trim().starts_with("case \""))
        .unwrap();
    assert_same(
        "interpreters",
        quoted(case_line),
        lists::COMMAND_INTERPRETERS,
    );
    assert_eq!(
        go_product(&parse, "const maxCommandBytes"),
        lists::MAX_COMMAND_BYTES
    );

    let output = go_source("output.go");
    assert_eq!(
        go_product(&output, "DefaultCommandOutputLimit"),
        lists::DEFAULT_COMMAND_OUTPUT_LIMIT
    );
    assert_eq!(
        go_product(&output, "commandStderrCaptureLimit"),
        lists::COMMAND_STDERR_CAPTURE_LIMIT
    );

    let command = go_source("command.go");
    let names = [
        "envExecAllowlistMode",
        "envExecAllowlistAcceptRisk",
        "envExecAllowedBinaries",
        "envExecBlockedBinaries",
        "envShellAllowlistMode",
        "envShellAllowlistAcceptRisk",
        "envShellAllowlistPrefixes",
        "envShellBlockedSubstrings",
    ];
    let go: Vec<String> = names
        .iter()
        .map(|name| {
            let line = command
                .lines()
                .find(|line| line.trim().starts_with(name) && line.contains('='))
                .unwrap_or_else(|| panic!("{name} not found"));
            quoted(line).remove(0)
        })
        .collect();
    assert_eq!(
        go, COMMAND_POLICY_ENV,
        "policy variable names differ from the Go source"
    );
}
