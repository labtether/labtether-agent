//! The Go agent's command and child-environment cases, from the data files
//! its own tests read. A case that passes in Go and fails here (or the other
//! way round) means the two agents treat a command differently.

mod cases;

use std::collections::BTreeMap;

use cases::{CasePaths, assert_none, load, mismatch, policy};
use labtether_agent_config::Environment;
use labtether_agent_security::{is_allowed_child_env_key, parse_command_line, sanitized_child_env};
use serde::Deserialize;

#[derive(Deserialize)]
struct ParseCase {
    #[serde(default)]
    r#in: String,
    #[serde(default)]
    repeat: String,
    #[serde(default)]
    count: usize,
    args: Option<Vec<String>>,
    arg_count: Option<usize>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct PolicyCase {
    r#in: String,
    want: String,
}

#[derive(Deserialize)]
struct CaseGroup {
    group: String,
    env: BTreeMap<String, String>,
    #[serde(default)]
    protect: Vec<String>,
    #[serde(default)]
    skip_os: Vec<String>,
    #[serde(default)]
    check: String,
    cases: Vec<PolicyCase>,
}

#[derive(Deserialize)]
struct CommandCases {
    parse: Vec<ParseCase>,
    exec: Vec<CaseGroup>,
    shell: Vec<CaseGroup>,
}

fn command_cases() -> CommandCases {
    load("command_cases.json")
}

// Risk: the command line splits differently from Go, so a quoted operator
// runs or a literal argument changes.
#[test]
fn parse_cases_match_go() {
    let mut failures = Vec::new();
    for (index, case) in command_cases().parse.iter().enumerate() {
        let input = if case.repeat.is_empty() {
            case.r#in.clone()
        } else {
            case.repeat.repeat(case.count)
        };
        let label = format!(
            "parse[{index}] {:?}",
            input.chars().take(60).collect::<String>()
        );
        let result = parse_command_line(&input);
        let failure = match (&case.error, result) {
            (Some(want), result) => mismatch(&label, result.map(|_| ()), want),
            (None, Err(error)) => Some(format!(
                "{label}: error {:?}, want arguments",
                error.to_string()
            )),
            (None, Ok(args)) if case.args.as_ref().is_some_and(|want| *want != args) => {
                Some(format!("{label}: args {args:?}, want {:?}", case.args))
            }
            (None, Ok(args)) if case.arg_count.is_some_and(|want| want != args.len()) => Some(
                format!("{label}: {} args, want {:?}", args.len(), case.arg_count),
            ),
            (None, Ok(_)) => None,
        };
        failures.extend(failure);
    }
    assert_none(&failures);
}

// Risk: a program off the exec allowlist starts, or a blocked one does.
#[test]
fn exec_cases_match_go() {
    let mut failures = Vec::new();
    for group in command_cases().exec {
        let policy = policy(&group.env, &[], &[]);
        for case in &group.cases {
            let label = format!("[{}] {:?}", group.group, case.r#in);
            failures.extend(mismatch(
                &label,
                policy.validate_exec_binary(&case.r#in),
                &case.want,
            ));
        }
    }
    assert_none(&failures);
}

// Risk: a Hub command escapes the shell allowlist, the blocked words or the
// read-only reader rules.
#[test]
fn shell_cases_match_go() {
    let mut failures = Vec::new();
    for group in command_cases().shell {
        if group.skip_os.iter().any(|os| os == std::env::consts::OS) {
            continue;
        }
        let paths = CasePaths::new();
        let protect: Vec<String> = group.protect.iter().map(|p| paths.replace(p)).collect();
        let policy = policy(&group.env, &protect, &[]);
        for case in &group.cases {
            let command = paths.replace(&case.r#in);
            let result = match group.check.as_str() {
                "" => policy.validate_shell_command(&command).map(|_| ()),
                // Go's NewValidatedShellCommandContext: shell rules, then exec rules.
                "validated" => policy
                    .validate_shell_command(&command)
                    .and_then(|args| policy.validate_exec_binary(&args[0])),
                other => panic!("unknown check {other}"),
            };
            let label = format!("[{}] {command:?}", group.group);
            failures.extend(mismatch(&label, result, &paths.replace(&case.want)));
        }
    }
    assert_none(&failures);
}

#[derive(Deserialize)]
struct FilterCase {
    env: BTreeMap<String, String>,
    removed: Vec<String>,
    kept: Vec<String>,
}

#[derive(Deserialize)]
struct KeyCase {
    allowed: Vec<String>,
    refused: Vec<String>,
}

#[derive(Deserialize)]
struct ChildEnvCases {
    filter: Vec<FilterCase>,
    keys: Vec<KeyCase>,
}

// Risk: a credential in the agent's environment reaches a started command,
// or a variable is passed on by guesswork instead of failing closed.
#[test]
fn child_env_cases_match_go() {
    let cases: ChildEnvCases = load("child_env_cases.json");
    let mut failures = Vec::new();
    for (index, case) in cases.filter.iter().enumerate() {
        let env = sanitized_child_env(&Environment::from_pairs(case.env.clone()));
        let entries: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        for removed in &case.removed {
            if env.iter().any(|(key, _)| key == removed) {
                failures.push(format!("filter[{index}]: kept {removed}"));
            }
        }
        for kept in &case.kept {
            if !entries.contains(kept) {
                failures.push(format!("filter[{index}]: lost {kept:?}"));
            }
        }
    }
    for case in &cases.keys {
        failures.extend(
            case.allowed
                .iter()
                .filter(|k| !is_allowed_child_env_key(k))
                .map(|k| format!("{k:?} refused, want allowed")),
        );
        failures.extend(
            case.refused
                .iter()
                .filter(|k| is_allowed_child_env_key(k))
                .map(|k| format!("{k:?} allowed, want refused")),
        );
    }
    assert_none(&failures);
}
