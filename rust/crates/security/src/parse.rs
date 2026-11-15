//! Go's `command_parse.go`: names, command lines and allowlist rules.

use labtether_agent_config::gopath;

use crate::error::Refusal;
use crate::gotext::{equal_fold, lower};
use crate::lists::{COMMAND_INTERPRETERS, MAX_COMMAND_BYTES};

/// Go's `normalizeExecutableName`: the lowercased last name of a path
/// (either slash), without a final `.exe`, or "" when there is none. Only
/// the name counts, so `/usr/bin/bash` and `C:\...\bash.exe` are `bash`.
pub fn normalize_executable_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let slashed = trimmed.replace('\\', "/");
    let base = gopath::base(&slashed);
    let base = base.trim();
    if base.is_empty() {
        return String::new();
    }
    let normalized = lower(base);
    match normalized.strip_suffix(".exe") {
        Some(stem) => stem.to_owned(),
        None => normalized,
    }
}

/// Go's `normalizeShellCommand`: lowercased, words joined by one space.
pub fn normalize_shell_command(raw: &str) -> String {
    lower(raw.trim())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Go's `ParseCommandLine`: splits a command into the program and its
/// arguments without a shell. Single and double quotes and backslash escapes
/// give literal text; shell operators and line breaks are refused.
pub fn parse_command_line(raw: &str) -> Result<Vec<String>, Refusal> {
    if raw.len() > MAX_COMMAND_BYTES {
        return Err(Refusal::TooLong(MAX_COMMAND_BYTES));
    }
    if raw.contains('\0') {
        return Err(Refusal::NulByte);
    }
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut have_token = false;

    for c in raw.chars() {
        if escaped {
            if c == '\n' || c == '\r' {
                return Err(Refusal::Multiline);
            }
            current.push(c);
            have_token = true;
            escaped = false;
            continue;
        }
        if let Some(open) = quote {
            match c {
                c if c == open => {
                    quote = None;
                    have_token = true;
                }
                '\\' if open == '"' => escaped = true,
                '\n' | '\r' => return Err(Refusal::Multiline),
                c => {
                    current.push(c);
                    have_token = true;
                }
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                have_token = true;
            }
            '\\' => {
                escaped = true;
                have_token = true;
            }
            ' ' | '\t' => {
                if have_token {
                    args.push(std::mem::take(&mut current));
                    have_token = false;
                }
            }
            '\n' | '\r' => return Err(Refusal::Multiline),
            ';' | '|' | '&' | '<' | '>' | '`' => return Err(Refusal::ControlOperator(c)),
            c => {
                current.push(c);
                have_token = true;
            }
        }
    }
    if escaped {
        return Err(Refusal::IncompleteEscape);
    }
    if quote.is_some() {
        return Err(Refusal::UnterminatedQuote);
    }
    if have_token {
        args.push(current);
    }
    match args.first() {
        Some(first) if !first.trim().is_empty() => Ok(args),
        _ => Err(Refusal::CommandRequired),
    }
}

fn args_have_prefix(args: &[String], prefix: &[String]) -> bool {
    !prefix.is_empty()
        && args.len() >= prefix.len()
        && prefix
            .iter()
            .zip(args)
            .all(|(rule, arg)| equal_fold(arg, rule))
}

fn is_command_interpreter(program: &str) -> bool {
    COMMAND_INTERPRETERS.contains(&normalize_executable_name(program).as_str())
}

fn is_cmd_echo(args: &[String]) -> bool {
    args.len() >= 3
        && normalize_executable_name(&args[0]) == "cmd"
        && equal_fold(&args[1], "/c")
        && equal_fold(&args[2], "echo")
}

/// Go's `shellRuleMatches`: every rule word matches the argument in its
/// place, ignoring case. More arguments are allowed except for exact (`=`)
/// rules and for command interpreters. The `cmd /c echo` rule takes values,
/// which must be plain words; a bad value is an error, not a miss.
pub fn shell_rule_matches(args: &[String], rule: &str) -> Result<bool, Refusal> {
    let rule = rule.trim();
    let exact = rule.starts_with('=');
    let Ok(rule_args) = parse_command_line(rule.strip_prefix('=').unwrap_or(rule)) else {
        return Ok(false);
    };
    if !args_have_prefix(args, &rule_args) {
        return Ok(false);
    }
    if !exact && is_cmd_echo(&rule_args) {
        validate_windows_cmd_echo(args)?;
        return Ok(true);
    }
    let extra_args = args.len() != rule_args.len();
    Ok(!(extra_args && (exact || is_command_interpreter(&rule_args[0]))))
}

/// Go's `validateWindowsCmdEcho`.
fn validate_windows_cmd_echo(args: &[String]) -> Result<(), Refusal> {
    if args.len() < 4 || !is_cmd_echo(args) {
        return Err(Refusal::CmdNotEchoProbe);
    }
    for arg in &args[3..] {
        if arg.is_empty() {
            return Err(Refusal::CmdEchoEmptyValue);
        }
        let plain = arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'));
        if !plain {
            return Err(Refusal::CmdEchoBadValue);
        }
    }
    Ok(())
}

/// Go's `containsCommandToken`: `token` is one of the words.
pub fn contains_command_token(normalized: &str, token: &str) -> bool {
    normalized.split_whitespace().any(|word| word == token)
}
