//! Why a command was refused. Each message is the Go agent's error text,
//! word for word, because the Hub shows it; the shared cases compare them.

use crate::gotext::quote;

/// A command refused by the policy before anything started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("command is required")]
    CommandRequired,
    #[error("command {} blocked by runtime policy", quote(.0))]
    ExecBlocked(String),
    #[error(
        "refusing to run {}: LABTETHER_EXEC_ALLOWLIST_MODE=false requires LABTETHER_EXEC_ALLOWLIST_ACCEPT_RISK=true to acknowledge that disabling the exec allowlist removes a significant security control",
        quote(.0)
    )]
    ExecAllowlistOffWithoutRisk(String),
    #[error("command {} is not allowlisted", quote(.0))]
    ExecNotAllowlisted(String),
    #[error("command {} must be a program name or a full path", quote(.0))]
    ExecNotFullPath(String),
    #[error("command {} is not the {} found in PATH", quote(.0), quote(.1))]
    ExecNotPathProgram(String, String),

    #[error("command exceeds {0} byte limit")]
    TooLong(usize),
    #[error("command contains a NUL byte")]
    NulByte,
    #[error("multiline commands are not supported")]
    Multiline,
    #[error("shell control operator '{0}' is not supported")]
    ControlOperator(char),
    #[error("command ends with an incomplete escape")]
    IncompleteEscape,
    #[error("command contains an unterminated quote")]
    UnterminatedQuote,

    #[error("command blocked by safety policy")]
    SafetyBlocked,
    #[error(
        "refusing shell command: LABTETHER_SHELL_COMMAND_ALLOWLIST_MODE=false requires LABTETHER_SHELL_COMMAND_ALLOWLIST_ACCEPT_RISK=true to acknowledge that disabling the shell allowlist removes a significant security control"
    )]
    ShellAllowlistOffWithoutRisk,
    #[error("command not in allowlist")]
    NotInAllowlist,
    #[error("cmd /c is limited to an echo probe with a non-empty ASCII value")]
    CmdNotEchoProbe,
    #[error("cmd /c echo probe values must not be empty")]
    CmdEchoEmptyValue,
    #[error(
        "cmd /c echo probe values may contain only ASCII letters, digits, dot, underscore, dash, or colon"
    )]
    CmdEchoBadValue,

    #[error("journalctl {0} changes system logs and is not allowed here")]
    JournalctlChangesLogs(&'static str),
    #[error("journalctl {0} can stand for {1}, which changes system logs, and is not allowed here")]
    JournalctlCanStandFor(String, &'static str),
    #[error(
        "journalctl {0} can stand for an option that changes system logs and is not allowed here"
    )]
    JournalctlCanStandForSeveral(String),
    #[error("recursive grep is not allowed here")]
    RecursiveGrep,
    #[error("reading {0} is not allowed here")]
    ProtectedRead(String),
}
