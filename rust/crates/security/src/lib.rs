//! The rules for every command the LabTether Rust agent starts.
//!
//! Ported from the Go agent's `internal/securityruntime`: the exec
//! allowlist (`command.go`), command-line parsing and the shell allowlist
//! (`command_parse.go`), the read-only reader rules (`command_readonly.go`),
//! the child environment (`child_env.go`) and bounded output capture
//! (`output.go`). Error text is Go's, word for word.
//!
//! Settings are read once at start (`labtether_agent_config::
//! CommandSecuritySettings`) and passed in as a [`CommandPolicy`]; nothing
//! here reads the environment later. The agent starts a process only with
//! [`CommandPolicy::run`], which waits for it, or
//! [`CommandPolicy::start_streaming`], whose output is read while it runs
//! (the log stream). Both build the process in one place;
//! `rust/clippy.toml` refuses `std::process::Command::new` everywhere else.
//!
//! Not here yet: the outbound network rules, file scope and log
//! redaction, and interactive sessions (terminal and desktop).

#![forbid(unsafe_code)]
// Linux only. On macOS the agent is the App Store monitoring edition and
// starts no process at all, so this crate is empty there and nothing in
// the macOS build can start one.
#![cfg(target_os = "linux")]

mod capture;
mod child_env;
mod error;
mod goerror;
mod gotext;
pub mod lists;
mod parse;
mod policy;
mod readonly;
mod run;
mod stream;

pub use capture::CappedBuffer;
pub use child_env::{is_allowed_child_env_key, sanitized_child_env};
pub use error::Refusal;
pub use goerror::{GoOutcome, exit_error, go_outcome};
pub use parse::{normalize_executable_name, parse_command_line};
pub use policy::CommandPolicy;
pub use run::{Capture, DEFAULT_WAIT_DELAY, Finished, RunError, RunRequest};
pub use stream::{Stopper, Streaming};
