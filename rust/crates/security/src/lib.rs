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
//! here reads the environment later. [`CommandPolicy::run`] is the only way
//! the agent starts a process; `rust/clippy.toml` refuses
//! `std::process::Command::new` everywhere else.
//!
//! Not here yet: the outbound network rules, file scope and log
//! redaction, and long-running processes (terminal and desktop sessions).

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("the LabTether Rust agent supports Linux only for now");

mod capture;
mod child_env;
mod error;
mod gotext;
pub mod lists;
mod parse;
mod policy;
mod readonly;
mod run;

pub use capture::CappedBuffer;
pub use child_env::{is_allowed_child_env_key, sanitized_child_env};
pub use error::Refusal;
pub use parse::{normalize_executable_name, parse_command_line};
pub use policy::CommandPolicy;
pub use run::{Capture, DEFAULT_WAIT_DELAY, Finished, RunError, RunRequest};
