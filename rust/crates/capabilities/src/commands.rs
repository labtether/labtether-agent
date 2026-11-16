//! What the pages that start programs are given: on Linux the command
//! rules, built once by the binary from the settings read at start; on
//! macOS nothing, as the monitoring edition starts no program.

#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use labtether_agent_security::CommandPolicy;

/// The command rules the pages run their programs under.
#[derive(Debug, Clone)]
pub struct Commands {
    #[cfg(target_os = "linux")]
    pub(crate) policy: Arc<CommandPolicy>,
}

impl Commands {
    /// Pages start every program through `policy`.
    #[cfg(target_os = "linux")]
    pub fn new(policy: CommandPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// The macOS build: no page starts a program.
    #[cfg(target_os = "macos")]
    pub fn none() -> Self {
        Self {}
    }
}
