//! Linux readers for the LabTether Rust agent: CPU, memory, disk, network
//! and temperature telemetry, and the host details the heartbeat carries.
//!
//! Ported from the Go agent's `internal/agentplatform/linux`,
//! `internal/agentplatform/temperature` and `internal/agentplatform/netid`,
//! with the same formulas and the same choices. Parsers take text and return
//! values; the few functions that read the system are thin wrappers around
//! them. There is no trait here until a second system needs one.

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("the LabTether Rust agent supports Linux only for now");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
