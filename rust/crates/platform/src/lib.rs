//! System readers for the LabTether Rust agent: CPU, memory, disk, network
//! and temperature telemetry, the host details the heartbeat carries, and
//! the mount, interface and process lists the device pages show.
//!
//! Linux (`linux/`) is ported from the Go agent's
//! `internal/agentplatform/linux`, `internal/agentplatform/temperature` and
//! `internal/agentplatform/netid`. macOS (`macos/`) is ported from the Go
//! agent's `internal/agentplatform/darwin` and `generic` providers and the
//! gopsutil calls behind them, reading the system without starting any
//! program, so it works inside the App Sandbox. Both give the rest of the
//! agent the same names: `Sampler`, `Sample`, `SysPaths`, `host_metadata`,
//! `heartbeat_disk_available`, `mounts::mount_list` and
//! `interfaces::interface_rows`. Parsers take text or bytes and return
//! values; the few functions that read the system are thin wrappers around
//! them.

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the LabTether Rust agent supports Linux and macOS only for now");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

/// The platform name the Hub expects in the heartbeat, the enrollment
/// request and the connection headers: Go's `runtime.GOOS`.
#[cfg(target_os = "linux")]
pub const PLATFORM: &str = "linux";
/// The platform name the Hub expects in the heartbeat, the enrollment
/// request and the connection headers: Go's `runtime.GOOS`.
#[cfg(target_os = "macos")]
pub const PLATFORM: &str = "darwin";
