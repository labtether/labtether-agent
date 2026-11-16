//! The macOS readers: the monitoring set that works inside the App Sandbox.
//!
//! Everything comes from system calls (through `labtether-agent-macos-sys`,
//! the one crate with `unsafe` code); no program is started. Where the Go
//! agent learns a value by running a program (`df`, `netstat`, `sw_vers`,
//! `ioreg`, `networksetup`, `tailscale`, `osx-cpu-temp`), this module reads
//! the same value from the kernel or leaves it out; each case is listed in
//! the module that owns it.
//!
//! `disk.rs`, `netid.rs` and `lookpath.rs` are shared with Linux: they
//! hold no Linux-only call (`statfs`, a UDP socket, `faccessat`), so the
//! files are compiled here from the `linux/` folder as they are.

#[path = "../linux/disk.rs"]
pub mod disk;
pub mod host;
pub mod interfaces;
#[path = "../linux/lookpath.rs"]
mod lookpath;
pub mod metadata;
pub mod mounts;
#[path = "../linux/netid.rs"]
pub mod netid;
pub mod route;
pub mod sampler;

pub use lookpath::{LookPathError, command_exists, look_path};
pub use metadata::{heartbeat_disk_available, host_metadata, host_name};
pub use sampler::{Sample, Sampler, SysPaths, TemperatureError};

#[cfg(test)]
mod tests;
