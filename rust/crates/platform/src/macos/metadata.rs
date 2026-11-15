//! The heartbeat's host details on macOS, ported from Go's darwin
//! provider (`internal/agentplatform/darwin/provider.go`) and
//! `generic.buildStaticMetadata`.
//!
//! Left out on purpose, because Go learns them by running a program:
//!
//! - `tailscale_*` other than `tailscale_installed`: Go runs `tailscale`.
//! - `cap_*` and `*_backend` keys: they advertise features, and the pages
//!   behind most of them (services through `launchctl`, packages through
//!   `brew`, logs through `log`, network actions through `networksetup`)
//!   start programs. The network page advertises its own keys.
//!
//! Added: `disk_root_available_bytes` in each heartbeat (from
//! [`heartbeat_disk_available`]). Go sends it on Linux only; the console's
//! device page reads it on every platform.

use std::collections::BTreeMap;
use std::path::Path;

use labtether_agent_macos_sys as sys;

use super::host::{self, HostFacts};
use super::{disk, interfaces, netid, route};

/// Go's `runtime.GOARCH` names, which the Hub shows.
pub fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Go's `os.Hostname` on macOS: `sysctl kern.hostname`, or empty.
pub fn host_name() -> String {
    sys::sysctl_string("kern.hostname").unwrap_or_default()
}

/// Reads the facts [`host::os_metadata`] and [`host::cpu_metadata`] shape.
pub fn host_facts() -> HostFacts {
    let text = |name: &str| sys::sysctl_string(name).ok();
    let number = |name: &str| sys::sysctl_u64(name).ok();
    HostFacts {
        os_type: text("kern.ostype"),
        product_version: text("kern.osproductversion"),
        os_release: text("kern.osrelease"),
        machine: text("hw.machine"),
        host_uuid: sys::host_uuid().ok(),
        cpu_brand: text("machdep.cpu.brand_string"),
        cpu_vendor: text("machdep.cpu.vendor"),
        physical_cpus: number("hw.physicalcpu"),
        logical_cpus: number("hw.logicalcpu"),
        cpu_hz: if cfg!(target_arch = "x86_64") {
            number("hw.cpufrequency")
        } else {
            None
        },
    }
}

/// Every static key, read once at start. `search_path` is the agent's
/// `PATH`, used only to tell whether `tailscale` is installed (a file
/// check; nothing is run).
pub fn host_metadata(hostname: &str, source: &str, search_path: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    for (key, value) in [
        ("hostname", hostname),
        ("agent", source),
        ("cpu_architecture", go_arch()),
        ("os", "darwin"),
        ("platform", "darwin"),
    ] {
        metadata.insert(key.to_owned(), value.to_owned());
    }
    let facts = host_facts();
    metadata.extend(host::os_metadata(&facts));
    metadata.extend(host::cpu_metadata(&facts));
    if let Some(total) = sys::sysctl_u64("hw.memsize").ok().filter(|n| *n > 0) {
        metadata.insert("memory_total_bytes".to_owned(), total.to_string());
    }
    let (disk_total, _) = root_bytes();
    if disk_total > 0 {
        metadata.insert("disk_root_total_bytes".to_owned(), disk_total.to_string());
    }
    let links = route::links().unwrap_or_default();
    let count = links.iter().filter(|link| !link.loopback()).count();
    if count > 0 {
        metadata.insert("network_interface_count".to_owned(), count.to_string());
    }
    let nics = interfaces::nics(&links);
    let route_ip = netid::default_route_ip();
    let mac = netid::primary_mac(&nics, route_ip);
    if !mac.is_empty() {
        metadata.insert("mac_address".to_owned(), mac);
    }
    let ip = netid::primary_ip(&nics, route_ip);
    if !ip.is_empty() {
        metadata.insert("ip_address".to_owned(), ip);
    }
    let tailscale = super::command_exists("tailscale", search_path);
    metadata.insert("tailscale_installed".to_owned(), tailscale.to_string());
    metadata
}

fn root_bytes() -> (u64, u64) {
    disk::capacity(Path::new("/")).map_or((0, 0), |c| c.bytes())
}

/// Free bytes on `/` for each heartbeat (`f_bavail` times `f_bsize`), or
/// an empty value when `statfs` fails, as on Linux.
pub fn heartbeat_disk_available() -> String {
    match root_bytes() {
        (0, _) => String::new(),
        (_, available) => available.to_string(),
    }
}
