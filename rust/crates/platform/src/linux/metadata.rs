//! The heartbeat's host details, ported from Go's `collectHostMetadata`.
//!
//! Left out on purpose, because this agent cannot back them or would have to
//! run a program to learn them:
//!
//! - `cap_*`, `service_backend`, `package_backend`, `log_backend`,
//!   `network_backend`, `network_action_backend`: they advertise features.
//! - `tailscale_*` other than `tailscale_installed`: Go runs `tailscale`.

use std::collections::BTreeMap;
use std::path::Path;

use super::{disk, host, netid, netlink, procfs, read_trimmed};

/// Go's `runtime.GOARCH` names, which the Hub shows.
pub fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

/// Go's `runtime.NumCPU` on Linux: the CPUs this process may run on.
fn affinity_cpus() -> usize {
    rustix::thread::sched_getaffinity(None)
        .map(|set| set.count() as usize)
        .unwrap_or(1)
}

/// Every static key, read once at start. `search_path` is the agent's
/// `PATH`, used only to tell whether `tailscale` is installed.
pub fn host_metadata(hostname: &str, source: &str, search_path: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    for (key, value) in [
        ("hostname", hostname),
        ("agent", source),
        ("cpu_architecture", go_arch()),
        ("os", "linux"),
        ("platform", "linux"),
    ] {
        metadata.insert(key.to_owned(), value.to_owned());
    }
    let os_release = std::fs::read_to_string("/etc/os-release").ok();
    metadata.extend(host::os_metadata(
        os_release.as_deref(),
        read_trimmed(Path::new("/proc/sys/kernel/osrelease")),
        read_trimmed(Path::new("/proc/sys/kernel/version")),
    ));
    metadata.extend(host::dmi_metadata(Path::new("/sys/class/dmi/id")));
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok();
    let freq = "/sys/devices/system/cpu/cpu0/cpufreq";
    metadata.extend(host::cpu_metadata(
        cpuinfo.as_deref(),
        affinity_cpus(),
        read_trimmed(&Path::new(freq).join("cpuinfo_max_freq")).as_deref(),
        read_trimmed(&Path::new(freq).join("cpuinfo_min_freq")).as_deref(),
    ));

    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let memory_total = procfs::mem_total_bytes(&meminfo);
    if memory_total > 0 {
        metadata.insert("memory_total_bytes".to_owned(), memory_total.to_string());
    }
    let (disk_total, disk_available) = root_bytes();
    if disk_total > 0 {
        metadata.insert("disk_root_total_bytes".to_owned(), disk_total.to_string());
        metadata.insert(
            "disk_root_available_bytes".to_owned(),
            disk_available.to_string(),
        );
    }
    let net_dev = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let interfaces = procfs::interface_count(&net_dev);
    if interfaces > 0 {
        metadata.insert("network_interface_count".to_owned(), interfaces.to_string());
    }
    let nics = netlink::interfaces().unwrap_or_default();
    let route = netid::default_route_ip();
    let mac = netid::primary_mac(&nics, route);
    if !mac.is_empty() {
        metadata.insert("mac_address".to_owned(), mac);
    }
    let ip = netid::primary_ip(&nics, route);
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

/// Go's `HeartbeatMetadata`: free bytes on `/`, read for each heartbeat, or
/// an empty value when `statfs` fails.
pub fn heartbeat_disk_available() -> String {
    match root_bytes() {
        (0, _) => String::new(),
        (_, available) => available.to_string(),
    }
}
