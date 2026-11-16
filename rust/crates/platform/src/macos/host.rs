//! Host details on macOS, ported from gopsutil's `host.Info` and `cpu.Info`
//! (v4.26.9) as Go's `generic.buildStaticMetadata` and the darwin
//! provider's `applyMacOSName` use them. The values come from `sysctl` and
//! `gethostuuid`; these functions only shape them.
//!
//! Where Go runs a program, this reads the kernel instead:
//!
//! - `os_version`: Go runs `sw_vers -productVersion`; this reads
//!   `kern.osproductversion`, the same text.
//! - `host_id`: Go runs `ioreg -rd1 -c IOPlatformExpertDevice` for
//!   `IOPlatformUUID`; this reads the same UUID with `gethostuuid`.
//!
//! Left out on purpose:
//!
//! - `cpu_max_mhz` on Apple silicon: gopsutil reads an undocumented IOKit
//!   property (`voltage-states5-sram` of `pmgr`); on an M4 Go then reports
//!   `4`, because it divides a kHz value by 1,000,000. On Intel Macs it is
//!   `hw.cpufrequency` in MHz, as in Go.
//!
//! gopsutil fails `host.Info` as a whole when one part fails (`ioreg`
//! missing, say), and Go then sends none of these keys; here each key is
//! left out on its own.

use std::collections::BTreeMap;

/// What the host tells about itself, each `None` when its read failed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// `kern.ostype` (`Darwin`).
    pub os_type: Option<String>,
    /// `kern.osproductversion` (`27.2.1`).
    pub product_version: Option<String>,
    /// `kern.osrelease` (`27.2.0`).
    pub os_release: Option<String>,
    /// `hw.machine`, the `uname` machine (`arm64`, `x86_64`).
    pub machine: Option<String>,
    /// `gethostuuid`.
    pub host_uuid: Option<[u8; 16]>,
    /// `machdep.cpu.brand_string`.
    pub cpu_brand: Option<String>,
    /// `machdep.cpu.vendor` (Intel only).
    pub cpu_vendor: Option<String>,
    /// `hw.physicalcpu`.
    pub physical_cpus: Option<u64>,
    /// `hw.logicalcpu`.
    pub logical_cpus: Option<u64>,
    /// `hw.cpufrequency` in Hz (Intel only).
    pub cpu_hz: Option<u64>,
}

fn present(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.trim().is_empty())
}

/// A UUID as `ioreg` prints it, lowercased as gopsutil returns it.
pub fn uuid_text(id: &[u8; 16]) -> String {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// The OS keys: gopsutil's `Platform` (`kern.ostype`, lowercased),
/// `PlatformVersion` (lowercased), `KernelVersion` (lowercased),
/// `KernelArch` and `HostID`; then `applyMacOSName`, which names a `darwin`
/// platform `macOS` and builds `os_pretty_name` from the version.
pub fn os_metadata(facts: &HostFacts) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    let mut put = |key: &str, value: String| {
        if !value.trim().is_empty() {
            metadata.insert(key.to_owned(), value);
        }
    };
    put(
        "os_name",
        facts.os_type.as_deref().unwrap_or_default().to_lowercase(),
    );
    put(
        "os_version",
        facts
            .product_version
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_lowercase(),
    );
    put(
        "kernel_version",
        facts
            .os_release
            .as_deref()
            .unwrap_or_default()
            .to_lowercase(),
    );
    put("kernel_arch", facts.machine.clone().unwrap_or_default());
    put(
        "host_id",
        facts.host_uuid.as_ref().map(uuid_text).unwrap_or_default(),
    );
    if metadata
        .get("os_name")
        .is_some_and(|name| name.trim().eq_ignore_ascii_case("darwin"))
    {
        let version = metadata.get("os_version").map_or("", |v| v.trim());
        let pretty = format!("macOS {version}").trim().to_owned();
        metadata.insert("os_name".to_owned(), "macOS".to_owned());
        metadata.insert("os_pretty_name".to_owned(), pretty);
    }
    metadata
}

/// The CPU keys Go sets from `cpu.Info` and `cpu.Counts`.
pub fn cpu_metadata(facts: &HostFacts) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    if let Some(brand) = present(&facts.cpu_brand) {
        metadata.insert("cpu_model".to_owned(), brand.to_owned());
    }
    if let Some(vendor) = present(&facts.cpu_vendor) {
        metadata.insert("cpu_vendor".to_owned(), vendor.to_owned());
    }
    for (key, count) in [
        ("cpu_cores_physical", facts.physical_cpus),
        ("cpu_threads_logical", facts.logical_cpus),
    ] {
        if let Some(count) = count.filter(|n| *n > 0) {
            metadata.insert(key.to_owned(), count.to_string());
        }
    }
    if let Some(hz) = facts.cpu_hz.filter(|hz| *hz > 0) {
        metadata.insert(
            "cpu_max_mhz".to_owned(),
            format!("{:.0}", hz as f64 / 1_000_000.0),
        );
    }
    metadata
}
