//! Host details read once at start, ported from Go's
//! `provider_metadata.go`: `/etc/os-release`, the kernel version, DMI
//! firmware fields and `/proc/cpuinfo`.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::path::Path;

use super::read_trimmed;

/// Go's `parseKeyValueFile`: `KEY=value` lines, quotes trimmed, the last
/// value for a key kept.
pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            (key.trim().to_owned(), value.to_owned())
        })
        .collect()
}

/// Go's `readOSMetadata` from the os-release text and the two kernel files.
pub fn os_metadata(
    os_release: Option<&str>,
    kernel_release: Option<String>,
    kernel_version: Option<String>,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    let release = os_release.map(parse_os_release).unwrap_or_default();
    for (from, to) in [
        ("PRETTY_NAME", "os_pretty_name"),
        ("NAME", "os_name"),
        ("ID", "os_id"),
        ("ID_LIKE", "os_id_like"),
        ("VERSION_ID", "os_version_id"),
        ("VERSION", "os_version"),
    ] {
        if let Some(value) = release
            .get(from)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            metadata.insert(to.to_owned(), value.to_owned());
        }
    }
    if let Some(value) = kernel_release {
        metadata.insert("kernel_release".to_owned(), value);
    }
    if let Some(value) = kernel_version {
        metadata.insert("kernel_version".to_owned(), value);
    }
    metadata
}

/// The DMI files Go reads and the metadata key for each.
pub const DMI_FIELDS: [(&str, &str); 11] = [
    ("sys_vendor", "computer_vendor"),
    ("product_name", "computer_model"),
    ("product_version", "computer_version"),
    ("board_vendor", "motherboard_vendor"),
    ("board_name", "motherboard_model"),
    ("board_version", "motherboard_version"),
    ("chassis_vendor", "chassis_vendor"),
    ("chassis_type", "chassis_type"),
    ("bios_vendor", "bios_vendor"),
    ("bios_version", "bios_version"),
    ("bios_date", "bios_date"),
];

/// Go's `readDMIInfo` under `dmi_dir` (`/sys/class/dmi/id`).
pub fn dmi_metadata(dmi_dir: &Path) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    for (file, key) in DMI_FIELDS {
        let Some(mut value) = read_trimmed(&dmi_dir.join(file)) else {
            continue;
        };
        if key == "chassis_type" {
            value = chassis_type_label(&value);
        }
        metadata.insert(key.to_owned(), value);
    }
    metadata
}

/// Go's `normalizeChassisType`: the SMBIOS chassis code as a word.
pub fn chassis_type_label(raw: &str) -> String {
    const LABELS: [&str; 36] = [
        "other",
        "unknown",
        "desktop",
        "low profile desktop",
        "pizza box",
        "mini tower",
        "tower",
        "portable",
        "laptop",
        "notebook",
        "handheld",
        "docking station",
        "all in one",
        "sub notebook",
        "space-saving",
        "lunch box",
        "main server chassis",
        "expansion chassis",
        "sub chassis",
        "bus expansion chassis",
        "peripheral chassis",
        "raid chassis",
        "rack mount chassis",
        "sealed-case pc",
        "multi-system chassis",
        "compact pci",
        "advanced tca",
        "blade",
        "blade enclosure",
        "tablet",
        "convertible",
        "detachable",
        "iot gateway",
        "embedded pc",
        "mini pc",
        "stick pc",
    ];
    raw.parse::<i64>()
        .ok()
        .and_then(|code| usize::try_from(code).ok())
        .and_then(|code| code.checked_sub(1))
        .and_then(|index| LABELS.get(index))
        .map_or_else(|| raw.to_owned(), |label| (*label).to_owned())
}

/// Go's `readCPUInfo` over `/proc/cpuinfo` text. `fallback_logical` is the
/// CPU count Go's `runtime.NumCPU` gives, used when no `processor` line
/// exists.
pub fn cpu_metadata(
    cpuinfo: Option<&str>,
    fallback_logical: usize,
    max_khz: Option<&str>,
    min_khz: Option<&str>,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    let (mut logical, mut cores_per_socket, mut threads_per_socket) = (0usize, 0i64, 0i64);
    let mut physical_ids = HashSet::new();
    let set_once = |key: &str, value: &str, metadata: &mut BTreeMap<String, String>| {
        if !value.is_empty() && !metadata.contains_key(key) {
            metadata.insert(key.to_owned(), value.to_owned());
        }
    };
    for line in cpuinfo.unwrap_or_default().lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let positive = || value.parse::<i64>().ok().filter(|n| *n > 0);
        match key.trim() {
            "processor" => logical += 1,
            "physical id" if !value.is_empty() => {
                physical_ids.insert(value.to_owned());
            }
            "model name" => set_once("cpu_model", value, &mut metadata),
            "vendor_id" => set_once("cpu_vendor", value, &mut metadata),
            "cpu cores" if cores_per_socket == 0 => cores_per_socket = positive().unwrap_or(0),
            "siblings" if threads_per_socket == 0 => threads_per_socket = positive().unwrap_or(0),
            _ => {}
        }
    }
    if cpuinfo.is_some() {
        if logical == 0 {
            logical = fallback_logical;
        }
        if logical > 0 {
            metadata.insert("cpu_threads_logical".to_owned(), logical.to_string());
        }
        let mut sockets = physical_ids.len();
        if sockets == 0 && logical > 0 {
            sockets = 1;
        }
        if sockets > 0 {
            metadata.insert("cpu_sockets".to_owned(), sockets.to_string());
        }
        if cores_per_socket > 0 {
            metadata.insert(
                "cpu_cores_per_socket".to_owned(),
                cores_per_socket.to_string(),
            );
            if sockets > 0 {
                let physical = cores_per_socket * i64::try_from(sockets).unwrap_or(0);
                metadata.insert("cpu_cores_physical".to_owned(), physical.to_string());
            }
        }
        if threads_per_socket > 0 {
            metadata.insert(
                "cpu_threads_per_socket".to_owned(),
                threads_per_socket.to_string(),
            );
        }
        for (key, raw) in [("cpu_max_mhz", max_khz), ("cpu_min_mhz", min_khz)] {
            if let Some(mhz) = raw.and_then(khz_text_as_mhz) {
                metadata.insert(key.to_owned(), format!("{mhz:.0}"));
            }
        }
    }
    metadata
}

/// Go's `readKiloHertzFileAsMHz` on the file's text: a positive finite
/// number of kHz as MHz, else `None`.
pub fn khz_text_as_mhz(raw: &str) -> Option<f64> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "None" {
        return None;
    }
    let value: f64 = raw.parse().ok()?;
    (value.is_finite() && value > 0.0).then_some(value / 1000.0)
}
