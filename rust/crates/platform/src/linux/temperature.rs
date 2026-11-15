//! Host temperature, ported from Go's `temperature.ReadCelsius` on Linux.
//!
//! Go asks gopsutil first and falls back to its own sysfs scan:
//!
//! 1. gopsutil reads every `hwmon*/temp*_input` (or, when there are none,
//!    `hwmon*/device/temp*_input`) with its `name` and `temp*_label`. If any
//!    of those reads fails, the whole step fails, even when other sensors
//!    were read. Otherwise the plausible reading (-40 to 150 °C) with the
//!    best sensor priority wins (CPU, then GPU, then board), the hottest on
//!    a tie. gopsutil's `thermal_zone` branch for hosts without hwmon never
//!    matches a file (its pattern ends in `/`), so such hosts reach step 2.
//! 2. The fallback reads `thermal_zone*/temp`, `hwmon*/temp*_input` and
//!    `hwmon*/device/temp*_input` and takes the hottest plausible value.
//!    Values above 1000 in size are millidegrees.
//!
//! When neither step finds a value, no temperature is sent.

use std::path::{Path, PathBuf};

const MIN_PLAUSIBLE: f64 = -40.0;
const MAX_PLAUSIBLE: f64 = 150.0;

/// Both steps failed; the text follows Go's error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("gopsutil temperature probe failed: {sensors}; linux sysfs fallback failed: {fallback}")]
pub struct TemperatureError {
    pub sensors: String,
    pub fallback: String,
}

/// One sensor as gopsutil names it (`<hwmon name>_<label>`).
#[derive(Debug, Clone, PartialEq)]
pub struct SensorReading {
    pub key: String,
    pub celsius: f64,
}

/// Reads the temperature under `sys` (`/sys` on a real host).
pub fn read_celsius(sys: &Path) -> Result<f64, TemperatureError> {
    let sensors = match sensor_readings(sys) {
        Ok(readings) => match select_preferred(&readings) {
            Some((celsius, _)) => return Ok(celsius),
            None => "no usable temperature samples returned".to_owned(),
        },
        Err(error) => error,
    };
    sysfs_fallback(sys).map_err(|fallback| TemperatureError { sensors, fallback })
}

/// Go's `isPlausibleTemperature`.
pub fn is_plausible(celsius: f64) -> bool {
    (MIN_PLAUSIBLE..=MAX_PLAUSIBLE).contains(&celsius)
}

/// Go's `temperatureSensorPriority`.
pub fn sensor_priority(key: &str) -> i32 {
    let key = key.trim().to_lowercase();
    let any = |tokens: &[&str]| tokens.iter().any(|token| key.contains(token));
    if any(&[
        "cpu", "package", "tdie", "tctl", "peci", "core", "die", "soc", "ecpu", "pcpu",
    ]) {
        4
    } else if any(&["gpu", "graphics", "igpu"]) {
        3
    } else if any(&["memory", "dram", "chipset", "pch", "ambient", "board"]) {
        2
    } else {
        1
    }
}

/// Go's `selectPreferredTemperature`: the plausible reading with the
/// highest priority, the hottest among equals.
pub fn select_preferred(readings: &[SensorReading]) -> Option<(f64, &str)> {
    let mut best: Option<(i32, f64, &str)> = None;
    for reading in readings {
        let celsius = reading.celsius;
        if !celsius.is_finite() || !is_plausible(celsius) {
            continue;
        }
        let priority = sensor_priority(&reading.key);
        let better = match best {
            None => true,
            Some((best_priority, best_celsius, _)) => {
                priority > best_priority || (priority == best_priority && celsius > best_celsius)
            }
        };
        if better {
            best = Some((priority, celsius, reading.key.as_str()));
        }
    }
    best.map(|(_, celsius, key)| (celsius, key))
}

/// Go's `parseSysfsTemperatureValue`: millidegrees when above 1000 in size.
pub fn parse_sysfs_value(raw: &str) -> Option<f64> {
    let value: f64 = raw.trim().parse().ok()?;
    Some(if value.abs() > 1000.0 {
        value / 1000.0
    } else {
        value
    })
}

/// Entries of `dir` whose names start with `prefix` and end with `suffix`,
/// sorted, as Go's `filepath.Glob` lists them.
fn glob(dir: &Path, prefix: &str, suffix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        })
        .collect();
    names.sort();
    names.into_iter().map(|name| dir.join(name)).collect()
}

/// `<sys>/class/<class>/<prefix>*/<sub><file prefix>*<file suffix>`.
fn glob_two(sys: &Path, class: &str, prefix: &str, sub: &str, file: (&str, &str)) -> Vec<PathBuf> {
    glob(&sys.join("class").join(class), prefix, "")
        .into_iter()
        .flat_map(|dir| glob(&dir.join(sub), file.0, file.1))
        .collect()
}

fn hwmon_inputs(sys: &Path, device: bool) -> Vec<PathBuf> {
    let sub = if device { "device" } else { "" };
    glob_two(sys, "hwmon", "hwmon", sub, ("temp", "_input"))
}

/// gopsutil's `TemperaturesWithContext` on Linux. Any failed read fails the
/// call, as gopsutil returns its warnings as the error.
fn sensor_readings(sys: &Path) -> Result<Vec<SensorReading>, String> {
    let mut files = hwmon_inputs(sys, false);
    if files.is_empty() {
        files = hwmon_inputs(sys, true);
    }
    let mut readings = Vec::with_capacity(files.len());
    let mut warnings = 0usize;
    for file in files {
        let dir = file.parent().unwrap_or(Path::new("/"));
        let base = file
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split('_').next())
            .unwrap_or_default();
        let label = std::fs::read_to_string(dir.join(format!("{base}_label")))
            .map(|raw| raw.trim().to_lowercase().replace(' ', "_"))
            .unwrap_or_default();
        let Ok(name) = std::fs::read_to_string(dir.join("name")) else {
            warnings += 1;
            continue;
        };
        let mut key = name.trim().to_owned();
        if !label.is_empty() {
            key = format!("{key}_{label}");
        }
        let value = std::fs::read_to_string(&file)
            .ok()
            .and_then(|raw| raw.trim().parse::<f64>().ok());
        match value {
            Some(value) => readings.push(SensorReading {
                key,
                celsius: value / 1000.0,
            }),
            None => warnings += 1,
        }
    }
    if warnings > 0 {
        return Err(format!("Number of warnings: {warnings}"));
    }
    Ok(readings)
}

/// Go's `readTemperatureFromLinuxSysfs`.
fn sysfs_fallback(sys: &Path) -> Result<f64, String> {
    let mut paths: Vec<PathBuf> = glob(&sys.join("class/thermal"), "thermal_zone", "")
        .into_iter()
        .map(|dir| dir.join("temp"))
        .filter(|path| path.exists())
        .collect();
    paths.extend(hwmon_inputs(sys, false));
    paths.extend(hwmon_inputs(sys, true));
    if paths.is_empty() {
        return Err("no linux temperature sensor files discovered".to_owned());
    }
    paths
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .filter_map(|raw| parse_sysfs_value(&raw))
        .filter(|celsius| is_plausible(*celsius))
        .fold(None, |best: Option<f64>, celsius| {
            Some(best.map_or(celsius, |best| best.max(celsius)))
        })
        .ok_or_else(|| "linux temperature sensors discovered but no valid readings".to_owned())
}
