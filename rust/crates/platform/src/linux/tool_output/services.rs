//! The systemd service list, from `systemctl` output: Go's
//! `LinuxServiceBackend.ListServices`, `collectEnabledStatesLinux` and
//! `unloadedServiceUnits` (`internal/agentcore/backends/service_backend_systemd.go`).
//! Text in, rows out; the page runs the two commands.

use std::collections::{HashMap, HashSet};

use super::gotext::{fields, lossy, trim_space};

/// `systemctl list-units` with the arguments Go passes.
pub const LIST_UNITS_ARGS: [&str; 6] = [
    "list-units",
    "--type=service",
    "--all",
    "--no-pager",
    "--plain",
    "--no-legend",
];

/// `systemctl list-unit-files` with the arguments Go passes.
pub const LIST_UNIT_FILES_ARGS: [&str; 5] = [
    "list-unit-files",
    "--type=service",
    "--no-pager",
    "--plain",
    "--no-legend",
];

/// One service, with Go's field values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRow {
    /// The unit name without `.service`.
    pub name: String,
    pub description: String,
    pub active_state: String,
    pub sub_state: String,
    /// The unit file state from `list-unit-files`, or empty.
    pub enabled: String,
    /// Empty for a unit `list-units` did not list.
    pub load_state: String,
}

/// Go's lines: the whole output trimmed, split at `\n`, each line trimmed,
/// empty lines dropped. No length limit (Go uses `strings.Split`).
fn lines(out: &[u8]) -> impl Iterator<Item = &[u8]> {
    trim_space(out)
        .split(|&b| b == b'\n')
        .map(trim_space)
        .filter(|line| !line.is_empty())
}

/// The unit file states from `list-unit-files`: the first word of a line
/// to its second; a later line for the same unit wins, as in Go's map.
pub fn parse_unit_files(out: &[u8]) -> HashMap<String, String> {
    let mut states = HashMap::new();
    for line in lines(out) {
        if let [unit, state, ..] = fields(line)[..] {
            states.insert(lossy(unit), lossy(state));
        }
    }
    states
}

/// The services: every `list-units` line with at least four words
/// (`UNIT LOAD ACTIVE SUB DESCRIPTION...`, the description's words joined
/// by one space), in `systemctl`'s order, then the installed services it
/// left out (see [`unloaded_units`]).
pub fn parse_units(out: &[u8], enabled: &HashMap<String, String>) -> Vec<ServiceRow> {
    let mut rows = Vec::new();
    let mut listed = HashSet::new();
    for line in lines(out) {
        let words = fields(line);
        let [unit, load, active, sub, description @ ..] = &words[..] else {
            continue;
        };
        let unit = lossy(unit);
        let description: Vec<String> = description.iter().map(|w| lossy(w)).collect();
        rows.push(ServiceRow {
            name: unit.strip_suffix(".service").unwrap_or(&unit).to_owned(),
            description: description.join(" "),
            active_state: lossy(active),
            sub_state: lossy(sub),
            enabled: enabled.get(&unit).cloned().unwrap_or_default(),
            load_state: lossy(load),
        });
        listed.insert(unit);
    }
    rows.extend(unloaded_units(enabled, &listed));
    rows
}

/// Go's `unloadedServiceUnits`: installed services `list-units` leaves out
/// because systemd has not loaded them since boot (a disabled service that
/// has not run), sorted by unit name, as inactive and dead. Static, masked,
/// alias and template units are left out.
pub fn unloaded_units(
    enabled: &HashMap<String, String>,
    listed: &HashSet<String>,
) -> Vec<ServiceRow> {
    const STARTABLE: [&str; 6] = [
        "enabled",
        "enabled-runtime",
        "disabled",
        "indirect",
        "linked",
        "linked-runtime",
    ];
    let mut units: Vec<&String> = enabled
        .iter()
        .filter(|(unit, state)| {
            STARTABLE.contains(&state.as_str())
                && !listed.contains(*unit)
                && unit.ends_with(".service")
                && !unit.contains("@.")
        })
        .map(|(unit, _)| unit)
        .collect();
    units.sort();
    units
        .into_iter()
        .map(|unit| ServiceRow {
            name: unit.strip_suffix(".service").unwrap_or(unit).to_owned(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            enabled: enabled[unit].clone(),
            ..ServiceRow::default()
        })
        .collect()
}
