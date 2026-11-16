//! The "what can be upgraded" list: Go's `Parse*UpgradablePackages`
//! (`internal/agentcore/backends/package_upgradable_linuxpm.go`) and
//! `normalizeUpgradablePackages` (`package_upgradable.go`). Text in, rows
//! out; the page runs the query.

use std::collections::{HashMap, HashSet};

use super::gotext::{fields, go_quote, lossy, scan_lines, trim_space};
use super::package_names::valid_name;
use super::packages::{MAX_ITEMS, MAX_VERSION_BYTES, check_text, split_apk_name_version};

/// One available update as the tool printed it: bytes, checked by
/// [`normalize`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawUpgrade {
    pub name: Vec<u8>,
    pub version: Vec<u8>,
    pub available_version: Vec<u8>,
}

/// One available update after Go's checks: the installed and the
/// available version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Upgrade {
    pub name: String,
    pub version: String,
    pub available_version: String,
}

fn upgrade(name: &[u8], version: &[u8], available: &[u8]) -> RawUpgrade {
    RawUpgrade {
        name: name.to_vec(),
        version: version.to_vec(),
        available_version: available.to_vec(),
    }
}

fn too_many() -> String {
    format!("upgradable package inventory exceeds {MAX_ITEMS} entries")
}

/// Adds `item`, failing once the list holds more than [`MAX_ITEMS`].
fn push(list: &mut Vec<RawUpgrade>, item: RawUpgrade) -> Result<(), String> {
    list.push(item);
    if list.len() > MAX_ITEMS {
        return Err(too_many());
    }
    Ok(())
}

/// Go's `aptUpgradeLinePattern`, `^Inst\s+(\S+)\s+\[([^\]]+)\]\s+\((\S+)`
/// (RE2's `\s` is ASCII space, tab, newline, form feed and return).
fn apt_inst_line(line: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r');
    let skip_spaces = |s: &'_ [u8]| -> Option<usize> {
        let n = s.iter().take_while(|b| space(b)).count();
        (n > 0).then_some(n)
    };
    let word = |s: &'_ [u8]| -> usize { s.iter().take_while(|b| !space(b)).count() };
    let rest = line.strip_prefix(b"Inst")?;
    let rest = &rest[skip_spaces(rest)?..];
    let name_len = word(rest);
    let (name, rest) = rest.split_at(name_len);
    let rest = &rest[skip_spaces(rest)?..];
    let rest = rest.strip_prefix(b"[")?;
    let close = rest.iter().position(|&b| b == b']')?;
    let (current, rest) = rest.split_at(close);
    let rest = &rest[1..];
    let rest = &rest[skip_spaces(rest)?..];
    let rest = rest.strip_prefix(b"(")?;
    let available = &rest[..word(rest)];
    (!name.is_empty() && !current.is_empty() && !available.is_empty())
        .then_some((name, current, available))
}

/// `apt-get --just-print upgrade`: `Inst name [current] (available ...)`.
/// Empty output, or output with apt's progress lines, is a known form; any
/// other output without an `Inst` line is an error.
pub fn parse_apt(out: &[u8]) -> Result<Vec<RawUpgrade>, String> {
    let mut list = Vec::new();
    let mut recognized = trim_space(out).is_empty();
    let (lines, end) = scan_lines(out);
    for line in lines {
        let line = trim_space(line);
        if line.starts_with(b"Reading package lists")
            || line.starts_with(b"Calculating upgrade")
            || line.windows(10).any(|w| w == b" upgraded,")
        {
            recognized = true;
        }
        if let Some((name, current, available)) = apt_inst_line(line) {
            recognized = true;
            push(&mut list, upgrade(name, current, available))?;
        }
    }
    end.map_err(|e| format!("parse apt upgradable packages: {e}"))?;
    if !recognized {
        return Err("unrecognized apt upgradable package output".into());
    }
    Ok(list)
}

/// `dnf check-update --quiet` joined to `rpm -qa` (`name.arch\tversion`):
/// an update whose installed version is not found is left out. Where the
/// exact `name.arch` is missing, Go takes any installed `name.<arch>`; Go
/// walks a map there, so with two such entries its pick is random. This
/// takes the smallest name, so the reply does not change between calls.
pub fn parse_dnf(updates: &[u8], installed: &[u8]) -> Result<Vec<RawUpgrade>, String> {
    let mut current: HashMap<&[u8], &[u8]> = HashMap::new();
    let (lines, end) = scan_lines(installed);
    for line in lines {
        let mut parts = trim_space(line).splitn(2, |&b| b == b'\t');
        if let (Some(name), Some(version)) = (parts.next(), parts.next())
            && !name.is_empty()
            && !version.is_empty()
        {
            current.insert(name, version);
        }
        if current.len() > MAX_ITEMS * 4 {
            return Err("installed rpm lookup exceeds safe entry limit".into());
        }
    }
    end.map_err(|e| format!("parse installed rpm packages: {e}"))?;
    if !trim_space(installed).is_empty() && current.is_empty() {
        return Err("unrecognized installed rpm package output".into());
    }
    let mut by_name: Vec<(&[u8], &[u8])> = current.iter().map(|(k, v)| (*k, *v)).collect();
    by_name.sort();

    let unrecognized = || "unrecognized dnf upgradable package output".to_owned();
    let mut list = Vec::new();
    let mut recognized = trim_space(updates).is_empty();
    let (lines, end) = scan_lines(updates);
    for line in lines {
        let line = trim_space(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(b"Last metadata expiration check:") || line == b"Obsoleting Packages" {
            recognized = true;
            continue;
        }
        let words = fields(line);
        let [name, available, _, ..] = words[..] else {
            return Err(unrecognized());
        };
        recognized = true;
        if name.starts_with(b"Last") || name.starts_with(b"Obsoleting") {
            continue;
        }
        let mut version = current.get(name).copied();
        if version.is_none()
            && let Some(dot) = name.iter().rposition(|&b| b == b'.').filter(|&d| d > 0)
        {
            let prefix = [&name[..dot], b"."].concat();
            version = by_name
                .iter()
                .find(|(installed, _)| installed.starts_with(&prefix))
                .map(|(_, v)| *v);
        }
        let Some(version) = version else { continue };
        push(&mut list, upgrade(name, version, available))?;
    }
    end.map_err(|e| format!("parse dnf upgradable packages: {e}"))?;
    if !recognized {
        return Err(unrecognized());
    }
    Ok(list)
}

/// `zypper --non-interactive list-updates`: the `|` table, columns found by
/// their headings. As in Go, every line before one with a `Name` heading is
/// read as a heading line, and a heading seen on any of them counts. Go
/// indexes with -1 when the `Name` line lacks a version heading, and
/// panics on the first package row (no reply); this replies with the
/// unrecognized-output error instead.
pub fn parse_zypper(out: &[u8]) -> Result<Vec<RawUpgrade>, String> {
    let mut list = Vec::new();
    let (mut name_at, mut current_at, mut available_at) = (None, None, None);
    let mut no_updates = false;
    let (lines, end) = scan_lines(out);
    for line in lines {
        let line = trim_space(line);
        if lossy(line).to_lowercase().contains("no updates found") {
            no_updates = true;
            continue;
        }
        if line.is_empty() || line.starts_with(b"-") {
            continue;
        }
        let parts: Vec<&[u8]> = line.split(|&b| b == b'|').map(trim_space).collect();
        let Some(name_index) = name_at else {
            for (index, part) in parts.iter().enumerate() {
                match lossy(part).to_lowercase().as_str() {
                    "name" => name_at = Some(index),
                    "current version" => current_at = Some(index),
                    "available version" => available_at = Some(index),
                    _ => {}
                }
            }
            continue;
        };
        let (Some(current_index), Some(available_index)) = (current_at, available_at) else {
            return Err("unrecognized zypper upgradable package output".into());
        };
        let (Some(name), Some(current), Some(available)) = (
            parts.get(name_index),
            parts.get(current_index),
            parts.get(available_index),
        ) else {
            continue;
        };
        if name.is_empty() || current.is_empty() || available.is_empty() {
            continue;
        }
        push(&mut list, upgrade(name, current, available))?;
    }
    end.map_err(|e| format!("parse zypper upgradable packages: {e}"))?;
    if name_at.is_none() && !no_updates && !trim_space(out).is_empty() {
        return Err("unrecognized zypper upgradable package output".into());
    }
    Ok(list)
}

/// `pacman -Qu`: `name current -> available` on every line.
pub fn parse_pacman(out: &[u8]) -> Result<Vec<RawUpgrade>, String> {
    let mut list = Vec::new();
    let (lines, end) = scan_lines(out);
    for line in lines {
        match fields(trim_space(line))[..] {
            [name, current, b"->", available] => {
                push(&mut list, upgrade(name, current, available))?;
            }
            _ => return Err("unrecognized pacman upgradable package output".into()),
        }
    }
    end.map_err(|e| format!("parse pacman upgradable packages: {e}"))?;
    Ok(list)
}

/// `apk version -l <`: an optional `Installed: Available:` heading (apk 3),
/// then `name-version < available [@tag]`.
pub fn parse_apk(out: &[u8]) -> Result<Vec<RawUpgrade>, String> {
    let unrecognized = || "unrecognized apk upgradable package output".to_owned();
    let mut list = Vec::new();
    let mut heading_seen = false;
    let (lines, end) = scan_lines(out);
    for line in lines {
        let line = trim_space(line);
        if line.is_empty() {
            continue;
        }
        let words = fields(line);
        if !heading_seen && words[..] == [&b"Installed:"[..], b"Available:"] {
            heading_seen = true;
            continue;
        }
        let tagged = words.len() == 4 && words[3].len() >= 2 && words[3][0] == b'@';
        if !heading_seen || !(words.len() == 3 || tagged) || words[1] != b"<" {
            return Err(unrecognized());
        }
        let Some((name, version)) = split_apk_name_version(words[0]) else {
            return Err(format!(
                "unrecognized apk package name/version {}",
                go_quote(words[0])
            ));
        };
        push(&mut list, upgrade(name, version, words[2]))?;
    }
    end.map_err(|e| format!("parse apk upgradable packages: {e}"))?;
    if !heading_seen {
        return Err(unrecognized());
    }
    Ok(list)
}

/// Go's `normalizeUpgradablePackages`: at most [`MAX_ITEMS`]; every name
/// must pass the package name rule and both versions the text check; a
/// repeated name keeps its first entry; sorted by name.
pub fn normalize(list: Vec<RawUpgrade>) -> Result<Vec<Upgrade>, String> {
    if list.len() > MAX_ITEMS {
        return Err(too_many());
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(list.len());
    for (index, item) in list.into_iter().enumerate() {
        let name = trim_space(&item.name);
        if !valid_name(name) {
            return Err(format!(
                "upgradable package entry {} has an invalid name",
                index + 1
            ));
        }
        // `valid_name` admits ASCII only.
        let name = lossy(trim_space(name));
        let quoted = go_quote(name.as_bytes());
        let check = |value: &[u8], which: &str| {
            check_text(trim_space(value), MAX_VERSION_BYTES, true)
                .map_err(|e| format!("upgradable package {quoted} {which} version: {e}"))
        };
        let version = check(&item.version, "current")?;
        let available_version = check(&item.available_version, "available")?;
        if seen.insert(name.clone()) {
            out.push(Upgrade {
                name,
                version,
                available_version,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
