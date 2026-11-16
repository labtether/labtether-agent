//! The installed package list, from the package manager's query tool: Go's
//! `collectLinuxPackages*`, `ParsePacmanPackageList`, `ParseAPKPackageList`
//! (`internal/agentcore/backends/package_backend_linuxpm.go`) and
//! `validateInstalledPackageInventory` (`package_upgradable.go`).
//! Text in, rows out; the page picks the tool and runs it.

use super::gotext::{ERR_TOO_LONG, fields, scan_lines, trim_space};

/// Go's `MaxPackageInventoryItems`: more entries than this is an error, not
/// a cut list.
pub const MAX_ITEMS: usize = 10_000;
/// Go's `MaxPackageInventoryVersionBytes`.
pub const MAX_VERSION_BYTES: usize = 1_024;
const MAX_NAME_BYTES: usize = 1_024;
const MAX_STATUS_BYTES: usize = 256;

/// The query tools Go reads the installed list with, and their arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lister {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
}

impl Lister {
    pub fn program(self) -> &'static str {
        match self {
            Self::Dpkg => "dpkg-query",
            Self::Rpm => "rpm",
            Self::Pacman => "pacman",
            Self::Apk => "apk",
        }
    }

    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::Dpkg => &["-W", "-f", "${Package}\t${Version}\t${Status}\n"],
            Self::Rpm => &[
                "-qa",
                "--queryformat",
                "%{NAME}\t%{VERSION}-%{RELEASE}\tinstalled\n",
            ],
            Self::Pacman => &["-Q"],
            Self::Apk => &["info", "-v"],
        }
    }

    /// Parses this tool's output. Go's dpkg and rpm readers stop quietly at
    /// a line too long for its scanner; the pacman and apk readers report it.
    pub fn parse(self, out: &[u8]) -> Result<Vec<RawPackage>, String> {
        match self {
            Self::Dpkg => Ok(parse_tab_lines(out, true)),
            Self::Rpm => Ok(parse_tab_lines(out, false)),
            Self::Pacman => parse_pacman(out),
            Self::Apk => parse_apk(out),
        }
    }
}

/// One package as the tool printed it: bytes, checked by [`validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPackage {
    pub name: Vec<u8>,
    pub version: Vec<u8>,
    pub status: Vec<u8>,
}

/// One package after Go's checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub status: String,
}

fn raw(name: &[u8], version: &[u8], status: &[u8]) -> RawPackage {
    RawPackage {
        name: name.to_vec(),
        version: version.to_vec(),
        status: status.to_vec(),
    }
}

/// `name\tversion\tstatus` lines (dpkg-query and rpm): each line trimmed,
/// cut at the first two tabs; fewer than three parts is skipped. For dpkg
/// the status is the last word of `install ok installed`.
fn parse_tab_lines(out: &[u8], last_word_status: bool) -> Vec<RawPackage> {
    let (lines, _too_long_ends_quietly) = scan_lines(out);
    let mut rows = Vec::new();
    for line in lines {
        let line = trim_space(line);
        let mut parts = line.splitn(3, |&b| b == b'\t');
        let (Some(name), Some(version), Some(status)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let status = match fields(status).last() {
            Some(word) if last_word_status => word,
            _ => status,
        };
        rows.push(raw(name, version, status));
    }
    rows
}

/// `pacman -Q`: `name version`; a line with another number of words is
/// skipped.
pub fn parse_pacman(out: &[u8]) -> Result<Vec<RawPackage>, String> {
    let (lines, end) = scan_lines(out);
    end.map_err(|_| format!("parse pacman package list: {ERR_TOO_LONG}"))?;
    Ok(lines
        .into_iter()
        .filter_map(|line| match fields(line)[..] {
            [name, version] => Some(raw(name, version, b"installed")),
            _ => None,
        })
        .collect())
}

/// Go's `apkPackageVersionPattern`,
/// `^(.+)-([0-9][0-9A-Za-z._+~:-]*(?:-r[0-9]+)?)$`: the name is everything
/// up to the last `-` that is followed by a digit and only version
/// characters to the end (the regexp's greedy name takes the last such
/// split). The optional `-r[0-9]+` is made of version characters already.
pub fn split_apk_name_version(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let version_char = |b: &u8| b.is_ascii_alphanumeric() || b"._+~:-".contains(b);
    (1..text.len()).rev().find_map(|dash| {
        let (name, version) = (&text[..dash], &text[dash + 1..]);
        let fits = text[dash] == b'-'
            && version.first().is_some_and(u8::is_ascii_digit)
            && version.iter().all(version_char);
        fits.then_some((name, version))
    })
}

/// `apk info -v`: `name-version`; a line that does not split is skipped.
pub fn parse_apk(out: &[u8]) -> Result<Vec<RawPackage>, String> {
    let (lines, end) = scan_lines(out);
    end.map_err(|_| format!("parse apk package list: {ERR_TOO_LONG}"))?;
    Ok(lines
        .into_iter()
        .filter_map(|line| split_apk_name_version(trim_space(line)))
        .map(|(name, version)| raw(name, version, b"installed"))
        .collect())
}

/// Go's `validatePackageInventoryText`.
pub fn check_text(value: &[u8], max_bytes: usize, required: bool) -> Result<String, String> {
    if required && trim_space(value).is_empty() {
        return Err("is required".into());
    }
    let text = std::str::from_utf8(value).map_err(|_| "is not valid UTF-8".to_owned())?;
    if text.len() > max_bytes {
        return Err(format!("exceeds {max_bytes} bytes"));
    }
    if text.chars().any(|c| c < '\u{20}' || c == '\u{7f}') {
        return Err("contains a control character".into());
    }
    Ok(text.to_owned())
}

/// Go's `validateInstalledPackageInventory`: at most [`MAX_ITEMS`] entries;
/// each name, version and status checked, the first failure is the error.
pub fn validate(rows: Vec<RawPackage>) -> Result<Vec<Package>, String> {
    if rows.len() > MAX_ITEMS {
        return Err(format!(
            "installed package inventory exceeds {MAX_ITEMS} entries"
        ));
    }
    rows.into_iter()
        .enumerate()
        .map(|(index, row)| {
            let n = index + 1;
            let field = |value: &[u8], max, required, what: &str| {
                check_text(value, max, required)
                    .map_err(|e| format!("installed package entry {n} {what}: {e}"))
            };
            Ok(Package {
                name: field(&row.name, MAX_NAME_BYTES, true, "name")?,
                version: field(&row.version, MAX_VERSION_BYTES, false, "version")?,
                status: field(&row.status, MAX_STATUS_BYTES, false, "status")?,
            })
        })
        .collect()
}
