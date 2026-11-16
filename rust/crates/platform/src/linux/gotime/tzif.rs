//! Go's `time.Local` on Linux (`initLocal`) and its TZif reader
//! (`LoadLocationFromTZData`), with the same choices: `TZ` unset reads
//! `/etc/localtime`; `TZ=""` or `TZ=UTC` is UTC; `TZ=/path` (an optional
//! leading `:` dropped) reads that file; any other name is looked up in
//! Go's zone folders. A file that is missing or not valid TZif leaves UTC.
//! The Go agent does not embed zone data, and neither does this.

use super::{Transition, Zone, ZoneType};

/// Go's `platformZoneSources` on Linux.
const ZONE_SOURCES: [&str; 4] = [
    "/usr/share/zoneinfo/",
    "/usr/share/lib/zoneinfo/",
    "/usr/lib/locale/TZ/",
    "/etc/zoneinfo",
];

/// Go's `maxFileSize` for a zone file.
const MAX_FILE_SIZE: u64 = 10 << 20;

fn read_zone_file(path: &str) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_SIZE {
        return None;
    }
    std::fs::read(path).ok()
}

/// `time.Local` for the agent's `TZ` value (`None` when unset).
pub fn local_zone(tz: Option<&str>) -> Zone {
    local_zone_with(tz, &read_zone_file)
}

/// [`local_zone`] with the file reader given, for tests.
pub fn local_zone_with(tz: Option<&str>, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> Zone {
    let load = |name: &str, sources: &[&str]| {
        sources.iter().find_map(|source| {
            let path = if source.is_empty() {
                name.to_owned()
            } else {
                format!("{source}/{name}")
            };
            read(&path).and_then(|data| from_tzif(&data))
        })
    };
    let zone = match tz {
        None => load("localtime", &["/etc"]),
        Some(tz) => {
            let tz = tz.strip_prefix(':').unwrap_or(tz);
            if tz.starts_with('/') {
                load(tz, &[""])
            } else if !tz.is_empty() && tz != "UTC" {
                load(tz, &ZONE_SOURCES)
            } else {
                None
            }
        }
    };
    zone.unwrap_or_default()
}

struct Reader<'a> {
    data: &'a [u8],
    bad: bool,
}

impl<'a> Reader<'a> {
    fn read(&mut self, n: usize) -> &'a [u8] {
        if self.data.len() < n {
            self.data = &[];
            self.bad = true;
            return &[];
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        head
    }

    fn big4(&mut self) -> Option<u32> {
        let p = self.read(4);
        (p.len() == 4).then(|| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
    }

    fn big8(&mut self) -> Option<u64> {
        let p = self.read(8);
        (p.len() == 8).then(|| u64::from_be_bytes(p.try_into().unwrap_or([0; 8])))
    }
}

/// Go's `LoadLocationFromTZData`: `None` where Go returns an error.
pub fn from_tzif(data: &[u8]) -> Option<Zone> {
    let mut d = Reader { data, bad: false };
    if d.read(4) != b"TZif" {
        return None;
    }
    let version = match d.read(16).first()? {
        0 => 1,
        b'2' => 2,
        b'3' => 3,
        _ => return None,
    };
    // utc/local, std/wall, leap, time, zone and char counts.
    let mut n = [0usize; 6];
    for slot in &mut n {
        *slot = usize::try_from(d.big4()?).ok()?;
    }
    let is64 = version > 1;
    if is64 {
        let skip = n[3] * 4 + n[3] + n[4] * 6 + n[5] + n[2] * 8 + n[1] + n[0] + 4 + 16;
        d.read(skip);
        for slot in &mut n {
            *slot = usize::try_from(d.big4()?).ok()?;
        }
    }
    let [n_utc, n_std, n_leap, n_time, n_zone, n_char] = n;
    let size = if is64 { 8 } else { 4 };
    let mut times = Reader {
        data: d.read(n_time * size),
        bad: false,
    };
    let tx_zones = d.read(n_time);
    let mut zone_data = Reader {
        data: d.read(n_zone * 6),
        bad: false,
    };
    let abbrev = d.read(n_char);
    d.read(n_leap * (size + 4));
    d.read(n_std);
    d.read(n_utc);
    if d.bad || n_zone == 0 {
        return None;
    }
    let rest = d.data;
    let extend = if rest.len() > 2 && rest[0] == b'\n' && rest[rest.len() - 1] == b'\n' {
        String::from_utf8_lossy(&rest[1..rest.len() - 1]).into_owned()
    } else {
        String::new()
    };
    let mut types = Vec::with_capacity(n_zone);
    for _ in 0..n_zone {
        let offset = i64::from(zone_data.big4()? as i32);
        let is_dst = *zone_data.read(1).first()? != 0;
        let index = usize::from(*zone_data.read(1).first()?);
        if index >= abbrev.len() {
            return None;
        }
        let name = &abbrev[index..];
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        types.push(ZoneType {
            name: String::from_utf8_lossy(&name[..end]).into_owned(),
            offset,
            is_dst,
        });
    }
    let mut transitions = Vec::with_capacity(n_time);
    for &zone in tx_zones {
        let when = if is64 {
            times.big8()? as i64
        } else {
            i64::from(times.big4()? as i32)
        };
        let index = usize::from(zone);
        if index >= types.len() {
            return None;
        }
        transitions.push(Transition { when, index });
    }
    if transitions.is_empty() {
        transitions.push(Transition {
            when: super::ALPHA,
            index: 0,
        });
    }
    Some(Zone {
        types,
        transitions,
        extend,
    })
}
