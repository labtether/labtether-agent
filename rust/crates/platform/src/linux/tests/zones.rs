//! Go's `time.Local` rules and RFC 3339 text, which the Go oracle files do
//! not cover.

use std::cell::RefCell;

use super::schedules::zone;
use crate::linux::gotime::{Zone, local_zone_with, rfc3339};

/// The zone `local_zone_with` gives for `tz`, and the files it tried.
fn local(tz: Option<&str>, data: Option<&[u8]>) -> (Zone, Vec<String>) {
    let tried = RefCell::new(Vec::new());
    let read = |path: &str| {
        tried.borrow_mut().push(path.to_owned());
        data.map(<[u8]>::to_vec)
    };
    let zone = local_zone_with(tz, &read);
    (zone, tried.into_inner())
}

// Faults: `TZ` unset not reading /etc/localtime; `TZ=""` or `TZ=UTC` read
// from a file; the leading `:` kept; an absolute path looked up in the
// zone folders; a name not tried in Go's folder order; or a file that is
// not TZif used instead of falling back to UTC.
#[test]
fn local_zone_follows_go_init_local() {
    let sydney = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/zoneinfo/Australia_Sydney"
    ))
    .unwrap();
    let (found, tried) = local(None, Some(&sydney));
    assert_eq!(tried, ["/etc/localtime"]);
    assert_eq!(found, zone("Australia_Sydney"));
    for tz in ["", "UTC"] {
        let (found, tried) = local(Some(tz), Some(&sydney));
        assert!(tried.is_empty(), "{tz:?} read {tried:?}");
        assert_eq!(found, Zone::utc());
    }
    let (_, tried) = local(Some(":/opt/zones/Sydney"), Some(&sydney));
    assert_eq!(tried, ["/opt/zones/Sydney"]);
    let (found, tried) = local(Some("Australia/Sydney"), None);
    assert_eq!(
        tried,
        [
            "/usr/share/zoneinfo//Australia/Sydney",
            "/usr/share/lib/zoneinfo//Australia/Sydney",
            "/usr/lib/locale/TZ//Australia/Sydney",
            "/etc/zoneinfo/Australia/Sydney",
        ]
    );
    assert_eq!(found, Zone::utc());
    let (found, _) = local(None, Some(b"not a zone file"));
    assert_eq!(found, Zone::utc());
}

// Fault: the Sydney summer-time offset or Go's RFC 3339 text is wrong
// (`+11:00`, `Z` only for offset 0).
#[test]
fn sydney_offsets_and_rfc3339_text() {
    let sydney = zone("Australia_Sydney");
    let summer = sydney.date(2026, 11, 16, 12, 15, 0);
    assert_eq!(rfc3339(summer, 0), "2026-11-16T01:15:00Z");
    assert_eq!(
        rfc3339(summer, sydney.lookup(summer).offset),
        "2026-11-16T12:15:00+11:00"
    );
    let winter = sydney.date(2026, 7, 1, 12, 0, 0);
    assert_eq!(
        rfc3339(winter, -5 * 3600 - 30 * 60),
        "2026-06-30T20:30:00-05:30"
    );
}
