//! The upgradable lists: `apt-get --just-print upgrade` captured on the
//! lab VM; dnf with rpm, zypper, `pacman -Qu` and `apk version -l <` in
//! their documented forms.

use super::super::upgradable::{
    RawUpgrade, Upgrade, normalize, parse_apk, parse_apt, parse_dnf, parse_pacman, parse_zypper,
};

fn rows(list: &[RawUpgrade]) -> Vec<(String, String, String)> {
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    list.iter()
        .map(|r| (text(&r.name), text(&r.version), text(&r.available_version)))
        .collect()
}

fn row(name: &str, version: &str, available: &str) -> (String, String, String) {
    (name.into(), version.into(), available.into())
}

fn raw(name: &str, version: &str, available: &str) -> RawUpgrade {
    RawUpgrade {
        name: name.into(),
        version: version.into(),
        available_version: available.into(),
    }
}

// Faults: an `Inst` line is missed or its versions swapped; apt's progress
// output or the "kept back" names are read as packages; part of the
// 268-package plan is lost; empty output is refused or unknown output
// passes as "no updates".
#[test]
fn apt_plan_from_the_lab_vm() {
    let list = parse_apt(include_bytes!("../testdata/debian13-apt-upgrade.txt")).unwrap();
    assert_eq!(list.len(), 268);
    assert!(rows(&list).contains(&row("libc6-dev", "2.41-12+deb13u3", "2.41-12+deb13u4")));
    assert!(!rows(&list).iter().any(|r| r.0.starts_with("linux-image")));
    let normalized = normalize(list).unwrap();
    assert_eq!(normalized.len(), 268);
    assert_eq!(normalized[0].name, "apt");
    assert!(parse_apt(b"").unwrap().is_empty());
    let none = b"Reading package lists...\nCalculating upgrade...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
    assert!(parse_apt(none).unwrap().is_empty());
    assert_eq!(
        parse_apt(b"E: Could not get lock /var/lib/dpkg/lock-frontend\n"),
        Err("unrecognized apt upgradable package output".into())
    );
}

// Faults: an update is listed without its installed version; the
// architecture fallback is missing; dnf's header lines are read as
// packages; a two-word line passes; unparsable rpm output passes.
#[test]
fn dnf_joins_updates_to_rpm() {
    let installed = b"bash.x86_64\t5.2.26-3.fc40\ntzdata.noarch\t2024a-5.fc40\nkernel.x86_64\t6.10.6-200.fc40\n";
    let updates = b"Last metadata expiration check: 0:10:12 ago on Mon 16 Nov 2026.\n\n\
        bash.x86_64 5.2.32-1.fc40 updates\n\
        tzdata.noarch 2024b-1.fc40 updates\n\
        kernel.i686 6.11.3-200.fc40 updates\n\
        absent.x86_64 1.0-1.fc40 updates\n\
        Obsoleting Packages\n";
    assert_eq!(
        rows(&parse_dnf(updates, installed).unwrap()),
        [
            row("bash.x86_64", "5.2.26-3.fc40", "5.2.32-1.fc40"),
            row("tzdata.noarch", "2024a-5.fc40", "2024b-1.fc40"),
            row("kernel.i686", "6.10.6-200.fc40", "6.11.3-200.fc40"),
        ]
    );
    assert_eq!(
        parse_dnf(b"bash.x86_64 5.2.32-1.fc40\n", installed),
        Err("unrecognized dnf upgradable package output".into())
    );
    assert_eq!(
        parse_dnf(b"", b"garbage without tab\n"),
        Err("unrecognized installed rpm package output".into())
    );
}

// Faults: zypper's columns are taken by position instead of heading; "No
// updates found" is refused; output without a table passes.
#[test]
fn zypper_table_by_headings() {
    let out = b"Loading repository data...\nReading installed packages...\n\
        S | Repository | Name | Current Version | Available Version | Arch\n\
        --+------------+------+-----------------+-------------------+-------\n\
        v | repo-oss   | curl | 8.6.0-1.1       | 8.9.1-1.1         | x86_64\n\
        v | repo-oss   | vim  | 9.1.0330-1.1    | 9.1.0650-1.1      | x86_64\n";
    assert_eq!(
        rows(&parse_zypper(out).unwrap()),
        [
            row("curl", "8.6.0-1.1", "8.9.1-1.1"),
            row("vim", "9.1.0330-1.1", "9.1.0650-1.1"),
        ]
    );
    assert!(
        parse_zypper(b"Loading repository data...\nNo updates found.\n")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        parse_zypper(b"System management is locked\n"),
        Err("unrecognized zypper upgradable package output".into())
    );
}

// Faults: a pacman line not in `name old -> new` form passes; the arrow is
// read as a version.
#[test]
fn pacman_updates_need_the_arrow() {
    let out = b"linux 6.11.5.arch1-1 -> 6.11.6.arch1-1\nzstd 1.5.6-1 -> 1.5.6-2\n";
    assert_eq!(
        rows(&parse_pacman(out).unwrap()),
        [
            row("linux", "6.11.5.arch1-1", "6.11.6.arch1-1"),
            row("zstd", "1.5.6-1", "1.5.6-2"),
        ]
    );
    assert!(parse_pacman(b"").unwrap().is_empty());
    assert_eq!(
        parse_pacman(b"error: failed to init transaction\n"),
        Err("unrecognized pacman upgradable package output".into())
    );
    // Four words without the arrow.
    assert_eq!(
        parse_pacman(b"linux 6.11.5.arch1-1 => 6.11.6.arch1-1\n"),
        Err("unrecognized pacman upgradable package output".into())
    );
}

// Faults: apk rows are read before the heading; a tagged row is refused;
// the name is split at its first dash; a bad name's error does not quote
// it as Go does.
#[test]
fn apk_updates_after_the_heading() {
    let out = b"Installed:                                Available:\n\
        busybox-1.36.1-r29                      < 1.36.1-r30\n\
        py3-foo-bar-1.0-r0                      < 1.1-r0 @edge\n";
    assert_eq!(
        rows(&parse_apk(out).unwrap()),
        [
            row("busybox", "1.36.1-r29", "1.36.1-r30"),
            row("py3-foo-bar", "1.0-r0", "1.1-r0"),
        ]
    );
    assert_eq!(
        parse_apk(b"busybox-1.36.1-r29 < 1.36.1-r30\n"),
        Err("unrecognized apk upgradable package output".into())
    );
    // A row before a later heading is refused, not kept.
    assert_eq!(
        parse_apk(b"busybox-1.36.1-r29 < 1.36.1-r30\nInstalled: Available:\n"),
        Err("unrecognized apk upgradable package output".into())
    );
    assert_eq!(
        parse_apk(b"Installed: Available:\nnoversion < 1.0\n"),
        Err("unrecognized apk package name/version \"noversion\"".into())
    );
}

// Faults: a name the package rule refuses (`-rf`, a `..` segment) is sent
// to the Hub; a repeated name is listed twice; the list is not sorted; an
// empty version passes; more than 10,000 entries are sent.
#[test]
fn normalize_follows_go() {
    let list = vec![
        raw("zlib1g", "1:1.3", "1:1.3.1"),
        raw(" curl ", "8.6", "8.9"),
        raw("curl", "0", "0"),
    ];
    assert_eq!(
        normalize(list).unwrap(),
        [
            Upgrade {
                name: "curl".into(),
                version: "8.6".into(),
                available_version: "8.9".into()
            },
            Upgrade {
                name: "zlib1g".into(),
                version: "1:1.3".into(),
                available_version: "1:1.3.1".into()
            },
        ]
    );
    for bad in ["-rf", "a/../b", "pkg:/x", "caf\u{e9}"] {
        assert_eq!(
            normalize(vec![raw("ok", "1", "2"), raw(bad, "1", "2")]),
            Err("upgradable package entry 2 has an invalid name".into()),
            "{bad}"
        );
    }
    assert_eq!(
        normalize(vec![raw("ok", " ", "2")]),
        Err("upgradable package \"ok\" current version: is required".into())
    );
    assert_eq!(
        normalize(vec![raw("a", "1", "2"); 10_001]),
        Err("upgradable package inventory exceeds 10000 entries".into())
    );
}
