//! The installed lists: `dpkg-query` captured on the lab VM; `rpm`,
//! `pacman -Q` and `apk info -v` in their documented forms.

use super::super::gotext::MAX_SCAN_LINE;
use super::super::packages::{Lister, Package, RawPackage, split_apk_name_version, validate};

fn names(rows: &[RawPackage]) -> Vec<String> {
    rows.iter()
        .map(|r| String::from_utf8_lossy(&r.name).into_owned())
        .collect()
}

fn checked(lister: Lister, out: &[u8]) -> Vec<Package> {
    validate(lister.parse(out).unwrap()).unwrap()
}

fn package(name: &str, version: &str, status: &str) -> Package {
    Package {
        name: name.into(),
        version: version.into(),
        status: status.into(),
    }
}

// Faults: the dpkg status is sent whole (`install ok installed`) instead
// of its last word; an epoch, tilde or plus in a version is cut; dpkg's
// order is not kept; part of the 2,200-package list is lost.
#[test]
fn dpkg_list_from_the_lab_vm() {
    let rows = checked(
        Lister::Dpkg,
        include_bytes!("../testdata/debian13-dpkg.txt"),
    );
    assert_eq!(rows.len(), 2200);
    assert_eq!(
        rows[0],
        package("7zip", "25.01+dfsg-1~deb13u2", "installed")
    );
    assert!(rows.iter().all(|r| r.status == "installed"));
    assert!(rows.contains(&package("bash-completion", "1:2.16.0-7", "installed")));
}

// Faults: a multi-arch package printed twice (`${Package}` has no
// architecture) loses one entry; a removed package's `config-files` state
// or a half-configured one is reported as installed; a short line is
// listed; a line past the Go scanner's limit ends with an error (Go's dpkg
// reader stops there quietly and returns what it read).
#[test]
fn dpkg_odd_lines_follow_go() {
    let mut out = b"libc6\t2.41-12+deb13u4\tinstall ok installed\n\
        libc6\t2.41-12+deb13u4\tinstall ok installed\n\
        oldpkg\t1.0-1\tdeinstall ok config-files\n\
        brokenpkg\t2:3.4~rc1+dfsg-0.1\tinstall ok half-configured\n\
        nostatus\t1.0\n\
        spaced\t1.0\t   \n\
        \n"
    .to_vec();
    out.extend(vec![b'x'; MAX_SCAN_LINE]);
    out.extend_from_slice(b"\nafter\t1\tinstall ok installed\n");
    let rows = checked(Lister::Dpkg, &out);
    assert_eq!(
        rows,
        [
            package("libc6", "2.41-12+deb13u4", "installed"),
            package("libc6", "2.41-12+deb13u4", "installed"),
            package("oldpkg", "1.0-1", "config-files"),
            package("brokenpkg", "2:3.4~rc1+dfsg-0.1", "half-configured"),
        ]
    );
}

// Faults: rpm's third column is replaced, or a version with its release
// is cut at the dash.
#[test]
fn rpm_list_keeps_version_release() {
    let out = b"bash\t5.2.26-3.fc40\tinstalled\ngpg-pubkey\td94ca9b2-6567c2c5\tinstalled\nhalf\n";
    assert_eq!(
        checked(Lister::Rpm, out),
        [
            package("bash", "5.2.26-3.fc40", "installed"),
            package("gpg-pubkey", "d94ca9b2-6567c2c5", "installed"),
        ]
    );
}

// Faults: a pacman line with other than two words is listed; a line past
// the scanner's limit is not reported (Go's pacman reader reports it).
#[test]
fn pacman_list_and_its_scanner_error() {
    let out = b"linux 6.11.5.arch1-1\nzstd 1.5.6-1\nwarning: database lock\n";
    assert_eq!(
        checked(Lister::Pacman, out),
        [
            package("linux", "6.11.5.arch1-1", "installed"),
            package("zstd", "1.5.6-1", "installed"),
        ]
    );
    let long = vec![b'x'; MAX_SCAN_LINE];
    assert_eq!(
        Lister::Pacman.parse(&long),
        Err("parse pacman package list: bufio.Scanner: token too long".into())
    );
}

// Fault: an Alpine name with dashes is split at its first dash, or a line
// without a version is listed.
#[test]
fn apk_names_split_at_the_last_version_dash() {
    let out = b"busybox-1.36.1-r29\npy3-foo-bar-1.0_rc1-r0\nmusl-utils-1.2.5-r0\nnameonly\n";
    let rows = Lister::Apk.parse(out).unwrap();
    assert_eq!(names(&rows), ["busybox", "py3-foo-bar", "musl-utils"]);
    assert_eq!(rows[1].version, b"1.0_rc1-r0");
    assert_eq!(
        split_apk_name_version(b"a-2-b-3.0"),
        Some((&b"a-2-b"[..], &b"3.0"[..]))
    );
}

// Faults: more than 10,000 entries is sent cut instead of refused; a name
// that is not UTF-8, a control character or an over-long status passes;
// the error does not name the entry and field as Go does.
#[test]
fn installed_rows_are_checked_as_go_checks_them() {
    let raw = |name: &[u8], version: &[u8], status: &[u8]| RawPackage {
        name: name.to_vec(),
        version: version.to_vec(),
        status: status.to_vec(),
    };
    let ok = raw(b"a", b"1", b"installed");
    let too_many = vec![ok.clone(); 10_001];
    assert_eq!(
        validate(too_many),
        Err("installed package inventory exceeds 10000 entries".into())
    );
    assert_eq!(validate(vec![ok.clone(); 10_000]).unwrap().len(), 10_000);
    let cases: [(RawPackage, &str); 4] = [
        (
            raw(b"b\xff", b"1", b""),
            "installed package entry 2 name: is not valid UTF-8",
        ),
        (
            raw(b" ", b"1", b""),
            "installed package entry 2 name: is required",
        ),
        (
            raw(b"b", b"1\x01", b""),
            "installed package entry 2 version: contains a control character",
        ),
        (
            raw(b"b", b"", &[b's'; 257]),
            "installed package entry 2 status: exceeds 256 bytes",
        ),
    ];
    for (bad, want) in cases {
        assert_eq!(validate(vec![ok.clone(), bad]), Err(want.to_owned()));
    }
}
