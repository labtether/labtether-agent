//! `package.list` with fake package tools run through the real command
//! rules: which tool is chosen, the arguments and environment, Go's error
//! texts, and the replies to requests Go cannot serve.

use std::time::Duration;

use labtether_agent_platform::tool_output::packages::Package;
use labtether_protocol::Message;
use serde_json::{Value, json};

use super::lists::{UPGRADABLE_TIMEOUT, list_installed, list_upgradable};
use super::{MAX_PAYLOAD_BYTES, answer_installed, go_json_len, handle};
use crate::tests::fakebin::{FakeBin, serial};

const DPKG: &[u8] =
    b"bash\t5.2.37-2+b5\tinstall ok installed\ncurl\t8.14.1-2\tdeinstall ok config-files\n";
const APT: &[u8] = b"Reading package lists...\nInst curl [8.14.1-2] (8.14.1-2+deb13u1 Debian:13.7/stable [amd64])\nConf curl\n";

fn message(value: Value) -> Message {
    serde_json::from_value(value).unwrap()
}

fn reply(bin: &FakeBin, value: Value) -> (String, Value) {
    let answer = handle(&message(value), &bin.policy(&[]), UPGRADABLE_TIMEOUT);
    assert_eq!(answer.r#type, "package.listed");
    (answer.id.clone(), answer.decode().unwrap())
}

fn names(list: Result<Vec<Package>, String>) -> Vec<String> {
    list.unwrap().into_iter().map(|p| p.name).collect()
}

/// apt-get and dpkg-query as on Debian.
fn debian() -> FakeBin {
    let bin = FakeBin::new();
    bin.file("dpkg.out", DPKG)
        .file("apt.out", APT)
        .program("dpkg-query", "/bin/cat \"$D/dpkg.out\"")
        .program("apt-get", "/bin/cat \"$D/apt.out\"");
    bin
}

// Faults: the installed list is read with other arguments than Go's or
// with the forced C locale Go uses only for the upgradable queries; the
// upgradable query lacks `LC_ALL=C`, `LANG=C` or the Homebrew switches, or
// lets the agent's own variables through; the reply forms differ from Go's
// (status word, `upgradable` echo, no echo for the installed list).
#[test]
fn both_lists_run_go_commands_and_environments() {
    let _serial = serial();
    let bin = debian();
    let (id, data) = reply(
        &bin,
        json!({"type": "package.list", "id": "p1", "data": {"request_id": "p1"}}),
    );
    assert_eq!(id, "p1");
    assert_eq!(
        data,
        json!({"request_id": "p1", "packages": [
            {"name": "bash", "version": "5.2.37-2+b5", "status": "installed"},
            {"name": "curl", "version": "8.14.1-2", "status": "config-files"}]})
    );
    assert_eq!(
        bin.calls("dpkg-query").unwrap(),
        ["-W -f ${Package}\t${Version}\t${Status}", ""]
    );
    assert!(
        bin.env("dpkg-query")
            .contains(&"LANG=de_DE.UTF-8".to_owned())
    );

    let (_, data) = reply(
        &bin,
        json!({"type": "package.list", "id": "p2", "data": {"request_id": "p2", "inventory": " Upgradable "}}),
    );
    assert_eq!(
        data,
        json!({"request_id": "p2", "inventory": "upgradable", "packages": [
            {"name": "curl", "version": "8.14.1-2", "available_version": "8.14.1-2+deb13u1", "status": "upgradable"}]})
    );
    assert_eq!(bin.calls("apt-get").unwrap(), ["--just-print upgrade"]);
    let env = bin.env("apt-get");
    for want in [
        "LANG=C",
        "LC_ALL=C",
        "HOMEBREW_NO_AUTO_UPDATE=1",
        "HOMEBREW_NO_ANALYTICS=1",
        "HOME=/home/demo",
    ] {
        assert!(
            env.contains(&want.to_owned()),
            "{want} missing from {env:?}"
        );
    }
    assert!(
        !env.iter().any(|v| v.starts_with("LABTETHER_SECRET")),
        "{env:?}"
    );
}

// Faults: a blocked tool is started, or its refusal is not the reply's
// error.
#[test]
fn blocked_tools_are_refused_and_never_started() {
    let _serial = serial();
    let bin = debian();
    let policy = bin.policy(&["dpkg-query", "apt-get"]);
    let refusal = policy.validate_exec_binary("dpkg-query").unwrap_err();
    assert_eq!(list_installed(&policy), Err(refusal.to_string()));
    let refusal = policy.validate_exec_binary("apt-get").unwrap_err();
    assert_eq!(
        list_upgradable(&policy, UPGRADABLE_TIMEOUT),
        Err(format!(
            "apt-get upgradable package listing failed: {refusal}"
        ))
    );
    assert_eq!(
        (bin.calls("dpkg-query"), bin.calls("apt-get")),
        (None, None)
    );
}

// Faults: the tool choice differs from Go's: rpm read on a Debian host
// that has it too, no dpkg-query fallback without apt-get, no rpm
// fallback when the manager's own tool is missing; no tool does not give
// Go's text; a failing tool's error is not the command's.
#[test]
fn installed_tool_choice_follows_go() {
    let _serial = serial();
    let bin = debian();
    bin.program("rpm", "echo 'rpm-pkg\t1-1\tinstalled'");
    assert_eq!(names(list_installed(&bin.policy(&[]))), ["bash", "curl"]);
    assert_eq!(bin.calls("rpm"), None);

    let bin = FakeBin::new();
    bin.file("dpkg.out", DPKG)
        .program("dpkg-query", "/bin/cat \"$D/dpkg.out\"");
    assert_eq!(names(list_installed(&bin.policy(&[]))).len(), 2);

    let bin = FakeBin::new();
    bin.program("apt-get", "exit 0")
        .program("rpm", "printf 'bash\\t5.2-1\\tinstalled\\n'");
    assert_eq!(names(list_installed(&bin.policy(&[]))), ["bash"]);
    assert_eq!(
        bin.calls("rpm").unwrap()[0],
        "-qa --queryformat %{NAME}\t%{VERSION}-%{RELEASE}\tinstalled"
    );

    let none = FakeBin::new();
    assert_eq!(
        list_installed(&none.policy(&[])),
        Err("no supported package manager".into())
    );
    assert_eq!(
        list_upgradable(&none.policy(&[]), UPGRADABLE_TIMEOUT),
        Err("no supported package manager found".into())
    );

    let bin = FakeBin::new();
    bin.program("dpkg-query", "echo 'dpkg-query: error'; exit 2");
    assert_eq!(
        list_installed(&bin.policy(&[])),
        Err("exit status 2".into())
    );
}

// Faults: dnf's "updates found" exit 100 or pacman's "none" exit 1 is an
// error; a failing query's output is not in the error; a hung query, a
// query over 2 MiB or a missing rpm join does not give Go's text.
#[test]
fn upgradable_queries_follow_go_exit_codes_and_limits() {
    let _serial = serial();
    let bin = FakeBin::new();
    bin.program("dnf", "echo 'bash.x86_64 5.2.32-1.fc40 updates'; exit 100")
        .program("rpm", "printf 'bash.x86_64\\t5.2.26-3.fc40\\n'");
    let list = list_upgradable(&bin.policy(&[]), UPGRADABLE_TIMEOUT).unwrap();
    assert_eq!((list.len(), list[0].version.as_str()), (1, "5.2.26-3.fc40"));
    assert_eq!(bin.calls("dnf").unwrap(), ["check-update --quiet"]);

    let bin = FakeBin::new();
    bin.program("pacman", "exit 1");
    assert_eq!(
        list_upgradable(&bin.policy(&[]), UPGRADABLE_TIMEOUT),
        Ok(Vec::new())
    );

    let bin = FakeBin::new();
    bin.program("apt-get", "echo 'E: Could not get lock'; exit 100");
    assert_eq!(
        list_upgradable(&bin.policy(&[]), UPGRADABLE_TIMEOUT),
        Err("apt-get upgradable package listing failed: E: Could not get lock".into())
    );

    let bin = FakeBin::new();
    bin.program("apt-get", "/usr/bin/head -c 2200000 /dev/zero");
    assert_eq!(
        list_upgradable(&bin.policy(&[]), UPGRADABLE_TIMEOUT),
        Err("apt-get upgradable package listing output exceeded 2097152 bytes".into())
    );

    let bin = FakeBin::new();
    bin.program("yum", "exec /bin/sleep 5")
        .program("rpm", "exit 0");
    assert_eq!(
        list_upgradable(&bin.policy(&[]), Duration::from_millis(300)),
        Err("yum upgradable package listing timed out".into())
    );
    assert_eq!(bin.calls("rpm"), None, "rpm ran after the query failed");

    // The two dnf queries share one deadline: rpm gets what dnf left.
    let bin = FakeBin::new();
    bin.program("dnf", "/bin/sleep 0.3; exit 100")
        .program("rpm", "exec /bin/sleep 3");
    assert_eq!(
        list_upgradable(&bin.policy(&[]), Duration::from_millis(600)),
        Err("rpm installed package lookup timed out".into())
    );

    let bin = FakeBin::new();
    bin.program("dnf", "exit 0")
        .program("rpm", "echo 'rpm: db locked'; exit 1");
    assert_eq!(
        list_upgradable(&bin.policy(&[]), UPGRADABLE_TIMEOUT),
        Err("rpm installed package lookup failed: rpm: db locked".into())
    );
}

// Faults: a request Go answers with an error gets silence or another ID:
// one that does not decode, one without any ID, a too long ID, an envelope
// ID that differs, an unknown inventory (echoed lowercased).
#[test]
fn unusable_requests_get_go_error_replies() {
    let _serial = serial();
    let bin = debian();
    let cases = [
        (
            json!({"type": "package.list", "id": " e1 ", "data": 5}),
            "e1",
            json!({"request_id": "e1", "packages": [], "error": "invalid package inventory request"}),
        ),
        (
            json!({"type": "package.list", "id": "e2", "data": {"request_id": 7}}),
            "e2",
            json!({"request_id": "e2", "packages": [], "error": "invalid package inventory request"}),
        ),
        (
            json!({"type": "package.list", "data": {}}),
            "",
            json!({"request_id": "", "packages": [], "error": "invalid package inventory request id"}),
        ),
        (
            json!({"type": "package.list", "id": "e4", "data": {"request_id": "x".repeat(513)}}),
            "e4",
            json!({"request_id": "e4", "packages": [], "error": "invalid package inventory request id"}),
        ),
        (
            json!({"type": "package.list", "id": "e5", "data": {"request_id": "other"}}),
            "e5",
            json!({"request_id": "e5", "packages": [], "error": "package inventory request id mismatch"}),
        ),
        (
            json!({"type": "package.list", "id": "e6", "data": {"request_id": "e6", "inventory": "Bogus"}}),
            "e6",
            json!({"request_id": "e6", "inventory": "bogus", "packages": [], "error": "invalid package inventory"}),
        ),
    ];
    for (request, want_id, want) in cases {
        assert_eq!(
            reply(&bin, request.clone()),
            (want_id.to_owned(), want),
            "{request}"
        );
    }
    let (id, data) = reply(
        &bin,
        json!({"type": "package.list", "id": "e7", "data": {}}),
    );
    assert_eq!(
        (id.as_str(), data["packages"].as_array().map(Vec::len)),
        ("e7", Some(2))
    );
    assert_eq!(
        bin.calls("apt-get"),
        None,
        "no request above lists upgrades"
    );
}

// Faults: a reply over Go's 8 MiB payload limit is sent; the size is
// measured without Go's escapes for `<`, `>` and `&`.
#[test]
fn oversized_replies_become_go_errors() {
    let big = |n: usize, version: &str| -> Vec<Package> {
        (0..n)
            .map(|i| Package {
                name: format!("p{i}"),
                version: version.to_owned(),
                status: "installed".into(),
            })
            .collect()
    };
    let answer = answer_installed("r1", Ok(big(9_000, &"9".repeat(1_000))));
    let data: Value = answer.decode().unwrap();
    assert_eq!(
        data,
        json!({"request_id": "r1", "packages": [], "error": format!("package inventory response exceeds {MAX_PAYLOAD_BYTES} bytes")})
    );
    // 1,500 versions of 1,000 `<`: 1.5 MB as serde writes it, 9 MB as Go
    // writes it (`\u003c`), so Go refuses it.
    let escaped = answer_installed("r1", Ok(big(1_500, &"<".repeat(1_000))));
    assert_eq!(escaped.decode::<Value>().unwrap()["packages"], json!([]));
    let fits = answer_installed("r1", Ok(big(9_000, &"9".repeat(100))));
    let data: Value = fits.decode().unwrap();
    assert_eq!(
        (data["packages"].as_array().map(Vec::len), data.get("error")),
        (Some(9_000), None)
    );
}

#[test]
fn go_json_len_counts_go_escapes() {
    let data = labtether_protocol::PackageListedData {
        request_id: "<&>".into(),
        ..Default::default()
    };
    let plain = serde_json::to_string(&data).unwrap().len();
    assert_eq!(go_json_len(&data), plain + 15);
}
