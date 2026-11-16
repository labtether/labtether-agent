//! The local API and parent-PID settings against Go's rules.

use std::fs;
use std::path::PathBuf;

use super::local_api::{self, LocalAuth, ParentPid, is_loopback_bind_address};
use super::{Environment, Secret};

fn env(pairs: &[(&str, &str)]) -> Environment {
    Environment::from_pairs(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
}

fn temp_file(name: &str, text: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("lt-local-api-{}-{name}", std::process::id()));
    fs::write(&path, text).unwrap();
    path
}

// Faults: a non-loopback bind serves the agent's state with no token; a
// token file that cannot be read leaves the API open instead of off; the
// token variable loses to the file; an IPv4-mapped loopback address or
// another 127/8 address counts as remote, or the any-address as loopback.
#[test]
fn local_auth_follows_go() {
    let file = temp_file("token", "  file-token\n");
    let empty = temp_file("empty", " \n");
    let file_path = file.display().to_string();
    let empty_path = empty.display().to_string();
    let missing = "/nonexistent/local-api-auth-token";
    let token = |raw: &str| LocalAuth::Token(Secret::new(raw).unwrap());
    let off_remote = "non-loopback local API binding requires LABTETHER_AGENT_LOCAL_AUTH_TOKEN or LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED=true";
    let cases: Vec<(Vec<(&str, &str)>, LocalAuth)> = vec![
        (vec![], LocalAuth::Open { remote: false }),
        (
            vec![
                ("LABTETHER_AGENT_LOCAL_AUTH_TOKEN", " env-token "),
                ("LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE", &file_path),
            ],
            token("env-token"),
        ),
        (
            vec![("LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE", &file_path)],
            token("file-token"),
        ),
        (
            vec![("LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE", &empty_path)],
            LocalAuth::Open { remote: false },
        ),
        (
            vec![("LABTETHER_AGENT_LOCAL_BIND_ADDRESS", "0.0.0.0")],
            LocalAuth::Off(off_remote.into()),
        ),
        (
            vec![
                ("LABTETHER_AGENT_LOCAL_BIND_ADDRESS", "192.0.2.10"),
                ("LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED", "true"),
            ],
            LocalAuth::Open { remote: true },
        ),
        (
            vec![
                ("LABTETHER_AGENT_LOCAL_BIND_ADDRESS", "192.0.2.10"),
                ("LABTETHER_AGENT_LOCAL_ALLOW_UNAUTHENTICATED", "yes"),
            ],
            LocalAuth::Off(off_remote.into()),
        ),
    ];
    for (pairs, want) in cases {
        assert_eq!(local_api::load(&env(&pairs)).auth, want, "{pairs:?}");
    }
    let unreadable = local_api::load(&env(&[("LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE", missing)]));
    match unreadable.auth {
        LocalAuth::Off(reason) => assert!(
            reason.starts_with("failed to load LABTETHER_AGENT_LOCAL_AUTH_TOKEN_FILE: "),
            "{reason}"
        ),
        other => panic!("an unreadable token file must turn the API off, got {other:?}"),
    }
    for (address, loopback) in [
        ("", true),
        (" LOCALHOST ", true),
        ("127.0.0.1", true),
        ("127.5.5.5", true),
        ("::1", true),
        ("::ffff:127.0.0.2", true),
        ("0.0.0.0", false),
        ("::", false),
        ("192.0.2.10", false),
        ("127.1", false),
        ("nas01", false),
    ] {
        assert_eq!(is_loopback_bind_address(address), loopback, "{address:?}");
    }
    let _ = fs::remove_file(file);
    let _ = fs::remove_file(empty);
}

// Faults: the default port is the app's 8091 instead of Go's 8090; the bind
// address is not trimmed; /version shows the agent version instead of
// APP_VERSION or "dev".
#[test]
fn local_api_defaults_follow_go() {
    let defaults = local_api::load(&env(&[]));
    assert_eq!(defaults.port, "8090");
    assert_eq!(defaults.bind_address, "127.0.0.1");
    assert_eq!(defaults.app_version, "dev");
    let set = local_api::load(&env(&[
        ("AGENT_PORT", " 19601 "),
        ("LABTETHER_AGENT_LOCAL_BIND_ADDRESS", " ::1 "),
        ("APP_VERSION", "v9.9.9"),
    ]));
    assert_eq!(
        (
            set.port.as_str(),
            set.bind_address.as_str(),
            set.app_version.as_str()
        ),
        ("19601", "::1", "v9.9.9")
    );
}

// Faults: a bad LABTETHER_PARENT_PID is ignored, so the agent outlives the
// app that started it; a blank value starts a watch.
#[test]
fn parent_pid_follows_go() {
    for (raw, want) in [
        (None, ParentPid::Unset),
        (Some("  "), ParentPid::Unset),
        (Some("4242"), ParentPid::Pid(4242)),
        (Some(" +4242 "), ParentPid::Pid(4242)),
        (Some("0042"), ParentPid::Pid(42)),
        (Some("0"), ParentPid::Invalid),
        (Some("-7"), ParentPid::Invalid),
        (Some("12abc"), ParentPid::Invalid),
        (Some("1.5"), ParentPid::Invalid),
        (Some("99999999999"), ParentPid::Invalid),
    ] {
        let pairs: Vec<(&str, &str)> = raw
            .map(|v| ("LABTETHER_PARENT_PID", v))
            .into_iter()
            .collect();
        assert_eq!(local_api::parent_pid(&env(&pairs)), want, "{raw:?}");
    }
}
