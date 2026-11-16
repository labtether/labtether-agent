//! Page replies: request in, reply out, error reply, Go's sort and limit.
//! Each test names the fault it catches. Values are made up.

use std::io;

use labtether_agent_config::{Environment, HostFacts, Settings, load};
use labtether_agent_platform::interfaces::InterfaceRow;
#[cfg(target_os = "linux")]
use labtether_agent_platform::mounts::MountListError;
use labtether_agent_platform::mounts::{MountList, MountUsage};
#[cfg(target_os = "linux")]
use labtether_agent_platform::processes::ProcessRow;
#[cfg(target_os = "linux")]
use labtether_protocol::ProcessListData;
use labtether_protocol::{DiskListData, Message, NetworkListData};
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
use crate::processes;
use crate::{disks, network};

pub(crate) fn settings() -> Settings {
    let dir = std::env::temp_dir().join("lt-capabilities-unused");
    let path = |name: &str| dir.join(name).display().to_string();
    let env = Environment::from_pairs([
        ("LABTETHER_TOKEN_FILE", path("agent-token")),
        ("LABTETHER_AGENT_SETTINGS_FILE", path("agent-config.json")),
    ]);
    let host = HostFacts {
        hostname: "nas01".into(),
        version: "0.1.0".into(),
    };
    load(&env, &host).unwrap().settings
}

#[cfg(target_os = "linux")]
fn row(pid: i64, cpu: f64, mem: f64) -> ProcessRow {
    ProcessRow {
        pid,
        name: format!("p{pid}"),
        user: "root".into(),
        cpu_pct: cpu,
        mem_pct: mem,
        mem_rss: 1,
        command: format!("/usr/bin/p{pid}"),
    }
}

#[cfg(target_os = "linux")]
fn pids(reply: &labtether_protocol::ProcessListedData) -> Vec<i64> {
    reply.processes.iter().map(|p| p.pid).collect()
}

#[cfg(target_os = "linux")]
fn process_request(sort_by: &str, limit: i64) -> ProcessListData {
    ProcessListData {
        request_id: "r1".into(),
        sort_by: sort_by.into(),
        limit,
    }
}

// Fault: the default sort is not CPU, the sort is ascending, `memory` sorts
// by CPU, the default limit is not 25, a limit of 0 or below is used as
// given, or equal values are reordered (this port keeps PID order).
#[cfg(target_os = "linux")]
#[test]
fn process_reply_sorts_and_cuts_like_go() {
    let rows: Vec<ProcessRow> = (1..=30)
        .map(|pid| row(pid, f64::from(pid as i32 % 7), f64::from(30 - pid as i32)))
        .collect();
    let by_cpu = processes::answer(process_request("", 0), Ok(rows.clone()));
    assert_eq!(by_cpu.processes.len(), 25);
    assert_eq!(&pids(&by_cpu)[..6], [6, 13, 20, 27, 5, 12]);
    let by_memory = processes::answer(process_request("memory", 3), Ok(rows.clone()));
    assert_eq!(pids(&by_memory), [1, 2, 3]);
    let negative = processes::answer(process_request("name", -4), Ok(rows.clone()));
    assert_eq!(negative.processes.len(), 25);
    let all = processes::answer(process_request("cpu", 200), Ok(rows));
    assert_eq!(all.processes.len(), 30);
    assert_eq!(all.request_id, "r1");
    assert!(all.error.is_empty());
}

// Fault: a failed read gives no reply or a reply without the error text
// (the Hub shows it), or keeps partial rows.
#[test]
fn error_replies_carry_the_reason() {
    #[cfg(target_os = "linux")]
    {
        let failed = processes::answer(process_request("", 0), Err(io::Error::other("no /proc")));
        assert_eq!(
            (failed.processes.len(), failed.error.as_str()),
            (0, "no /proc")
        );
    }
    let request = NetworkListData {
        request_id: "n1".into(),
    };
    let failed = network::answer(request, Err(io::Error::other("netlink refused")));
    assert_eq!(
        (failed.interfaces.len(), failed.error.as_str()),
        (0, "netlink refused")
    );
    let request = DiskListData {
        request_id: "d1".into(),
    };
    #[cfg(target_os = "linux")]
    {
        let missing = MountListError::NoDfFallback(io::Error::from(io::ErrorKind::NotFound));
        let failed = disks::answer(request, Err(missing));
        assert!(failed.mounts.is_empty());
        assert!(failed.error.contains("no df fallback"), "{}", failed.error);
    }
    #[cfg(target_os = "macos")]
    {
        let missing = labtether_agent_platform::mounts::MountListError::MountTable(
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        let failed = disks::answer(request, Err(missing));
        assert!(failed.mounts.is_empty());
        assert!(failed.error.contains("mount table"), "{}", failed.error);
    }
}

// Fault: a field lands in the wrong reply field or unit (bytes, percent),
// or a mount whose `statfs` failed is listed.
#[test]
fn list_replies_carry_every_field() {
    let mount = MountUsage {
        device: "/dev/sda1".into(),
        mount_point: "/".into(),
        fs_type: "ext4".into(),
        total: 4_096_000,
        used: 2_662_400,
        available: 1_228_800,
        use_pct: 65.0,
    };
    let list = MountList {
        mounts: vec![mount],
        skipped: vec![("/gone".into(), io::Error::other("x"))],
    };
    let reply = disks::answer(
        DiskListData {
            request_id: "d1".into(),
        },
        Ok(list),
    );
    let json = serde_json::to_value(&reply).unwrap();
    assert_eq!(
        json,
        json!({"request_id": "d1", "mounts": [{"device": "/dev/sda1", "mount_point": "/", "fs_type": "ext4",
            "total": 4_096_000, "used": 2_662_400, "available": 1_228_800, "use_pct": 65.0}]})
    );
    let interface = InterfaceRow {
        name: "ens18".into(),
        state: "up",
        mac: "00:00:5e:00:53:0a".into(),
        mtu: 1500,
        ips: vec!["192.0.2.10/24".into()],
        rx_bytes: 1,
        tx_bytes: 2,
        rx_packets: 3,
        tx_packets: 4,
    };
    let reply = network::answer(
        NetworkListData {
            request_id: "n1".into(),
        },
        Ok(vec![interface]),
    );
    assert_eq!(
        serde_json::to_value(&reply).unwrap(),
        json!({"request_id": "n1", "interfaces": [{"name": "ens18", "state": "up", "mac": "00:00:5e:00:53:0a",
            "mtu": 1500, "ips": ["192.0.2.10/24"], "rx_bytes": 1, "tx_bytes": 2, "rx_packets": 3, "tx_packets": 4}]})
    );
}

// Fault: a page is wired to the wrong reply type, replies with the envelope
// ID, or answers a request that does not decode. Runs the real readers of
// the test machine.
#[test]
fn registered_handlers_reply_with_their_types() {
    let features = crate::all(&settings());
    for (request, reply) in [
        ("disk.list", "disk.listed"),
        ("network.list", "network.listed"),
        #[cfg(target_os = "linux")]
        ("process.list", "process.listed"),
    ] {
        let handler = features
            .handler(request)
            .unwrap_or_else(|| panic!("{request} has no handler"));
        let message: Message = serde_json::from_value(
            json!({"type": request, "id": "envelope", "data": {"request_id": "q7"}}),
        )
        .unwrap();
        let answer = handler(&message).unwrap_or_else(|| panic!("{request} gave no reply"));
        assert_eq!((answer.r#type.as_str(), answer.id.as_str()), (reply, "q7"));
        let data: Value = answer.decode().unwrap();
        assert_eq!(data["request_id"], "q7");
        assert_eq!(data["error"], Value::Null, "{request}: {data}");
        let bad: Message =
            serde_json::from_value(json!({"type": request, "data": {"request_id": 5}})).unwrap();
        assert!(handler(&bad).is_none(), "{request} answered a bad request");
    }
}
