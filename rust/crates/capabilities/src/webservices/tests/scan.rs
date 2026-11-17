//! The local port scan's parts against Go: the `/proc/net/tcp*` reader
//! (fed made-up lines and text captured in the Go oracle's network
//! namespace), the port list setting, the registry's names by port, and
//! the dial on the network. Go's output is `testdata/go/scan-parsers.txt`;
//! the scan itself is compared cycle by cycle in `steps.rs`, with the
//! [`FakeHost`] standing for the oracle's namespace.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read as _};
use std::net::TcpListener;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use labtether_agent_config::web_services::normalize_port_list;
use labtether_agent_platform::proc_net;
use rustls::{ServerConnection, StreamOwned};
use serde::Deserialize;

use super::TESTDATA;
use super::client::self_signed;
use crate::webservices::registry;
use crate::webservices::scan::{Dialing, ScanHost};
use crate::webservices::scan_host::LocalHost;

/// One set of listeners the Go oracle opens: on `bind`, the `ports` and
/// `from` to `to`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Listener {
    bind: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    from: u16,
    #[serde(default)]
    to: u16,
}

impl Listener {
    fn all(&self) -> impl Iterator<Item = u16> + '_ {
        let range = (self.from..=self.to).filter(|port| *port > 0);
        self.ports.iter().copied().chain(range)
    }
}

/// The oracle's namespace: the listeners' ports are listening; a
/// connection to the host's address is taken by a listener on any IPv4
/// address, on both families (`::`) or on that address. Records each dial.
pub(crate) struct FakeHost {
    host: String,
    listeners: Mutex<Vec<Listener>>,
    dials: Mutex<Vec<(String, u16, bool, bool)>>,
}

impl FakeHost {
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_owned(),
            listeners: Mutex::default(),
            dials: Mutex::default(),
        }
    }

    pub fn set(&self, listeners: Vec<Listener>) {
        *self.listeners.lock().unwrap() = listeners;
    }

    /// The dials since the last call that a listener took, as the oracle
    /// records them (`<port> plain` or `<port> tls`), sorted; the
    /// addresses dialled; how many dials there were.
    pub fn take(&self) -> (Vec<String>, Vec<String>, usize) {
        let dials = std::mem::take(&mut *self.dials.lock().unwrap());
        let mut taken: Vec<String> = dials
            .iter()
            .filter(|dial| dial.3)
            .map(|(_, port, tls, _)| format!("{port} {}", if *tls { "tls" } else { "plain" }))
            .collect();
        taken.sort();
        let mut hosts: Vec<String> = dials.iter().map(|dial| dial.0.clone()).collect();
        hosts.sort();
        hosts.dedup();
        (taken, hosts, dials.len())
    }
}

impl ScanHost for FakeHost {
    fn listening(&self) -> Vec<u16> {
        let listeners = self.listeners.lock().unwrap();
        let mut ports: Vec<u16> = listeners.iter().flat_map(Listener::all).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn dial<'a>(&'a self, host: &'a str, port: u16, tls_hello: bool) -> Dialing<'a> {
        let takes = |l: &Listener| {
            let address = matches!(l.bind.as_str(), "0.0.0.0" | "::") || l.bind == host;
            address && l.all().any(|p| p == port)
        };
        let taken = host == self.host && self.listeners.lock().unwrap().iter().any(takes);
        self.dials
            .lock()
            .unwrap()
            .push((host.to_owned(), port, tls_hello, taken));
        Box::pin(async move { taken })
    }
}

/// Go's lines in `scan-parsers.txt` by kind.
fn go_lines(kind: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(format!("{TESTDATA}/go/scan-parsers.txt")).unwrap();
    text.lines()
        .map(|line| line.split('\t').map(str::to_owned).collect::<Vec<_>>())
        .filter(|fields| {
            fields[0] == kind
                || (kind == "section" && !["list", "port"].contains(&fields[0].as_str()))
        })
        .collect()
}

/// `proc-net.txt` by section name.
fn sections() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(format!("{TESTDATA}/proc-net.txt")).unwrap();
    text.split("== ")
        .skip(1)
        .map(|section| {
            let (name, body) = section.split_once('\n').unwrap_or((section, ""));
            (name.to_owned(), body.to_owned())
        })
        .collect()
}

// Faults: the header kept or a line after it skipped; another state than
// `0A` (or `0a`) taken; a port read from another column or not from the
// last colon; Go's sign, hex and 1 to 65535 rules not kept (a socket's
// port wrong, missing or invented, so the scan dials another port).
#[test]
fn listening_ports_match_go() {
    let sections = sections();
    let go = go_lines("section");
    assert_eq!(go.len(), sections.len(), "every section compared");
    for fields in go {
        let rust = proc_net::listening_ports(&sections[&fields[0]]);
        let text = format!("{rust:?}").replace(',', "");
        assert_eq!(text, fields[1], "section {}", fields[0]);
    }
}

// Faults: the two files' ports not merged, sorted or each kept once (Go's
// `detectListeningTCPPorts`): the scan's first 128 would be other ports.
// The captured files are from the oracle's namespace after the scan run's
// second cycle; Go read the same listeners before it.
#[test]
fn listening_files_merge_as_go() {
    let sections = sections();
    let rust = proc_net::listening_tcp_ports(&sections["captured-tcp"], &sections["captured-tcp6"]);
    let steps = std::fs::read_to_string(format!("{TESTDATA}/go/webservice-steps.json")).unwrap();
    let go: Vec<u16> = steps
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|step| step["run"] == "scan" && step["step"] == 1)
        .map(|step| serde_json::from_value(step["listening"].clone()).unwrap())
        .unwrap();
    assert_eq!(rust, go);
}

// Faults: a list with a bad entry kept in part (Go then scans its default
// ports); a sign, leading zeros, separators or spaces read otherwise;
// ports not sorted or kept twice.
#[test]
fn port_lists_normalise_as_go() {
    let text = std::fs::read_to_string(format!("{TESTDATA}/port-lists.jsonl")).unwrap();
    let go = go_lines("list");
    let cases: Vec<String> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(go.len(), cases.len(), "every list compared");
    for (raw, fields) in cases.iter().zip(&go) {
        let rust = normalize_port_list(raw).map_or("error".to_owned(), |ports| {
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            format!("={}", list.join(","))
        });
        assert_eq!(rust, fields[1], "list {raw:?}");
    }
}

// Faults: a port shared by two services named after one (Go names only a
// port one service has), or a service's port missing.
#[test]
fn ports_name_as_go() {
    let go: BTreeMap<u16, String> = go_lines("port")
        .into_iter()
        .map(|fields| (fields[1].parse().unwrap(), fields[3].clone()))
        .collect();
    for port in 1..=u16::MAX {
        let rust = registry::unique_by_port(port).map(|known| known.key);
        let want = go.get(&port).map(String::as_str).filter(|key| *key != "-");
        assert_eq!(rust, want, "port {port}");
    }
}

/// What a loopback listener got from one dial: the first byte, or `None`
/// when the connection ended before one.
fn first_byte(listener: &TcpListener) -> Option<u8> {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte), Ok(1)).then_some(byte[0])
}

// Faults: no TLS hello on the HTTPS ports (a TLS service logs a broken
// handshake every cycle, as Go avoids) or one on the others; a completed
// handshake not closed with a TLS close alert (Go's `Close` sends one; a
// TLS service sees a connection cut instead); a closed port counted as
// reachable; an open port not counted when the hello gets no reply; no
// 250 ms limit (a silent service holds a scan slot).
#[test]
fn dials_as_go() {
    let host = LocalHost::new().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!(runtime.block_on(host.dial("127.0.0.1", port, false)));
    assert_eq!(first_byte(&listener), None, "plain dial sends nothing");
    // The listener stays silent: the hello gets no reply.
    let started = Instant::now();
    assert!(runtime.block_on(host.dial("127.0.0.1", port, true)));
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(200), "{waited:?}");
    assert!(waited < Duration::from_millis(1000), "{waited:?}");
    assert_eq!(first_byte(&listener), Some(0x16), "TLS hello first");
    drop(listener);
    assert!(!runtime.block_on(host.dial("127.0.0.1", port, false)));
    assert!(!runtime.block_on(host.dial("127.0.0.1", port, true)));
    // A TLS service: the handshake completes, then the dial closes it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (done, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let connection = ServerConnection::new(self_signed()).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        let read = tls.read(&mut [0u8; 16]).map_err(|error| error.kind());
        done.send(read).unwrap();
    });
    assert!(runtime.block_on(host.dial("127.0.0.1", port, true)));
    let ended = ended.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(
        ended,
        Ok::<_, ErrorKind>(0),
        "closed with a TLS close alert, not cut"
    );
}
