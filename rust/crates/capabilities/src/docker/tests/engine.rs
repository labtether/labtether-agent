//! The engine client over a real Unix socket, against a stand-in engine
//! that answers with fixed bytes.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labtether_agent_core::Stop;

use super::{Folder, TESTDATA};
use crate::docker::engine::{self, BODY_LIMIT, Blocking, EngineApi, EngineError, Socket};

/// How the stand-in answers one request target.
pub(crate) enum Reply {
    /// The status, the body in pieces with a pause between, and whether the
    /// connection stays open after it (an event stream).
    Body {
        status: u16,
        pieces: Vec<Vec<u8>>,
        hold: bool,
    },
    /// Reads the request and never answers.
    Silent,
}

impl Reply {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::Body {
            status: 200,
            pieces: vec![body.into()],
            hold: false,
        }
    }

    /// `body` in pieces of `size` bytes.
    pub fn chunks(body: Vec<u8>, size: usize, hold: bool) -> Self {
        Self::Body {
            status: 200,
            pieces: body.chunks(size).map(<[u8]>::to_vec).collect(),
            hold,
        }
    }
}

/// A stand-in Docker Engine on a Unix socket; each connection gets its own
/// thread. Every request head is kept.
pub(crate) struct StandIn {
    pub socket: PathBuf,
    pub requests: Arc<Mutex<Vec<String>>>,
    done: Arc<AtomicBool>,
    _folder: Folder,
}

impl StandIn {
    pub fn start(name: &str, routes: Vec<(String, Reply)>) -> Self {
        let folder = Folder::new(&format!("engine-{name}"), &Default::default());
        let socket = folder.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (requests, done) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(AtomicBool::new(false)),
        );
        let routes = Arc::new(routes);
        let (seen, finished) = (Arc::clone(&requests), Arc::clone(&done));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if finished.load(Ordering::SeqCst) {
                    return;
                }
                let (routes, seen, finished) = (
                    Arc::clone(&routes),
                    Arc::clone(&seen),
                    Arc::clone(&finished),
                );
                std::thread::spawn(move || serve(conn.unwrap(), &routes, &seen, &finished));
            }
        });
        Self {
            socket,
            requests,
            done,
            _folder: folder,
        }
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
    }
}

fn serve(
    mut conn: UnixStream,
    routes: &[(String, Reply)],
    seen: &Mutex<Vec<String>>,
    done: &AtomicBool,
) {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
    seen.lock().unwrap().push(head);
    let hold = |done: &AtomicBool| {
        while !done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    match routes
        .iter()
        .find(|(path, _)| *path == target)
        .map(|(_, reply)| reply)
    {
        Some(Reply::Body {
            status,
            pieces,
            hold: keep,
        }) => {
            let line = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
            );
            let _ = conn.write_all(line.as_bytes());
            for piece in pieces {
                if conn.write_all(piece).is_err() {
                    return;
                }
                let _ = conn.flush();
                std::thread::sleep(Duration::from_millis(2));
            }
            if *keep {
                hold(done);
            }
        }
        Some(Reply::Silent) => hold(done),
        None => {
            let body = r#"{"message":"page not found"}"#;
            let reply = format!(
                "HTTP/1.1 404 X\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(reply.as_bytes());
        }
    }
}

fn engine_for(stand_in: &StandIn, stop: &Stop) -> Blocking {
    Blocking::new(Socket(stand_in.socket.clone()), stop).unwrap()
}

// Faults: a versioned path (`/v1.45/...`) or a missing `Host` (the engine
// answers in another API version's shape, or refuses); an error reply read
// as an empty list (the Hub would be sent an inventory with every
// container gone); a ping that passes on an error reply (the collector
// starts on an endpoint that is not a Docker engine).
#[test]
fn reads_unversioned_paths_and_refuses_error_replies() {
    let version = std::fs::read(format!("{TESTDATA}/engine/version.json")).unwrap();
    let stand_in = StandIn::start(
        "paths",
        vec![
            ("/version".into(), Reply::ok(version)),
            (
                "/containers/json?all=1".into(),
                Reply::Body {
                    status: 500,
                    pieces: vec![b"[]".to_vec()],
                    hold: false,
                },
            ),
            (
                "/_ping".into(),
                Reply::Body {
                    status: 503,
                    pieces: vec![b"OK".to_vec()],
                    hold: false,
                },
            ),
        ],
    );
    let stop = Stop::new();
    let api = engine_for(&stand_in, &stop);
    assert_eq!(engine::version(&api).unwrap().api_version, "1.45");
    let refused = engine::containers(&api).unwrap_err();
    assert!(
        matches!(refused, EngineError::Status { code: 500, .. }),
        "{refused}"
    );
    assert!(!engine::ping(
        &Socket(stand_in.socket.clone()),
        Duration::from_secs(2)
    ));
    let heads = stand_in.requests.lock().unwrap().clone();
    let lines: Vec<&str> = heads.iter().map(|h| h.lines().next().unwrap()).collect();
    assert_eq!(
        lines,
        [
            "GET /version HTTP/1.1",
            "GET /containers/json?all=1 HTTP/1.1",
            "GET /_ping HTTP/1.1"
        ]
    );
    assert!(
        heads
            .iter()
            .all(|h| h.to_ascii_lowercase().contains("host: localhost\r\n"))
    );
}

// Faults: a reply read without a bound (a runaway engine fills the
// agent's memory), or cut at another size than Go's 10 MiB.
#[test]
fn a_reply_is_cut_at_ten_mib() {
    let mut big = b"[".to_vec();
    big.resize(BODY_LIMIT + 4096, b' ');
    big.extend_from_slice(b"]");
    let stand_in = StandIn::start(
        "big",
        vec![("/networks".into(), Reply::chunks(big, 1 << 20, false))],
    );
    let stop = Stop::new();
    let api = engine_for(&stand_in, &stop);
    assert_eq!(api.get("/networks").unwrap().len(), BODY_LIMIT);
    assert!(matches!(engine::networks(&api), Err(EngineError::Json(_))));
}

// Fault: an event split across two reads, or two events in one read, is
// lost or misread (the Hub misses a container start).
#[test]
fn events_split_across_reads_are_read_whole() {
    let stream = std::fs::read(format!("{TESTDATA}/engine/events.jsonl")).unwrap();
    let want = stream
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    let stand_in = StandIn::start(
        "split",
        vec![("/events".into(), Reply::chunks(stream, 13, false))],
    );
    let stop = Stop::new();
    let api = engine_for(&stand_in, &stop);
    let mut events = api.run(api.socket.events()).unwrap();
    let mut got = Vec::new();
    while let Some(event) = api.run(events.next()).unwrap() {
        got.push(event);
    }
    assert_eq!(got.len(), want);
    assert_eq!(
        (got[0].r#type.as_str(), got[0].action.as_str()),
        ("image", "tag")
    );
    assert_eq!(got[3].actor.attributes["ltqa.note"], "héllo ✓");
    assert!(got.iter().all(|event| event.time > 0));
}

// Fault: stopping the agent waits for an engine that does not answer (Go's
// cancelled context ends the request at once; a request here would hold
// the stop for its 30 s limit).
#[test]
fn a_stop_ends_a_request_the_engine_never_answers() {
    let stand_in = StandIn::start("silent", vec![("/version".into(), Reply::Silent)]);
    let stop = Stop::new();
    let api = engine_for(&stand_in, &stop);
    let stopper = stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        stopper.stop();
    });
    let started = Instant::now();
    assert!(matches!(api.get("/version"), Err(EngineError::Stopped)));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}
