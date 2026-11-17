//! The probe client against stand-in services on loopback, for what Go's
//! `http.Client`s do on the wire.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::webservices::client::{HttpProber, TIMEOUT};
use crate::webservices::cycle::Runner;
use crate::webservices::health::{Client, Method, Prober};
use crate::webservices::pages::{MAX_BODY, Page};
use labtether_agent_core::Stop;

/// What a stand-in does with one request (its head lines): the bytes it
/// writes, or `None` to close the connection.
type Answer = fn(&[String]) -> Option<Vec<u8>>;

fn text(reply: &str) -> Option<Vec<u8>> {
    Some(reply.as_bytes().to_vec())
}

/// A loopback service answering each connection on its own thread; it
/// keeps every request head it read.
struct StandIn {
    port: u16,
    heads: Arc<Mutex<Vec<Vec<String>>>>,
}

fn read_head(reader: &mut impl BufRead) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            return lines;
        }
        lines.push(line.trim().to_owned());
    }
}

impl StandIn {
    fn start(answer: Answer, tls: Option<Arc<ServerConfig>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&heads);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (kept, tls) = (Arc::clone(&kept), tls.clone());
                std::thread::spawn(move || serve(stream, answer, tls, &kept));
            }
        });
        Self { port, heads }
    }

    fn heads(&self) -> Vec<Vec<String>> {
        self.heads.lock().unwrap().clone()
    }
}

fn serve(
    stream: TcpStream,
    answer: Answer,
    tls: Option<Arc<ServerConfig>>,
    kept: &Mutex<Vec<Vec<String>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let respond = |io: &mut dyn ReadWrite| {
        let head = read_head(&mut BufReader::new(&mut *io));
        if head.is_empty() {
            return;
        }
        kept.lock().unwrap().push(head.clone());
        // `None` closes the connection; an empty reply holds it open.
        if let Some(reply) = answer(&head) {
            let _ = io.write_all(&reply);
            let _ = io.flush();
            std::thread::sleep(Duration::from_secs(3));
        }
    };
    match tls {
        None => respond(&mut { stream }),
        Some(config) => {
            let Ok(connection) = ServerConnection::new(config) else {
                return;
            };
            respond(&mut StreamOwned::new(connection, stream));
        }
    }
}

trait ReadWrite: std::io::Read + Write {}
impl<T: std::io::Read + Write> ReadWrite for T {}

pub(crate) fn self_signed() -> Arc<ServerConfig> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], der)
            .unwrap(),
    )
}

fn ask(prober: &HttpProber, client: Client, method: Method, url: &str) -> Option<u16> {
    let runner = Runner::new(&Stop::new()).unwrap();
    runner.run(prober.attempt(client, method, url)).unwrap()
}

/// GET answered with headers and a body that never comes; HEAD closed.
fn head_closed(head: &[String]) -> Option<Vec<u8>> {
    text("HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nContent-Type: text/plain\r\n\r\npartial")
        .filter(|_| head[0].starts_with("GET "))
}

// Faults: a closed connection on HEAD counts as an answer (Go then never
// tries GET, so a service that refuses HEAD shows down); the status waits
// for the body (a long or endless page times the probe out and shows the
// service down); the request is not Go's, line for line: another path, or
// other headers, header case or order than Go's `Host`, `User-Agent` and,
// on GET, `Accept-Encoding` (services that log or route by them see
// another client than Go's).
#[test]
fn heads_then_gets_as_go_writes_them_and_reads_no_body() {
    let service = StandIn::start(head_closed, None);
    let prober = HttpProber::new(TIMEOUT).unwrap();
    let url = format!("http://127.0.0.1:{}/api/health?probe=1", service.port);
    assert_eq!(ask(&prober, Client::Secure, Method::Head, &url), None);
    let started = Instant::now();
    assert_eq!(ask(&prober, Client::Secure, Method::Get, &url), Some(200));
    assert!(started.elapsed() < Duration::from_millis(1500));
    let host = format!("Host: 127.0.0.1:{}", service.port);
    let agent = "User-Agent: LabTether-Agent/1.0".to_owned();
    assert_eq!(
        service.heads(),
        [
            vec![
                "HEAD /api/health?probe=1 HTTP/1.1".to_owned(),
                host.clone(),
                agent.clone()
            ],
            vec![
                "GET /api/health?probe=1 HTTP/1.1".to_owned(),
                host,
                agent,
                "Accept-Encoding: gzip".to_owned()
            ],
        ]
    );
}

fn redirect(_: &[String]) -> Option<Vec<u8>> {
    text(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:9/elsewhere\r\nContent-Length: 0\r\n\r\n",
    )
}

fn silent(_: &[String]) -> Option<Vec<u8>> {
    text("")
}

// Faults: a redirect is followed (Go stops at it: the probe would reach
// another host and report its answer); a service that accepts and never
// answers holds the probe past Go's 2 s limit (the whole cycle waits) or
// another limit is used.
#[test]
fn stops_at_a_redirect_and_at_the_limit() {
    let moved = StandIn::start(redirect, None);
    let prober = HttpProber::new(TIMEOUT).unwrap();
    let url = format!("http://127.0.0.1:{}", moved.port);
    assert_eq!(ask(&prober, Client::Secure, Method::Get, &url), Some(302));
    assert_eq!(moved.heads().len(), 1);
    assert_eq!(moved.heads()[0][0], "GET / HTTP/1.1");

    assert_eq!(TIMEOUT, Duration::from_secs(2));
    let quiet = StandIn::start(silent, None);
    let short = HttpProber::new(Duration::from_millis(300)).unwrap();
    let started = Instant::now();
    let url = format!("http://127.0.0.1:{}", quiet.port);
    assert_eq!(ask(&short, Client::Secure, Method::Head, &url), None);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(2),
        "{took:?}"
    );
}

fn ok(_: &[String]) -> Option<Vec<u8>> {
    text("HTTP/1.1 204 No Content\r\n\r\n")
}

// Faults: the client Go uses first for https checks the certificate (every
// self-signed service shows down), or the one Go falls back to does not
// (it is Go's verified client); plain http to a TLS port or https to a
// plain port counts as an answer (Go's scheme switch then picks the wrong
// one).
#[test]
fn https_takes_any_certificate_only_on_the_insecure_client() {
    let tls = StandIn::start(ok, Some(self_signed()));
    let plain = StandIn::start(ok, None);
    let prober = HttpProber::new(TIMEOUT).unwrap();
    let secure = format!("https://127.0.0.1:{}/", tls.port);
    assert_eq!(
        ask(&prober, Client::Insecure, Method::Head, &secure),
        Some(204)
    );
    assert_eq!(ask(&prober, Client::Secure, Method::Head, &secure), None);
    let http_to_tls = format!("http://127.0.0.1:{}/", tls.port);
    assert_eq!(
        ask(&prober, Client::Secure, Method::Head, &http_to_tls),
        None
    );
    let https_to_plain = format!("https://127.0.0.1:{}/", plain.port);
    assert_eq!(
        ask(&prober, Client::Insecure, Method::Head, &https_to_plain),
        None
    );
    assert_eq!(tls.heads().len(), 1, "{:?}", tls.heads());
}

fn get_page(prober: &HttpProber, url: &str) -> Option<Page> {
    let runner = Runner::new(&Stop::new()).unwrap();
    runner.run(prober.fetch(Client::Secure, url)).unwrap()
}

/// A page of `size` bytes starting with Proxmox VE's title.
fn proxmox_page(size: usize) -> Vec<u8> {
    let mut page = b"<title>Proxmox Virtual Environment</title>".to_vec();
    page.resize(size, b'y');
    page
}

fn gzip(page: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(page).unwrap();
    encoder.finish().unwrap()
}

/// Pages by path; gzip-compressed only when the request asks for it.
fn pages(head: &[String]) -> Option<Vec<u8>> {
    let path = head[0].split(' ').nth(1).unwrap_or("");
    let asks_gzip = head.iter().any(|l| l == "Accept-Encoding: gzip");
    let reply = |extra: &str, body: &[u8]| {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        Some(out)
    };
    let mut broken = gzip(b"<title>TrueNAS</title>");
    let middle = broken.len() / 2;
    broken[middle] ^= 0xff;
    match path {
        "/gzip" if asks_gzip => reply("Content-Encoding: gzip\r\n", &gzip(&proxmox_page(70_000))),
        "/gzip-small" if asks_gzip => reply(
            "Content-Encoding: GZIP\r\n",
            &gzip(b"<title>TrueNAS</title>"),
        ),
        "/gzip-broken" => reply("Content-Encoding: gzip\r\n", &broken),
        "/big" => reply("", &proxmox_page(70_000)),
        "/stall" => text("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\npartial"),
        "/moved" => text(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /en/login\r\nContent-Length: 0\r\n\r\n",
        ),
        _ => reply("", b"plain"),
    }
}

// Faults: a gzip page is not decoded (a service that compresses its
// pages, as Proxmox VE's and many others do, is never recognised; Go's
// transport asks for gzip and decodes it) or a broken one is read as a
// page; more than 64 KiB is kept (Go reads no further) or a page past it is
// read whole; Go's 2 s limit does not cover the page (a slow page holds the
// whole cycle); the `Location` header is lost (the console's login
// redirect is not followed); the GET is not Go's.
#[test]
fn reads_pages_as_go() {
    let service = StandIn::start(pages, None);
    let prober = HttpProber::new(TIMEOUT).unwrap();
    let url = |path: &str| format!("http://127.0.0.1:{}{path}", service.port);

    let page = get_page(&prober, &url("/gzip")).unwrap();
    assert_eq!(page.status, 200);
    assert_eq!(page.body, Some(proxmox_page(MAX_BODY)));
    let small = get_page(&prober, &url("/gzip-small")).unwrap();
    assert_eq!(small.body.as_deref(), Some(&b"<title>TrueNAS</title>"[..]));
    let broken = get_page(&prober, &url("/gzip-broken")).unwrap();
    assert_eq!((broken.status, broken.body), (200, None));
    let big = get_page(&prober, &url("/big")).unwrap();
    assert_eq!(big.body, Some(proxmox_page(MAX_BODY)));
    let moved = get_page(&prober, &url("/moved")).unwrap();
    assert_eq!((moved.status, moved.location.as_str()), (307, "/en/login"));
    assert_eq!(MAX_BODY, 64 * 1024);

    let short = HttpProber::new(Duration::from_millis(300)).unwrap();
    let started = Instant::now();
    let stalled = get_page(&short, &url("/stall")).unwrap();
    assert_eq!((stalled.status, stalled.body), (200, None));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );

    let host = format!("Host: 127.0.0.1:{}", service.port);
    assert_eq!(
        service.heads()[0],
        [
            "GET /gzip HTTP/1.1".to_owned(),
            host,
            "User-Agent: LabTether-Agent/1.0".to_owned(),
            "Accept-Encoding: gzip".to_owned()
        ]
    );
}
