//! A stand-in Hub for the integration tests: one listener that answers
//! `POST /api/v1/enroll` and the agent WebSocket, records what it receives,
//! and can refuse tokens, stall, drop connections or run pending enrollment.

#![allow(dead_code)]

pub mod pki;
pub mod setup;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_rustls::TlsAcceptor;

mod socket;

/// Something the stand-in Hub saw.
#[derive(Debug, Clone)]
pub enum Event {
    Connected {
        id: usize,
        headers: HashMap<String, String>,
    },
    Refused {
        status: u16,
        headers: HashMap<String, String>,
    },
    Enroll {
        body: Value,
    },
    Message {
        id: usize,
        message: Value,
    },
    Proof {
        valid: bool,
    },
    Closed {
        id: usize,
    },
}

/// What the Hub does with a pending-enrollment socket.
#[derive(Debug, Clone)]
pub enum Pending {
    Ignore,
    Approve { token: String, asset_id: String },
    Reject,
}

/// One enrollment answer for a one-use token.
#[derive(Debug, Clone)]
pub struct EnrollAnswer {
    pub agent_token: String,
    pub asset_id: String,
}

/// The Hub's behaviour, changeable while a test runs.
#[derive(Debug)]
pub struct Behaviour {
    pub accepted_tokens: HashSet<String>,
    pub canonical_asset: Option<String>,
    pub enroll: HashMap<String, EnrollAnswer>,
    pub ca_pem_in_answer: Option<String>,
    pub pending: Pending,
    /// Stop reading after the upgrade: no pongs, no reads.
    pub stall: bool,
    /// Pause this long after each message read: a slow Hub.
    pub read_pause: Duration,
    /// Close each socket right after the upgrade.
    pub close_at_once: bool,
    /// Answer every upgrade with 503, as a Hub that is down behind a proxy.
    pub refuse_upgrade: bool,
    /// The Hub's words when it refuses a one-use token (401).
    pub enroll_refusal: String,
    /// The group in the enrollment answer.
    pub enroll_group: String,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            accepted_tokens: HashSet::new(),
            canonical_asset: None,
            enroll: HashMap::new(),
            ca_pem_in_answer: None,
            pending: Pending::Ignore,
            stall: false,
            read_pause: Duration::ZERO,
            close_at_once: false,
            refuse_upgrade: false,
            enroll_refusal: "enrollment token is invalid or used".to_owned(),
            enroll_group: String::new(),
        }
    }
}

pub struct Shared {
    pub behaviour: Mutex<Behaviour>,
    events: mpsc::UnboundedSender<Event>,
    next_id: AtomicUsize,
    kick: watch::Sender<u64>,
    push: broadcast::Sender<String>,
}

impl Shared {
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }
}

/// A running stand-in Hub.
pub struct Hub {
    pub addr: SocketAddr,
    pub shared: Arc<Shared>,
    events: mpsc::UnboundedReceiver<Event>,
    pub tls: bool,
}

impl Hub {
    /// Starts a Hub on 127.0.0.1, with TLS when `acceptor` is given.
    pub async fn start(acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, events) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            behaviour: Mutex::new(Behaviour::default()),
            events: tx,
            next_id: AtomicUsize::new(1),
            kick: watch::channel(0).0,
            push: broadcast::channel(16).0,
        });
        let tls = acceptor.is_some();
        let task_shared = shared.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let shared = task_shared.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                serve(stream, shared).await;
                            }
                        }
                        None => serve(tcp, shared).await,
                    }
                });
            }
        });
        Self {
            addr,
            shared,
            events,
            tls,
        }
    }

    pub fn ws_url(&self) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!("{scheme}://{}/ws/agent", self.addr)
    }

    pub fn behaviour(&self) -> std::sync::MutexGuard<'_, Behaviour> {
        self.shared.behaviour.lock().unwrap()
    }

    /// Closes every open agent socket from the Hub side.
    pub fn drop_connections(&self) {
        self.shared.kick.send_modify(|count| *count += 1);
    }

    /// Sends `message` to every open agent socket.
    pub fn send_to_agents(&self, message: &Value) {
        let _ = self.shared.push.send(message.to_string());
    }

    /// The next event, or `None` after `limit`.
    pub async fn next_event(&mut self, limit: Duration) -> Option<Event> {
        tokio::time::timeout(limit, self.events.recv())
            .await
            .ok()
            .flatten()
    }

    /// Skips events until `want` matches one; panics after `limit`.
    pub async fn wait_for<T>(
        &mut self,
        limit: Duration,
        mut want: impl FnMut(&Event) -> Option<T>,
    ) -> T {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next_event(left).await {
                Some(event) => {
                    if let Some(found) = want(&event) {
                        return found;
                    }
                }
                None => panic!("the stand-in Hub did not see the expected event within {limit:?}"),
            }
        }
    }

    /// Waits for the next agent message of `kind` and returns it.
    pub async fn wait_message(&mut self, kind: &str, limit: Duration) -> Value {
        let kind = kind.to_owned();
        self.wait_for(limit, move |event| match event {
            Event::Message { message, .. } if message["type"] == kind.as_str() => {
                Some(message.clone())
            }
            _ => None,
        })
        .await
    }

    /// The ID the next accepted connection will get: connections opened
    /// before now have lower IDs.
    pub fn next_connection(&self) -> usize {
        self.shared.next_id.load(Ordering::Relaxed)
    }

    /// Waits for the next agent message of `kind` on a connection opened at
    /// or after `first` (from [`Hub::next_connection`]), skipping messages
    /// an earlier agent sent before its connection closed.
    pub async fn wait_message_since(&mut self, first: usize, kind: &str, limit: Duration) -> Value {
        let kind = kind.to_owned();
        self.wait_for(limit, move |event| match event {
            Event::Message { id, message } if *id >= first && message["type"] == kind.as_str() => {
                Some(message.clone())
            }
            _ => None,
        })
        .await
    }

    /// Waits for the next accepted connection and returns its headers.
    pub async fn wait_connected(&mut self, limit: Duration) -> HashMap<String, String> {
        self.wait_for(limit, |event| match event {
            Event::Connected { headers, .. } => Some(headers.clone()),
            _ => None,
        })
        .await
    }
}

/// The bytes already read while parsing the request head, then the socket.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let take = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..take]);
            self.prefix.drain(..take);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A parsed request head.
pub struct Head {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    /// Bytes after the head (the start of a request body).
    pub rest: Vec<u8>,
    /// Every byte read, head included, to replay into the WebSocket accept.
    pub raw: Vec<u8>,
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Head> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || data.len() > 64 * 1024 {
            return None;
        }
        data.extend_from_slice(&chunk[..read]);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
    };
    let text = String::from_utf8_lossy(&data[..end]).to_string();
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some(Head {
        method,
        path,
        headers,
        rest: data[end + 4..].to_vec(),
        raw: data,
    })
}

async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, status: &str, body: &str) {
    let text = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(text.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    shared: Arc<Shared>,
) {
    let Some(head) = read_head(&mut stream).await else {
        return;
    };
    if head.method == "POST" && head.path == "/api/v1/enroll" {
        let length: usize = head
            .headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = head.rest.clone();
        while body.len() < length {
            let mut chunk = vec![0u8; length - body.len()];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => body.extend_from_slice(&chunk[..read]),
            }
        }
        let (status, answer) = enroll_answer(&shared, &body);
        respond(&mut stream, status, &answer).await;
        return;
    }
    socket::serve_ws(
        Prefixed {
            prefix: head.raw.clone(),
            inner: stream,
        },
        head,
        shared,
    )
    .await;
}

fn enroll_answer(shared: &Shared, body: &[u8]) -> (&'static str, String) {
    let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    shared.emit(Event::Enroll { body: body.clone() });
    let token = body["enrollment_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let mut behaviour = shared.behaviour.lock().unwrap();
    let Some(answer) = behaviour.enroll.remove(&token) else {
        return (
            "401 Unauthorized",
            json!({"error": behaviour.enroll_refusal}).to_string(),
        );
    };
    behaviour.accepted_tokens.insert(answer.agent_token.clone());
    let mut reply = json!({
        "agent_token": answer.agent_token,
        "asset_id": answer.asset_id,
        "group_id": behaviour.enroll_group,
        "hub_ws_url": "wss://hub.example.invalid:8443/ws/agent",
        "hub_api_url": "https://hub.example.invalid:8443",
    });
    if let Some(pem) = &behaviour.ca_pem_in_answer {
        reply["ca_cert_pem"] = json!(pem);
    }
    ("200 OK", reply.to_string())
}

pub(crate) fn next_id(shared: &Shared) -> usize {
    shared.next_id.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn kick_receiver(shared: &Shared) -> watch::Receiver<u64> {
    shared.kick.subscribe()
}

pub(crate) fn push_receiver(shared: &Shared) -> broadcast::Receiver<String> {
    shared.push.subscribe()
}

pub(crate) fn emit(shared: &Shared, event: Event) {
    shared.emit(event);
}

/// Keeps a TCP stream type in scope for tests that dial the Hub directly.
pub type Tcp = TcpStream;
