//! The Docker Engine API over its Unix socket, as Go's `dockerClient`
//! (`client.go`) reads it: hyper's HTTP/1 client on a tokio Unix stream,
//! one connection per request, unversioned paths (no API version is
//! negotiated or sent, so the engine answers in its own current version),
//! 5 s to connect, 30 s for a whole request, and at most 10 MiB of a reply
//! read (Go's `io.LimitReader`: the rest is cut, so the JSON fails). The
//! event stream has no overall limit.
//!
//! The collector threads are not async: each holds a [`Blocking`] engine,
//! a current-thread runtime of its own, and every request ends when the
//! agent stops.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use http::{Request, header};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use labtether_agent_core::{OnStop, Stop};
use tokio::net::UnixStream;
use tokio::sync::watch;

use super::raw::{self, Event};

/// Go's `http.Client.Timeout` for the collector.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Go's `net.DialTimeout` for the Unix socket.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Go's `io.LimitReader` on a reply.
pub(crate) const BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Why a read failed. Go only logs these; nothing goes to the Hub.
#[derive(Debug)]
pub(crate) enum EngineError {
    Io(std::io::Error),
    Http(hyper::Error),
    Timeout,
    Status {
        path: String,
        code: u16,
        body: String,
    },
    Json(serde_json::Error),
    Stopped,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Timeout => f.write_str("timed out"),
            Self::Status { path, code, body } => {
                write!(f, "docker API {path} returned {code}: {body}")
            }
            Self::Json(error) => write!(f, "{error}"),
            Self::Stopped => f.write_str("the agent is stopping"),
        }
    }
}

/// What the collector reads the engine through; the tests answer it with
/// recorded engine replies.
pub(crate) trait EngineApi {
    /// `GET path`: the body of a reply under 300, or an error.
    fn get(&self, path: &str) -> Result<Vec<u8>, EngineError>;
}

pub(crate) fn version(api: &dyn EngineApi) -> Result<raw::Version, EngineError> {
    raw::parse(&api.get("/version")?).map_err(EngineError::Json)
}

pub(crate) fn containers(api: &dyn EngineApi) -> Result<Vec<raw::Container>, EngineError> {
    raw::parse_list(&api.get("/containers/json?all=1")?).map_err(EngineError::Json)
}

pub(crate) fn images(api: &dyn EngineApi) -> Result<Vec<raw::Image>, EngineError> {
    raw::parse_list(&api.get("/images/json")?).map_err(EngineError::Json)
}

pub(crate) fn networks(api: &dyn EngineApi) -> Result<Vec<raw::Network>, EngineError> {
    raw::parse_list(&api.get("/networks")?).map_err(EngineError::Json)
}

pub(crate) fn volumes(api: &dyn EngineApi) -> Result<Vec<raw::Volume>, EngineError> {
    raw::parse::<Option<raw::Volumes>>(&api.get("/volumes")?)
        .map(|found| found.unwrap_or_default().volumes)
        .map_err(EngineError::Json)
}

/// One sample: Go's `containerStats`, `stream=false`.
pub(crate) fn stats(api: &dyn EngineApi, id: &str) -> Result<raw::Stats, EngineError> {
    let path = format!("/containers/{}/stats?stream=false", path_segment(id.trim()));
    raw::parse(&api.get(&path)?).map_err(EngineError::Json)
}

/// Go's `url.PathEscape`.
fn path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~$&+=:@".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Ends the connection's task when the request is done with it.
struct Connection(tokio::task::JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The engine's Unix socket.
#[derive(Debug, Clone)]
pub(crate) struct Socket(pub PathBuf);

impl Socket {
    async fn open(
        &self,
        path: &str,
    ) -> Result<(hyper::Response<Incoming>, Connection), EngineError> {
        let stream = tokio::time::timeout(DIAL_TIMEOUT, UnixStream::connect(&self.0))
            .await
            .map_err(|_| EngineError::Timeout)?
            .map_err(EngineError::Io)?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(EngineError::Http)?;
        let connection = Connection(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = Request::get(path)
            .header(header::HOST, "localhost")
            .body(Empty::<Bytes>::new())
            .map_err(|error| EngineError::Io(std::io::Error::other(error)))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(EngineError::Http)?;
        Ok((response, connection))
    }

    /// Go's `dockerClient.get`.
    pub async fn get(&self, path: &str) -> Result<Vec<u8>, EngineError> {
        let exchange = async {
            let (response, _connection) = self.open(path).await?;
            let code = response.status().as_u16();
            let body = read_limited(response.into_body()).await?;
            if code >= 300 {
                let body = String::from_utf8_lossy(&body).trim().to_owned();
                return Err(EngineError::Status {
                    path: path.to_owned(),
                    code,
                    body,
                });
            }
            Ok(body)
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| EngineError::Timeout)?
    }

    /// Go's `streamEvents`: `GET /events`, read as one JSON value after
    /// another. As Go, the status is not checked.
    pub async fn events(&self) -> Result<EventStream, EngineError> {
        let (response, connection) = self.open("/events").await?;
        Ok(EventStream {
            body: response.into_body(),
            buffer: Vec::new(),
            _connection: connection,
        })
    }
}

async fn read_limited(mut body: Incoming) -> Result<Vec<u8>, EngineError> {
    let mut data = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(chunk) = frame.map_err(EngineError::Http)?.into_data() {
            let room = BODY_LIMIT - data.len();
            data.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if data.len() >= BODY_LIMIT {
                break;
            }
        }
    }
    Ok(data)
}

/// The engine's event stream.
pub(crate) struct EventStream {
    body: Incoming,
    buffer: Vec<u8>,
    _connection: Connection,
}

impl EventStream {
    /// The next event; `None` when the stream ended. A value that is not an
    /// event, or one over 10 MiB, ends it with an error, as Go's decoder.
    pub async fn next(&mut self) -> Result<Option<Event>, EngineError> {
        loop {
            let mut values =
                serde_json::Deserializer::from_slice(&self.buffer).into_iter::<Event>();
            match values.next() {
                Some(Ok(event)) => {
                    let used = values.byte_offset();
                    self.buffer.drain(..used);
                    return Ok(Some(event));
                }
                Some(Err(error)) if !error.is_eof() => return Err(EngineError::Json(error)),
                Some(Err(_)) if self.buffer.len() > BODY_LIMIT => {
                    return Err(EngineError::Io(std::io::Error::other("event over 10 MiB")));
                }
                Some(Err(_)) => {}
                None => self.buffer.clear(),
            }
            match self.body.frame().await {
                None => return Ok(None),
                Some(frame) => {
                    if let Ok(chunk) = frame.map_err(EngineError::Http)?.into_data() {
                        self.buffer.extend_from_slice(&chunk);
                    }
                }
            }
        }
    }
}

/// An engine for one collector thread: requests run on the thread's own
/// runtime and end with [`EngineError::Stopped`] when the agent stops.
pub(crate) struct Blocking {
    pub socket: Socket,
    runtime: tokio::runtime::Runtime,
    stopped: watch::Receiver<bool>,
    _hook: OnStop,
}

impl Blocking {
    pub fn new(socket: Socket, stop: &Stop) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (stopping, stopped) = watch::channel(false);
        let hook = stop.on_stop(move || {
            let _ = stopping.send(true);
        });
        Ok(Self {
            socket,
            runtime,
            stopped,
            _hook: hook,
        })
    }

    /// Runs `work` until it ends or the agent stops.
    pub fn run<T>(
        &self,
        work: impl Future<Output = Result<T, EngineError>>,
    ) -> Result<T, EngineError> {
        let mut stopped = self.stopped.clone();
        self.runtime.block_on(async move {
            tokio::select! {
                result = work => result,
                _ = stopped.wait_for(|stopped| *stopped) => Err(EngineError::Stopped),
            }
        })
    }
}

impl EngineApi for Blocking {
    fn get(&self, path: &str) -> Result<Vec<u8>, EngineError> {
        self.run(self.socket.get(path))
    }
}

/// Go's `PingDockerEndpoint` on a Unix socket: `GET /_ping` within
/// `limit`, on a runtime of its own (callable from any thread that is not
/// inside a runtime).
pub(crate) fn ping(socket: &Socket, limit: Duration) -> bool {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime.block_on(async {
        matches!(
            tokio::time::timeout(limit, socket.get("/_ping")).await,
            Ok(Ok(_))
        )
    })
}
