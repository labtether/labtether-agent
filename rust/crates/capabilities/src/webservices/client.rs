//! The probe client: Go's two `http.Client`s of `NewWebServiceCollector`.
//! One request each, no redirect followed, TLS 1.2 or later,
//! `User-Agent: LabTether-Agent/1.0`. The secure client checks the
//! certificate against the system roots; the insecure one takes any
//! certificate but still checks the server's key, as Go's
//! `InsecureSkipVerify`. Each request opens its own connection (Go keeps
//! connections alive between probes) and speaks HTTP/1.1 only (Go also
//! offers HTTP/2 over TLS). Go's client also reads the `HTTP_PROXY`
//! variables; this one connects directly.
//!
//! Go's 2 s limit covers the whole exchange: a health check reads only the
//! status line and headers; a recognition probe also reads the first
//! 64 KiB of the body, decoded when the service sent it gzip-compressed
//! (Go's transport asks for gzip on a GET and decodes the answer).

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use flate2::write::MultiGzDecoder;
use http::{Request, Response, header};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper::rt::{Read, Write};
use hyper_util::rt::TokioIo;
use labtether_agent_config::TlsSettings;
use labtether_agent_core::tls::{TlsError, client_config};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;

use super::health::{Client, Method, Pending, Prober};
use super::pages::{Fetching, MAX_BODY, Page};
use super::urls::Target;

/// Go's `healthCheckTimeout`.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const USER_AGENT: &str = "LabTether-Agent/1.0";

/// Ends the connection's task when the request is done with it.
struct Connection(tokio::task::JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The probe client on the network.
pub(crate) struct HttpProber {
    secure: Arc<ClientConfig>,
    insecure: Arc<ClientConfig>,
    timeout: Duration,
}

impl HttpProber {
    pub fn new(timeout: Duration) -> Result<Self, TlsError> {
        let trust = |skip_verify| TlsSettings {
            ca_file: None,
            skip_verify,
            ca_only: false,
        };
        Ok(Self {
            secure: client_config(&trust(false))?,
            insecure: client_config(&trust(true))?,
            timeout,
        })
    }

    /// One request on a new connection: the answer's head, with the
    /// connection kept open while the body is read.
    async fn exchange(
        &self,
        client: Client,
        method: Method,
        url: &str,
    ) -> Option<(Response<Incoming>, Connection)> {
        let target = Target::parse(url)?;
        let stream = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .ok()?;
        if !target.https {
            return send(TokioIo::new(stream), method, &target).await;
        }
        let config = match client {
            Client::Secure => &self.secure,
            Client::Insecure => &self.insecure,
        };
        let name = ServerName::try_from(target.host.clone()).ok()?;
        let tls = TlsConnector::from(Arc::clone(config))
            .connect(name, stream)
            .await
            .ok()?;
        send(TokioIo::new(tls), method, &target).await
    }
}

impl Prober for HttpProber {
    fn attempt<'a>(&'a self, client: Client, method: Method, url: &'a str) -> Pending<'a> {
        Box::pin(async move {
            let (response, _connection) =
                tokio::time::timeout(self.timeout, self.exchange(client, method, url))
                    .await
                    .ok()
                    .flatten()?;
            Some(response.status().as_u16())
        })
    }

    fn fetch<'a>(&'a self, client: Client, url: &'a str) -> Fetching<'a> {
        Box::pin(async move {
            let deadline = Instant::now() + self.timeout;
            let (response, connection) =
                timeout_at(deadline, self.exchange(client, Method::Get, url))
                    .await
                    .ok()
                    .flatten()?;
            let status = response.status().as_u16();
            let first = |name| {
                response
                    .headers()
                    .get(name)
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                    .unwrap_or_default()
            };
            let location = first(header::LOCATION);
            let gzip = first(header::CONTENT_ENCODING).eq_ignore_ascii_case("gzip");
            let body = timeout_at(deadline, read_body(response.into_body(), gzip))
                .await
                .ok()
                .flatten();
            drop(connection);
            Some(Page {
                status,
                location,
                body,
            })
        })
    }
}

/// One request on a new connection; the answer's head and the
/// connection, which ends when dropped.
async fn send<T>(io: T, method: Method, target: &Target) -> Option<(Response<Incoming>, Connection)>
where
    T: Read + Write + Unpin + Send + 'static,
{
    // Go writes header names in title case.
    let (mut sender, connection) = http1::Builder::new()
        .title_case_headers(true)
        .handshake(io)
        .await
        .ok()?;
    let connection = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let builder = Request::builder()
        .uri(target.path.as_str())
        .header(header::HOST, target.authority.as_str())
        .header(header::USER_AGENT, USER_AGENT);
    // Go's transport asks for gzip on a GET it sends without a Range.
    let builder = match method {
        Method::Head => builder.method(http::Method::HEAD),
        Method::Get => builder
            .method(http::Method::GET)
            .header(header::ACCEPT_ENCODING, "gzip"),
    };
    let request = builder.body(Empty::<Bytes>::new()).ok()?;
    let response = sender.send_request(request).await.ok()?;
    Some((response, connection))
}

/// Go's `io.ReadAll(io.LimitReader(resp.Body, 64 KiB))` over the body Go's
/// transport hands back: the first 64 KiB, decoded first when gzip;
/// `None` when reading or decoding fails before then (Go's read error).
async fn read_body(mut body: Incoming, gzip: bool) -> Option<Vec<u8>> {
    let mut plain = Vec::new();
    let mut decoder = gzip.then(|| MultiGzDecoder::new(Vec::new()));
    let mut compressed = false;
    while let Some(frame) = body.frame().await {
        let Ok(data) = frame.ok()?.into_data() else {
            continue;
        };
        let out = match decoder.as_mut() {
            None => {
                plain.extend_from_slice(&data);
                &mut plain
            }
            Some(decoder) => {
                compressed |= !data.is_empty();
                decoder.write_all(&data).ok()?;
                decoder.flush().ok()?;
                decoder.get_mut()
            }
        };
        if out.len() >= MAX_BODY {
            out.truncate(MAX_BODY);
            return Some(std::mem::take(out));
        }
    }
    match decoder {
        None => Some(plain),
        // Go's gzip reader takes an empty body as an empty page.
        Some(_) if !compressed => Some(Vec::new()),
        Some(mut decoder) => {
            // The end of the stream (its checksum) counts only when Go
            // would read that far: before 64 KiB of the page.
            let finished = decoder.try_finish();
            let out = decoder.get_mut();
            if out.len() >= MAX_BODY {
                out.truncate(MAX_BODY);
            } else {
                finished.ok()?;
            }
            Some(std::mem::take(out))
        }
    }
}
