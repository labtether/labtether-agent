//! The probe client: Go's two `http.Client`s of `NewWebServiceCollector`.
//! One request each, 2 s for the whole exchange up to the status line and
//! headers (the body is not read), no redirect followed, TLS 1.2 or later,
//! `User-Agent: LabTether-Agent/1.0`. The secure client checks the
//! certificate against the system roots; the insecure one takes any
//! certificate but still checks the server's key, as Go's
//! `InsecureSkipVerify`. Each request opens its own connection (Go keeps
//! connections alive between probes) and speaks HTTP/1.1 only (Go also
//! offers HTTP/2 over TLS). Go's client also reads the `HTTP_PROXY`
//! variables; this one connects directly.

use std::sync::Arc;
use std::time::Duration;

use http::{Request, header};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::rt::{Read, Write};
use hyper_util::rt::TokioIo;
use labtether_agent_config::TlsSettings;
use labtether_agent_core::tls::{TlsError, client_config};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::health::{Client, Method, Pending, Prober};
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

    async fn exchange(&self, client: Client, method: Method, url: &str) -> Option<u16> {
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
            tokio::time::timeout(self.timeout, self.exchange(client, method, url))
                .await
                .ok()
                .flatten()
        })
    }
}

/// One request on a new connection; the status of the answer.
async fn send<T>(io: T, method: Method, target: &Target) -> Option<u16>
where
    T: Read + Write + Unpin + Send + 'static,
{
    // Go writes header names in title case.
    let (mut sender, connection) = http1::Builder::new()
        .title_case_headers(true)
        .handshake(io)
        .await
        .ok()?;
    let _connection = Connection(tokio::spawn(async move {
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
    Some(response.status().as_u16())
}
