//! One TCP (and TLS) dial used by both enrollment and the WebSocket.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Uri;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, lookup_host};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Why a dial failed.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("the Hub address has no usable host or scheme")]
    BadAddress,
    #[error("cannot find the Hub's address: {0}")]
    Lookup(io::Error),
    #[error("cannot reach the Hub: {0}")]
    Connect(io::Error),
    #[error("the Hub's certificate is not trusted: {0}")]
    Untrusted(rustls::Error),
    #[error("TLS handshake failed: {0}")]
    Tls(io::Error),
}

/// A plain or TLS connection to the Hub.
#[derive(Debug)]
pub enum HubStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

/// Scheme, host and port of a Hub address.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub secure: bool,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Reads `wss`/`https` (TLS) and `ws`/`http` (plain) addresses.
    pub fn from_uri(uri: &Uri) -> Result<Self, DialError> {
        let secure = match uri.scheme_str().map(str::to_ascii_lowercase).as_deref() {
            Some("wss" | "https") => true,
            Some("ws" | "http") => false,
            _ => return Err(DialError::BadAddress),
        };
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or(DialError::BadAddress)?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        Ok(Self { secure, host, port })
    }
}

/// Connects to `endpoint`, with TLS when it is secure.
pub async fn dial(endpoint: &Endpoint, tls: &Arc<ClientConfig>) -> Result<HubStream, DialError> {
    // The name is looked up first so a failed lookup is told apart from a
    // failed connect (Go's `name_lookup_failed` on the status page).
    let addresses: Vec<SocketAddr> = lookup_host((endpoint.host.as_str(), endpoint.port))
        .await
        .map_err(DialError::Lookup)?
        .collect();
    if addresses.is_empty() {
        return Err(DialError::Lookup(io::Error::new(
            io::ErrorKind::NotFound,
            "no address found",
        )));
    }
    let tcp = TcpStream::connect(&addresses[..])
        .await
        .map_err(DialError::Connect)?;
    let _ = tcp.set_nodelay(true);
    if !endpoint.secure {
        return Ok(HubStream::Plain(tcp));
    }
    let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| DialError::BadAddress)?;
    match TlsConnector::from(tls.clone()).connect(name, tcp).await {
        Ok(stream) => Ok(HubStream::Tls(Box::new(stream))),
        Err(error) => Err(classify_tls_error(error)),
    }
}

fn classify_tls_error(error: io::Error) -> DialError {
    let certificate_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .filter(|inner| matches!(inner, rustls::Error::InvalidCertificate(_)))
        .cloned();
    match certificate_error {
        Some(inner) => DialError::Untrusted(inner),
        None => DialError::Tls(error),
    }
}

impl AsyncRead for HubStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HubStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}
