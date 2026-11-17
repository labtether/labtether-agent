//! [`ProxyApi`] on the network: one HTTP/1.1 request per connection, TLS
//! checked against the system roots (Go's default transport), the answer
//! read whole and decoded when gzip (Go's transport asks for gzip and
//! decodes it). With the outbound rules, the name is looked up and every
//! address checked before any is dialled, then tried in order, as Go's
//! `dialOutboundValidated`.
//!
//! Differences from Go's default transport: no `HTTP_PROXY` variables (Go
//! reads them for Traefik and Caddy, not for NPM), HTTP/1.1 only, the
//! agent's `User-Agent` instead of Go's library default, and the answer
//! cut at 16 MiB (Go reads it whole within the 5 s).

use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use flate2::write::MultiGzDecoder;
use http::{Request, header};
use http_body_util::{BodyExt, Full};
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

use super::api::{ApiRequest, ApiResponse, Exchanging, ProxyApi, Resolving};
use super::outbound::{Outbound, check_ip, normalize_host};
use crate::webservices::client::USER_AGENT;
use crate::webservices::urls::Target;

/// The most of an answer read.
const MAX_BODY: usize = 16 * 1024 * 1024;
/// Go's `resolvedHostRisk` look-up limit.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct HttpApi {
    tls: Arc<ClientConfig>,
}

impl HttpApi {
    pub fn new() -> Result<Self, TlsError> {
        let settings = TlsSettings {
            ca_file: None,
            skip_verify: false,
            ca_only: false,
        };
        Ok(Self {
            tls: client_config(&settings)?,
        })
    }

    async fn connect(
        target: &Target,
        rules: Option<(&Outbound, &str)>,
    ) -> Result<TcpStream, String> {
        let Some((rules, scheme)) = rules else {
            return TcpStream::connect((target.host.as_str(), target.port))
                .await
                .map_err(|e| e.to_string());
        };
        let host = normalize_host(&target.host);
        let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => tokio::net::lookup_host((host.as_str(), target.port))
                .await
                .map_err(|e| e.to_string())?
                .map(|addr| addr.ip())
                .collect(),
        };
        if ips.is_empty() {
            return Err(format!("host {host:?} did not resolve"));
        }
        let private = rules.allow_private(scheme);
        for ip in &ips {
            check_ip(&host, *ip, rules.allow_loopback(), private)?;
        }
        let mut last = String::new();
        for ip in ips {
            match TcpStream::connect(SocketAddr::new(ip, target.port)).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error.to_string(),
            }
        }
        Err(last)
    }

    async fn exchange_once(
        &self,
        request: &ApiRequest,
        rules: Option<(&Outbound, &str)>,
    ) -> Result<ApiResponse, String> {
        let target = Target::parse(&request.url).ok_or("unsupported URL")?;
        let stream = Self::connect(&target, rules).await?;
        if !target.https {
            return send(TokioIo::new(stream), request, &target).await;
        }
        let name = ServerName::try_from(target.host.clone()).map_err(|e| e.to_string())?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, stream)
            .await
            .map_err(|e| e.to_string())?;
        send(TokioIo::new(tls), request, &target).await
    }
}

impl ProxyApi for HttpApi {
    fn exchange<'a>(
        &'a self,
        request: &'a ApiRequest,
        rules: Option<(&'a Outbound, &'a str)>,
    ) -> Exchanging<'a> {
        Box::pin(self.exchange_once(request, rules))
    }

    fn resolve<'a>(&'a self, host: &'a str) -> Resolving<'a> {
        Box::pin(async move {
            let lookup = tokio::net::lookup_host((host, 0));
            let addrs = tokio::time::timeout(LOOKUP_TIMEOUT, lookup)
                .await
                .ok()?
                .ok()?;
            Some(addrs.map(|addr| addr.ip()).collect())
        })
    }
}

async fn send<T>(io: T, request: &ApiRequest, target: &Target) -> Result<ApiResponse, String>
where
    T: Read + Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::Builder::new()
        .title_case_headers(true)
        .handshake(io)
        .await
        .map_err(|e| e.to_string())?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(request.method)
        .uri(target.path.as_str())
        .header(header::HOST, target.authority.as_str())
        .header(header::USER_AGENT, USER_AGENT);
    if let Some(value) = &request.authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if request.json.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(value) = &request.referer {
        builder = builder.header(header::REFERER, value);
    }
    let body = Full::new(Bytes::from(request.json.clone().unwrap_or_default()));
    let built = builder
        .header(header::ACCEPT_ENCODING, "gzip")
        .body(body)
        .map_err(|e| e.to_string())?;
    let result = async {
        let response = sender
            .send_request(built)
            .await
            .map_err(|e| e.to_string())?;
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
        let body = read_all(response.into_body(), gzip).await?;
        Ok(ApiResponse {
            status,
            location,
            body,
        })
    }
    .await;
    connection.abort();
    result
}

async fn read_all(mut body: hyper::body::Incoming, gzip: bool) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.map_err(|e| e.to_string())?.into_data() {
            raw.extend_from_slice(&data);
            if raw.len() > MAX_BODY {
                return Err("answer larger than 16 MiB".into());
            }
        }
    }
    if !gzip || raw.is_empty() {
        return Ok(raw);
    }
    let mut decoder = MultiGzDecoder::new(Vec::new());
    for chunk in raw.chunks(4096) {
        decoder.write_all(chunk).map_err(|e| e.to_string())?;
        if decoder.get_ref().len() > MAX_BODY {
            return Err("answer larger than 16 MiB".into());
        }
    }
    decoder.finish().map_err(|e| e.to_string())
}
