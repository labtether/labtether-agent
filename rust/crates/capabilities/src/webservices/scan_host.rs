//! The host the local scan reads: its listening ports from `/proc` and a
//! TCP connection to one of its ports, as Go's `detectListeningTCPPorts`
//! and `probeTCPPortReachable` (`scan_discovery.go`). On the usual HTTPS
//! ports Go sends a TLS hello before closing, so a TLS service sees a
//! hello rather than a connection that ends at once; the hello takes any
//! certificate, names no server (Go's empty `ServerName`), and a completed
//! handshake is closed with a TLS close alert, as Go's `Close`; all within
//! the same 250 ms as the connection. Its result does not matter: a port
//! that took the connection counts as reachable.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use labtether_agent_config::TlsSettings;
use labtether_agent_core::tls::{TlsError, client_config};
use labtether_agent_platform::proc_net;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;

use super::scan::{DIAL_TIMEOUT, Dialing, ScanHost};

/// This machine.
pub(crate) struct LocalHost {
    hello: Arc<ClientConfig>,
}

impl LocalHost {
    pub fn new() -> Result<Self, TlsError> {
        let trust = TlsSettings {
            ca_file: None,
            skip_verify: true,
            ca_only: false,
        };
        let mut hello = (*client_config(&trust)?).clone();
        hello.enable_sni = false;
        Ok(Self {
            hello: Arc::new(hello),
        })
    }
}

impl ScanHost for LocalHost {
    fn listening(&self) -> Vec<u16> {
        proc_net::read_listening_tcp_ports(Path::new("/proc"))
    }

    fn dial<'a>(&'a self, host: &'a str, port: u16, tls_hello: bool) -> Dialing<'a> {
        Box::pin(async move {
            let deadline = Instant::now() + DIAL_TIMEOUT;
            let Ok(Ok(stream)) = timeout_at(deadline, TcpStream::connect((host, port))).await
            else {
                return false;
            };
            if tls_hello && let Ok(name) = ServerName::try_from(host.to_owned()) {
                let connector = TlsConnector::from(Arc::clone(&self.hello));
                if let Ok(Ok(mut tls)) = timeout_at(deadline, connector.connect(name, stream)).await
                {
                    let close = std::future::poll_fn(|cx| Pin::new(&mut tls).poll_shutdown(cx));
                    let _ = timeout_at(deadline, close).await;
                }
            }
            true
        })
    }
}
