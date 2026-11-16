//! The listener: Go's bind and retry schedule (`serveLocalAPI`: 30 s,
//! doubling to 5 minutes, the agent keeps running), and limits Go does not
//! have, so a local program cannot tie the agent up: a fixed number of
//! connections at once (more are closed at once), request headers within a
//! time and a size, no request body read, and each connection closed after
//! a maximum age (its in-flight answer first, within a grace time). See
//! [`Limits::default`] for the values.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::gotime::duration_text;
use crate::router::Router;

/// The retry schedule and the per-connection limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// First wait after a failed bind; doubles up to `retry_max`.
    pub retry_first: Duration,
    pub retry_max: Duration,
    /// Open connections at once.
    pub max_connections: usize,
    /// Time to send the request line and headers.
    pub header_timeout: Duration,
    /// Request line and headers together.
    pub max_header_bytes: usize,
    /// The most any one connection lives.
    pub max_age: Duration,
    /// Time to finish an answer once a connection is told to close.
    pub close_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Go's `localAPIRetryInitialDelay` and `localAPIRetryMaxDelay`.
            retry_first: Duration::from_secs(30),
            retry_max: Duration::from_secs(300),
            // The apps poll on one connection; Go has no cap.
            max_connections: 32,
            // Go's `ReadHeaderTimeout`.
            header_timeout: Duration::from_secs(5),
            // Go allows 1 MiB.
            max_header_bytes: 16 * 1024,
            // Go's `IdleTimeout`.
            max_age: Duration::from_secs(120),
            close_grace: Duration::from_secs(10),
        }
    }
}

/// Go's `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn bind(host: &str, port: &str) -> std::io::Result<TcpListener> {
    let port: u16 = port.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown port {port:?}"),
        )
    })?;
    TcpListener::bind((host, port)).await
}

/// Waits `duration`; false when the agent is stopping.
async fn wait(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => true,
        _ = shutdown.changed() => false,
    }
}

/// Binds with Go's retry schedule, then serves until `shutdown`. `make`
/// builds the router for a listener given its start time.
pub async fn serve(
    name: &str,
    host: &str,
    port: &str,
    limits: Limits,
    make: impl Fn(SystemTime) -> Router,
    mut shutdown: watch::Receiver<bool>,
) {
    let address = join_host_port(host, port);
    let mut delay = limits.retry_first;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let since = SystemTime::now();
        match bind(host, port).await {
            Ok(listener) => {
                log::info!("{name} listening on {address}");
                accept_loop(listener, Arc::new(make(since)), limits, shutdown).await;
                return;
            }
            Err(error) => log::warn!(
                "{name}: local API unavailable on {address}: {error}; retrying in {}. The Hub connection is not affected.",
                duration_text(delay.as_secs())
            ),
        }
        if !wait(delay, &mut shutdown).await {
            return;
        }
        delay = (delay * 2).min(limits.retry_max);
    }
}

async fn accept_loop(
    listener: TcpListener,
    router: Arc<Router>,
    limits: Limits,
    mut shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.changed() => return,
        };
        match accepted {
            Ok((stream, _)) => match slots.clone().try_acquire_owned() {
                Ok(slot) => {
                    let router = router.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        connection(stream, router, limits, shutdown).await;
                        drop(slot);
                    });
                }
                Err(_) => {
                    log::debug!(
                        "local API: {} connections open; closing a new one",
                        limits.max_connections
                    );
                    drop(stream);
                }
            },
            Err(error) => {
                // Out of file descriptors and the like: Go's server waits
                // and accepts again.
                log::warn!("local API accept failed: {error}");
                if !wait(Duration::from_millis(100), &mut shutdown).await {
                    return;
                }
            }
        }
    }
}

async fn connection(
    stream: TcpStream,
    router: Arc<Router>,
    limits: Limits,
    mut shutdown: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let service = service_fn(move |request| {
        let response = router.handle(&request);
        async move { Ok::<_, Infallible>(response) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .max_header_size(limits.max_header_bytes)
        .max_buf_size((2 * limits.max_header_bytes).max(8192))
        .keep_alive(true);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = connection.as_mut() => return,
        () = tokio::time::sleep(limits.max_age) => {}
        _ = shutdown.changed() => {}
    }
    connection.as_mut().graceful_shutdown();
    let _ = tokio::time::timeout(limits.close_grace, connection).await;
}
