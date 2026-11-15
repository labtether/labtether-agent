//! Connection timing. The defaults are the Go agent's values; tests use
//! shorter ones so reconnect and keepalive behaviour runs in seconds.

use std::time::Duration;

/// Every interval and limit the connection uses.
#[derive(Debug, Clone)]
pub struct Timing {
    /// WebSocket ping from the agent (Go: 25 s, staggered from the Hub's 30 s).
    pub ping_interval: Duration,
    /// Close the connection when no pong arrives within this time (Go: 60 s).
    pub read_deadline: Duration,
    /// Give up on one frame write after this long (Go: 10 s).
    pub write_timeout: Duration,
    /// TCP, TLS and WebSocket handshake together (Go: 10 s).
    pub handshake_timeout: Duration,
    /// First reconnect wait; doubles up to `backoff_max` (Go: 1 s to 60 s).
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// Wait after `auth_failure_threshold` refused credentials in a row
    /// (Go: 5 minutes after 3).
    pub auth_backoff: Duration,
    pub auth_failure_threshold: u32,
    /// Re-enrollment is tried at most this often (Go: 10 minutes).
    pub re_enroll_spacing: Duration,
    /// How often a rejected agent checks again (Go: 5 s).
    pub rejected_wait: Duration,
    /// Messages waiting for the writer. A full queue refuses new messages
    /// instead of growing.
    pub send_queue: usize,
    /// A session shorter than this counts as a failed attempt: the next
    /// connect waits and the wait grows. Only a longer one resets the wait.
    pub min_stable_session: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(25),
            read_deadline: Duration::from_secs(60),
            write_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            auth_backoff: Duration::from_secs(300),
            auth_failure_threshold: 3,
            re_enroll_spacing: Duration::from_secs(600),
            rejected_wait: Duration::from_secs(5),
            send_queue: 64,
            min_stable_session: Duration::from_secs(30),
        }
    }
}

/// A random wait in `[0, max)`, from the system's random source, as Go's
/// `jitterDuration`. Returns zero when no randomness is available.
pub fn jitter(max: Duration) -> Duration {
    let nanos = max.as_nanos();
    if nanos == 0 {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    let value = u128::from(u64::from_le_bytes(bytes)) % nanos;
    Duration::from_nanos(u64::try_from(value).unwrap_or(0))
}
