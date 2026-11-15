//! Reconnect waits, ported from Go's `reconnectLoop`: 1 s doubling to 60 s
//! with up to a quarter of jitter; after 3 refused credentials in a row, a
//! 5-minute wait. A successful connection starts over.

use std::time::Duration;

use crate::timing::Timing;

/// What to do after a refused credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthWait {
    /// Fewer than the threshold: the normal growing wait.
    Retry(Duration),
    /// The threshold was reached: the long wait, and re-enrollment may run.
    Long(Duration),
}

/// Reconnect wait state.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
    auth_failures: u32,
    base: Duration,
    max: Duration,
    auth_backoff: Duration,
    threshold: u32,
    jitter: fn(Duration) -> Duration,
}

impl Backoff {
    pub fn new(timing: &Timing, jitter: fn(Duration) -> Duration) -> Self {
        Self {
            current: timing.backoff_base,
            auth_failures: 0,
            base: timing.backoff_base,
            max: timing.backoff_max,
            auth_backoff: timing.auth_backoff,
            threshold: timing.auth_failure_threshold,
            jitter,
        }
    }

    /// A network, TLS or server failure.
    pub fn transient(&mut self) -> Duration {
        let wait = self.current + (self.jitter)(self.current / 4);
        self.current = (self.current * 2).min(self.max);
        wait
    }

    /// The Hub refused the credential (401 or 403).
    pub fn auth_refused(&mut self) -> AuthWait {
        self.auth_failures += 1;
        if self.auth_failures >= self.threshold {
            AuthWait::Long(self.auth_backoff)
        } else {
            AuthWait::Retry(self.transient())
        }
    }

    pub fn auth_failures(&self) -> u32 {
        self.auth_failures
    }

    /// True before the first failure since the last reset.
    pub fn at_base(&self) -> bool {
        self.current == self.base
    }

    /// A connection opened: the credential works, so the refusal count
    /// starts over. The wait itself resets only after a stable session.
    pub fn connected(&mut self) {
        self.auth_failures = 0;
    }

    /// A session stayed up long enough, or a new credential arrived.
    pub fn reset(&mut self) {
        self.current = self.base;
        self.auth_failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_jitter(_: Duration) -> Duration {
        Duration::ZERO
    }

    fn full_jitter(max: Duration) -> Duration {
        max
    }

    // Fault: the wait never grows (hammering a down Hub) or grows past the
    // 60 s cap (an agent that takes many minutes to come back).
    #[test]
    fn transient_wait_doubles_and_is_capped() {
        let mut backoff = Backoff::new(&Timing::default(), no_jitter);
        let waits: Vec<u64> = (0..9).map(|_| backoff.transient().as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        backoff.reset();
        assert_eq!(backoff.transient(), Duration::from_secs(1));
    }

    // Fault: jitter larger than a quarter of the wait, or none at all.
    #[test]
    fn jitter_adds_at_most_a_quarter() {
        let mut backoff = Backoff::new(&Timing::default(), full_jitter);
        assert_eq!(backoff.transient(), Duration::from_millis(1250));
        assert_eq!(backoff.transient(), Duration::from_millis(2500));
        for _ in 0..100 {
            let wait = crate::timing::jitter(Duration::from_secs(4));
            assert!(wait < Duration::from_secs(4));
        }
    }

    // Fault: a revoked agent keeps retrying every minute forever instead of
    // backing off to 5 minutes after the third refusal.
    #[test]
    fn third_refused_credential_gives_the_long_wait() {
        let mut backoff = Backoff::new(&Timing::default(), no_jitter);
        assert_eq!(
            backoff.auth_refused(),
            AuthWait::Retry(Duration::from_secs(1))
        );
        assert_eq!(
            backoff.auth_refused(),
            AuthWait::Retry(Duration::from_secs(2))
        );
        assert_eq!(
            backoff.auth_refused(),
            AuthWait::Long(Duration::from_secs(300))
        );
        assert_eq!(
            backoff.auth_refused(),
            AuthWait::Long(Duration::from_secs(300))
        );
        backoff.reset();
        assert_eq!(backoff.auth_failures(), 0);
        assert_eq!(
            backoff.auth_refused(),
            AuthWait::Retry(Duration::from_secs(1))
        );
    }
}
