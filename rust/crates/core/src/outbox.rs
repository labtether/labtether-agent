//! The send side of one connection: a bounded queue read by a single writer
//! task that owns the socket. The Go agent held one lock around every write,
//! so a stalled Hub blocked every sender for up to 10 s each. Here a sender
//! never waits: a full queue refuses the message.

use labtether_protocol::{MSG_ENROLLMENT_PROOF, Message};
use tokio::sync::mpsc;

/// One item for the writer.
#[derive(Debug)]
pub enum Outgoing {
    Text(String),
    /// Send a close frame and stop.
    Close,
}

/// Why a message was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("the send queue is full")]
    Full,
    #[error("the connection is closed")]
    Closed,
    /// Go's `errEnrollmentPending`: a socket without a token carries only
    /// `enrollment.proof`.
    #[error("enrollment_pending")]
    EnrollmentPending,
    #[error("the message could not be encoded")]
    Encode,
}

/// A handle to queue messages on the current connection.
#[derive(Debug, Clone)]
pub struct Outbox {
    tx: mpsc::Sender<Outgoing>,
    pending_enrollment: bool,
}

impl Outbox {
    /// A queue holding at most `capacity` messages, and its reading end.
    pub fn new(capacity: usize, pending_enrollment: bool) -> (Self, mpsc::Receiver<Outgoing>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                pending_enrollment,
            },
            rx,
        )
    }

    /// Queues `message` without waiting.
    pub fn send(&self, message: &Message) -> Result<(), SendError> {
        if self.pending_enrollment && message.r#type != MSG_ENROLLMENT_PROOF {
            return Err(SendError::EnrollmentPending);
        }
        let text = serde_json::to_string(message).map_err(|_| SendError::Encode)?;
        self.tx
            .try_send(Outgoing::Text(text))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendError::Full,
                mpsc::error::TrySendError::Closed(_) => SendError::Closed,
            })
    }

    /// Asks the writer to send a close frame. Never waits.
    pub fn close(&self) {
        let _ = self.tx.try_send(Outgoing::Close);
    }

    /// True once the connection's writer has stopped.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// True on a socket opened without a token.
    pub fn is_pending_enrollment(&self) -> bool {
        self.pending_enrollment
    }

    /// Messages waiting for the writer.
    pub fn queued(&self) -> usize {
        self.tx.max_capacity() - self.tx.capacity()
    }
}
