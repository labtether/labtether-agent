//! The send side of one connection: a bounded queue read by a single writer
//! task that owns the socket. The Go agent held one lock around every write,
//! so a stalled Hub blocked every sender for up to 10 s each. Here the read
//! loop and the telemetry loop never wait: a full queue refuses the message.
//! A feature's own thread may wait, with [`Outbox::send_and_wait`].

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use labtether_protocol::{MSG_ENROLLMENT_PROOF, Message};
use tokio::sync::mpsc;

/// How much longer than the write timeout [`Outbox::send_and_wait`] waits
/// before it gives up on its own.
pub const WAIT_MARGIN: Duration = Duration::from_secs(1);
/// How often a waiting send looks again for a place in a full queue.
const QUEUE_RETRY: Duration = Duration::from_millis(5);

/// One item for the writer.
#[derive(Debug)]
pub enum Outgoing {
    Text(String),
    /// A message whose sender waits: the writer marks it written once the
    /// frame is out; dropping it unmarked tells the sender it failed.
    Waited(String, Waiter),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Queued,
    Writing,
    Written,
    Failed,
    /// The sender stopped waiting before the writer took it.
    GivenUp,
}

#[derive(Debug)]
struct Answer {
    stage: Mutex<Stage>,
    changed: Condvar,
}

impl Answer {
    fn stage(&self) -> MutexGuard<'_, Stage> {
        self.stage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set(&self, stage: Stage) {
        *self.stage() = stage;
        self.changed.notify_all();
    }
}

/// The writer's side of a waited message.
#[derive(Debug)]
pub struct Waiter(Arc<Answer>);

impl Waiter {
    /// Called before writing; false when the sender has given up, and the
    /// message must then be dropped unwritten.
    pub fn start(&self) -> bool {
        let mut stage = self.0.stage();
        if *stage == Stage::GivenUp {
            return false;
        }
        *stage = Stage::Writing;
        true
    }

    /// The frame is written.
    pub fn written(self) {
        self.0.set(Stage::Written);
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut stage = self.0.stage();
        if matches!(*stage, Stage::Queued | Stage::Writing) {
            *stage = Stage::Failed;
            self.0.changed.notify_all();
        }
    }
}

/// A handle to queue messages on the current connection.
#[derive(Debug, Clone)]
pub struct Outbox {
    tx: mpsc::Sender<Outgoing>,
    pending_enrollment: bool,
    /// How long [`Outbox::send_and_wait`] waits in all.
    wait_limit: Duration,
}

impl Outbox {
    /// A queue holding at most `capacity` messages, and its reading end.
    /// `write_timeout` is the writer's limit for one frame.
    pub fn new(
        capacity: usize,
        pending_enrollment: bool,
        write_timeout: Duration,
    ) -> (Self, mpsc::Receiver<Outgoing>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                pending_enrollment,
                wait_limit: write_timeout + WAIT_MARGIN,
            },
            rx,
        )
    }

    /// Queues `message` without waiting.
    pub fn send(&self, message: &Message) -> Result<(), SendError> {
        let text = self.encode(message)?;
        self.tx
            .try_send(Outgoing::Text(text))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendError::Full,
                mpsc::error::TrySendError::Closed(_) => SendError::Closed,
            })
    }

    fn encode(&self, message: &Message) -> Result<String, SendError> {
        if self.pending_enrollment && message.r#type != MSG_ENROLLMENT_PROOF {
            return Err(SendError::EnrollmentPending);
        }
        serde_json::to_string(message).map_err(|_| SendError::Encode)
    }

    /// Queues `message` and blocks the calling thread until the writer has
    /// written it, as Go's `wsTransport.Send` returns once its frame is
    /// written. Gives [`SendError::Closed`] when the connection ends first:
    /// the message is then dropped, never carried to a later connection.
    ///
    /// It waits at most the write timeout plus [`WAIT_MARGIN`] in all, from
    /// the call, whatever the writer does (Go's `Send` cannot outlast its
    /// 10 s write deadline). A message not yet taken by the writer then is
    /// never written; one being written when the time runs out may still
    /// go out, as a frame cut off by Go's deadline may have.
    ///
    /// It holds at most one place in the queue, so the heartbeat and
    /// replies still fit. Only for a feature's own thread: it sleeps.
    pub fn send_and_wait(&self, message: &Message) -> Result<(), SendError> {
        let deadline = Instant::now() + self.wait_limit;
        let text = self.encode(message)?;
        let answer = Arc::new(Answer {
            stage: Mutex::new(Stage::Queued),
            changed: Condvar::new(),
        });
        let mut item = Outgoing::Waited(text, Waiter(answer.clone()));
        loop {
            match self.tx.try_send(item) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(SendError::Closed),
                Err(mpsc::error::TrySendError::Full(back)) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(SendError::Closed);
                    }
                    item = back;
                    std::thread::sleep(QUEUE_RETRY.min(left));
                }
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let stage = answer.stage();
        let (mut stage, _) = answer
            .changed
            .wait_timeout_while(stage, left, |stage| {
                matches!(stage, Stage::Queued | Stage::Writing)
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *stage {
            Stage::Written => Ok(()),
            Stage::Queued => {
                *stage = Stage::GivenUp;
                Err(SendError::Closed)
            }
            Stage::Writing | Stage::Failed | Stage::GivenUp => Err(SendError::Closed),
        }
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
