//! Go's `output.go`: output kept up to a limit while the command's pipes are
//! read to the end, so the command never blocks on a full pipe.

use std::io::{PipeReader, Read};
use std::os::fd::AsFd;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use labtether_agent_platform::process::{self, Readiness};

/// Go's `CappedRetainingWriter`: keeps the first `limit` bytes written and
/// reports every write as taken in full.
#[derive(Debug, Clone, Default)]
pub struct CappedBuffer {
    data: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl CappedBuffer {
    /// A buffer that keeps at most `limit` bytes (0 keeps none).
    pub fn new(limit: usize) -> Self {
        Self {
            data: Vec::new(),
            limit,
            truncated: false,
        }
    }

    /// Keeps what fits and drops the rest; always returns the full length.
    pub fn write(&mut self, payload: &[u8]) -> usize {
        let room = self.limit.saturating_sub(self.data.len());
        let take = room.min(payload.len());
        self.data.extend_from_slice(&payload[..take]);
        if take < payload.len() {
            self.truncated = true;
        }
        payload.len()
    }

    /// The bytes kept.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// True once at least one byte was dropped.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// A reader thread for one output pipe. It ends when the pipe closes or the
/// cancel pipe signals, and gives back what it kept when joined.
pub(crate) type Reader = JoinHandle<CappedBuffer>;

/// Reads `pipe` on its own thread into a buffer of `limit` bytes until the
/// pipe closes (then says so on `done`) or `cancel` signals. Either way the
/// thread ends and drops the pipe's read end, so a descendant still writing
/// gets a closed pipe, as Go's `WaitDelay` gives it.
pub(crate) fn spawn_reader(
    mut pipe: impl Read + AsFd + Send + 'static,
    limit: usize,
    cancel: PipeReader,
    done: &Sender<()>,
) -> Reader {
    let done = done.clone();
    thread::spawn(move || {
        let mut buffer = CappedBuffer::new(limit);
        let mut chunk = vec![0u8; 32 * 1024];
        loop {
            match process::wait_readable(pipe.as_fd(), cancel.as_fd()) {
                Ok(Readiness::Data) => {}
                Ok(Readiness::Cancelled) | Err(_) => return buffer,
            }
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    buffer.write(&chunk[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = done.send(());
        buffer
    })
}

/// Waits for `readers` pipes to close, for at most `bound` when set.
/// Returns false when the time ran out with a pipe still open, which means
/// a descendant still holds it.
pub(crate) fn wait_for_readers(
    done: &Receiver<()>,
    readers: usize,
    bound: Option<Duration>,
) -> bool {
    let deadline = bound.map(|delay| Instant::now() + delay);
    for _ in 0..readers {
        let result = match deadline {
            None => done.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(deadline) => done.recv_timeout(deadline.saturating_duration_since(Instant::now())),
        };
        match result {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            Err(RecvTimeoutError::Timeout) => return false,
        }
    }
    true
}

/// Joins a reader; a reader that panicked kept nothing.
pub(crate) fn join(reader: Reader) -> CappedBuffer {
    reader.join().unwrap_or_default()
}

/// A fresh channel for reader completion.
pub(crate) fn reader_channel() -> (Sender<()>, Receiver<()>) {
    channel()
}
