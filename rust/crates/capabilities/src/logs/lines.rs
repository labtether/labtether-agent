//! Go's `bufio.Scanner` with `ScanLines` over a pipe that is still being
//! written: lines split at `\n`, one trailing `\r` dropped, a last line
//! without `\n` kept when not empty. A line of `max` bytes or more is
//! skipped and the next one read, as the Go stream's `skipLongLines` does
//! (plain `ScanLines` would stop with `bufio.ErrTooLong`).

use std::io::{ErrorKind, Read};

use labtether_agent_platform::tool_output::gotext::errno_text;

/// Bytes read from the pipe at a time.
const CHUNK: usize = 64 * 1024;

pub(crate) struct Lines<R> {
    reader: R,
    /// Read bytes; those before `start` were handed out already.
    buf: Vec<u8>,
    start: usize,
    max: usize,
    eof: bool,
    /// Inside a line too long: drop bytes up to its `\n`.
    skipping: bool,
}

impl<R: Read> Lines<R> {
    pub fn new(reader: R, max: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            start: 0,
            max,
            eof: false,
            skipping: false,
        }
    }

    fn skipped(&self) {
        log::warn!(
            "logmgr: skipped a journal entry of {} bytes or more",
            self.max
        );
    }

    /// The next line; `Ok(None)` at the end; `Err` with Go's text when the
    /// read fails.
    pub fn next_line(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            let pending = &self.buf[self.start..];
            let newline = pending.iter().position(|&b| b == b'\n');
            match newline {
                Some(end) if self.skipping => {
                    self.start += end + 1;
                    self.skipping = false;
                    continue;
                }
                Some(end) if end >= self.max => {
                    self.start += end + 1;
                    self.skipped();
                    continue;
                }
                Some(end) => {
                    let line = trim_cr(&pending[..end]).to_vec();
                    self.start += end + 1;
                    return Ok(Some(line));
                }
                None if self.skipping => self.start = self.buf.len(),
                None if pending.len() >= self.max => {
                    self.start = self.buf.len();
                    self.skipping = true;
                    self.skipped();
                }
                None => {}
            }
            if self.eof {
                let pending = &self.buf[self.start..];
                if pending.is_empty() || self.skipping {
                    return Ok(None);
                }
                let line = trim_cr(pending).to_vec();
                self.start = self.buf.len();
                return Ok(Some(line));
            }
            self.buf.drain(..self.start);
            self.start = 0;
            let mut chunk = [0u8; CHUNK];
            match self.reader.read(&mut chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("read |0: {}", errno_text(&error))),
            }
        }
    }
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}
