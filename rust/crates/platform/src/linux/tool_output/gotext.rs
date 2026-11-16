//! The Go string helpers the output parsers lean on, over bytes: program
//! output is not always UTF-8, and Go treats it as bytes too.

/// `bufio.MaxScanTokenSize`: a `bufio.Scanner` line of this many bytes or
/// more stops the scan with `bufio.ErrTooLong`.
pub const MAX_SCAN_LINE: usize = 64 * 1024;

/// The text of `bufio.ErrTooLong`.
pub const ERR_TOO_LONG: &str = "bufio.Scanner: token too long";

/// Go's `bufio.Scanner` with `ScanLines`: lines split at `\n`, one trailing
/// `\r` dropped, a last line without `\n` kept when it is not empty. A line
/// of [`MAX_SCAN_LINE`] bytes or more ends the scan: the lines before it
/// come back with `Err`, as Go's loop sees them before `scanner.Err()`.
pub fn scan_lines(out: &[u8]) -> (Vec<&[u8]>, Result<(), &'static str>) {
    let mut lines = Vec::new();
    let mut rest = out;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&b| b == b'\n') {
            Some(end) => (&rest[..end], &rest[end + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if line.len() >= MAX_SCAN_LINE {
            return (lines, Err(ERR_TOO_LONG));
        }
        lines.push(line.strip_suffix(b"\r").unwrap_or(line));
        rest = next;
    }
    (lines, Ok(()))
}

/// The character at the start of `bytes` and its length, or `None` when
/// the bytes there are not valid UTF-8 (Go reads such a byte as U+FFFD,
/// which is not a space).
fn first_char(bytes: &[u8]) -> Option<(char, usize)> {
    let len = match bytes.first()? {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return None,
    };
    let text = std::str::from_utf8(bytes.get(..len)?).ok()?;
    text.chars().next().map(|c| (c, len))
}

/// The character ending `bytes` and its length, as [`first_char`].
fn last_char(bytes: &[u8]) -> Option<(char, usize)> {
    (1..=bytes.len().min(4)).find_map(|len| {
        let start = bytes.len() - len;
        first_char(&bytes[start..]).filter(|&(_, n)| n == len)
    })
}

/// Go's `unicode.IsSpace`, the same set as Rust's `char::is_whitespace`.
fn is_space(c: char) -> bool {
    c.is_whitespace()
}

/// Go's `strings.TrimSpace`.
pub fn trim_space(mut bytes: &[u8]) -> &[u8] {
    while let Some((c, len)) = first_char(bytes) {
        if !is_space(c) {
            break;
        }
        bytes = &bytes[len..];
    }
    while let Some((c, len)) = last_char(bytes) {
        if !is_space(c) {
            break;
        }
        bytes = &bytes[..bytes.len() - len];
    }
    bytes
}

/// Go's `strings.Fields`: the runs between Unicode spaces.
pub fn fields(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at < bytes.len() {
        let (space, len) = match first_char(&bytes[at..]) {
            Some((c, len)) => (is_space(c), len),
            None => (false, 1),
        };
        match (space, start) {
            (true, Some(from)) => {
                out.push(&bytes[from..at]);
                start = None;
            }
            (false, None) => start = Some(at),
            _ => {}
        }
        at += len;
    }
    if let Some(from) = start {
        out.push(&bytes[from..]);
    }
    out
}

/// The text Go's `encoding/json` sends for a byte string: each byte that is
/// not part of valid UTF-8 becomes U+FFFD on its own (Rust's lossy decoding
/// would join a cut sequence into one).
pub fn lossy(mut bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    loop {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(error) => {
                let (good, bad) = bytes.split_at(error.valid_up_to());
                // `good` is valid UTF-8 by the error's own account.
                out.push_str(std::str::from_utf8(good).unwrap_or_default());
                out.push(char::REPLACEMENT_CHARACTER);
                bytes = &bad[1..];
            }
        }
    }
}

/// The rune at the start of `bytes` and its length, as Go's
/// `utf8.DecodeRune` reads it: `None` (Go's U+FFFD) and length 1 for a byte
/// that does not start valid UTF-8.
pub fn first_rune(bytes: &[u8]) -> (Option<char>, usize) {
    match first_char(bytes) {
        Some((c, len)) => (Some(c), len),
        None => (None, 1),
    }
}

/// Go's `%q` of a byte string (`strconv.Quote`). Go keeps every rune
/// `unicode.IsPrint` accepts; this keeps every rune that is not a control
/// character or a space other than U+0020, which differs from Go only for
/// unassigned and format runes.
pub fn go_quote(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::from("\"");
    let mut at = 0;
    while at < bytes.len() {
        let (rune, len) = first_rune(&bytes[at..]);
        match rune {
            None => {
                let _ = write!(out, "\\x{:02x}", bytes[at]);
            }
            Some('"') => out.push_str("\\\""),
            Some('\\') => out.push_str("\\\\"),
            Some('\u{7}') => out.push_str("\\a"),
            Some('\u{8}') => out.push_str("\\b"),
            Some('\u{c}') => out.push_str("\\f"),
            Some('\n') => out.push_str("\\n"),
            Some('\r') => out.push_str("\\r"),
            Some('\t') => out.push_str("\\t"),
            Some('\u{b}') => out.push_str("\\v"),
            Some(c) if c == ' ' || !(c.is_control() || c.is_whitespace()) => out.push(c),
            Some(c) if u32::from(c) < 0x80 => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            Some(c) if u32::from(c) < 0x10000 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            Some(c) => {
                let _ = write!(out, "\\U{:08x}", u32::from(c));
            }
        }
        at += len;
    }
    out.push('"');
    out
}

/// Go's `syscall.Errno` text for an I/O error: the C library's message
/// with its first letter in lower case ("no such file or directory").
/// Errors that carry no system error number keep their own text.
pub fn errno_text(error: &std::io::Error) -> String {
    let text = error.to_string();
    let Some(code) = error.raw_os_error() else {
        return text;
    };
    let text = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => text.to_owned(),
    }
}

/// Go's `*os.PathError` text: `<op> <path>: <errno text>`.
pub fn path_error(op: &str, path: &std::path::Path, error: &std::io::Error) -> String {
    format!(
        "{op} {}: {}",
        lossy(path.as_os_str().as_encoded_bytes()),
        errno_text(error)
    )
}
