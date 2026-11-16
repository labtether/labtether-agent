//! JSON text written byte for byte as Go's `encoding/json` writes it, so
//! the status ETag (a hash of the body) is the one Go would give for the
//! same values: fields in struct order, no spaces, Go's string escapes
//! (HTML characters and U+2028/U+2029 escaped) and Go's float format.

use std::fmt::Write as _;

/// A number Go's encoder refuses (NaN or an infinity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonFinite;

/// Go's `appendString` with HTML escaping on (the default).
pub fn string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Go's float64 encoding: the shortest text that reads back the same,
/// plain decimal from 1e-6 up to 1e21 and exponent form outside
/// (`1e+21`, `1.5e-7`).
pub fn number(out: &mut String, value: f64) -> Result<(), NonFinite> {
    if !value.is_finite() {
        return Err(NonFinite);
    }
    let abs = value.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let text = format!("{value:e}");
        match text.split_once('e') {
            Some((mantissa, exponent)) if !exponent.starts_with('-') => {
                let _ = write!(out, "{mantissa}e+{exponent}");
            }
            _ => out.push_str(&text),
        }
    } else {
        let _ = write!(out, "{value}");
    }
    Ok(())
}

/// One JSON object, written field by field in the order given.
pub struct Object<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> Object<'a> {
    pub fn start(out: &'a mut String) -> Self {
        out.push('{');
        Self { out, empty: true }
    }

    /// Writes the key and returns the buffer for the value.
    pub fn key(&mut self, key: &str) -> &mut String {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        string(self.out, key);
        self.out.push(':');
        self.out
    }

    pub fn str(&mut self, key: &str, value: &str) {
        string(self.key(key), value);
    }

    /// An `omitempty` string field.
    pub fn str_nonempty(&mut self, key: &str, value: &str) {
        if !value.is_empty() {
            self.str(key, value);
        }
    }

    pub fn bool(&mut self, key: &str, value: bool) {
        self.key(key).push_str(if value { "true" } else { "false" });
    }

    pub fn number(&mut self, key: &str, value: f64) -> Result<(), NonFinite> {
        number(self.key(key), value)
    }

    pub fn end(self) {
        self.out.push('}');
    }
}
