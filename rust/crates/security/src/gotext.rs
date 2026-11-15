//! Go's string functions where a ported rule depends on their exact result:
//! `strconv.Quote` (error text), `strings.ToLower`/`ToUpper` (simple,
//! one character to one character) and `strings.EqualFold`.

use std::fmt::Write;

/// Go's `unicode.ToLower` for one character.
pub fn lower_char(c: char) -> char {
    if c == '\u{130}' {
        return 'i';
    }
    single(c.to_lowercase(), c)
}

/// Go's `unicode.ToUpper` for one character.
pub fn upper_char(c: char) -> char {
    single(c.to_uppercase(), c)
}

fn single(mut mapped: impl Iterator<Item = char>, original: char) -> char {
    match (mapped.next(), mapped.next()) {
        (Some(one), None) => one,
        _ => original,
    }
}

/// Go's `strings.ToLower`.
pub fn lower(text: &str) -> String {
    text.chars().map(lower_char).collect()
}

/// Go's `strings.ToUpper`.
pub fn upper(text: &str) -> String {
    text.chars().map(upper_char).collect()
}

/// Go's `strings.EqualFold`, by simple case mapping in both directions.
pub fn equal_fold(left: &str, right: &str) -> bool {
    let mut right_chars = right.chars();
    for a in left.chars() {
        let Some(b) = right_chars.next() else {
            return false;
        };
        let same = a == b || lower_char(a) == lower_char(b) || upper_char(a) == upper_char(b);
        if !same {
            return false;
        }
    }
    right_chars.next().is_none()
}

/// Go's `strconv.Quote`, for the names in error messages.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if c == ' ' || !(c.is_control() || c.is_whitespace()) => out.push(c),
            c if (c as u32) < 0x10000 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let _ = write!(out, "\\U{:08x}", c as u32);
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fault: a refusal names the command differently from the Go agent, so
    // the Hub shows another message for the same refusal.
    #[test]
    fn quote_and_case_follow_go() {
        assert_eq!(quote("custom-binary"), "\"custom-binary\"");
        assert_eq!(quote("a\"b\\c\td\u{1}"), "\"a\\\"b\\\\c\\td\\x01\"");
        assert_eq!(quote("日本"), "\"日本\"");
        assert_eq!(quote("a\u{a0}b"), "\"a\\u00a0b\"");
        assert_eq!(lower("İSTANBUL"), "istanbul");
        assert_eq!(upper("straße"), "STRAßE");
        assert!(equal_fold("Status", "STATUS"));
        assert!(equal_fold("\u{212a}", "k"));
        assert!(!equal_fold("status", "statusx"));
    }
}
