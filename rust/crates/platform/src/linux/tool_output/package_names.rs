//! Go's package name rule (`internal/agentcore/packagepolicy`,
//! `NormalizeAndValidate` for one name), which the upgradable list applies
//! to every name it returns.

use super::gotext::{first_rune, trim_space};

/// Go's `MaxPackageNameBytes`.
const MAX_NAME_BYTES: usize = 128;

/// True when Go's `NormalizeAndValidate` accepts `raw` as one package name:
/// no control character, not empty once trimmed, at most 128 bytes, not
/// starting with `-`, ASCII letters and digits plus `@+._:/=~-` (the first
/// a letter, digit or `@`), no empty, `.` or `..` path segment and no `:/`.
pub fn valid_name(raw: &[u8]) -> bool {
    let mut at = 0;
    while at < raw.len() {
        let (rune, len) = first_rune(&raw[at..]);
        // Go's `unicode.IsControl`: C0, DEL and C1. An invalid byte reads
        // as U+FFFD, which is not a control character.
        if rune.is_some_and(char::is_control) {
            return false;
        }
        at += len;
    }
    let name = trim_space(raw);
    let Some(&first) = name.first() else {
        return false;
    };
    if name.len() > MAX_NAME_BYTES || first == b'-' {
        return false;
    }
    let allowed = |b: &u8| b.is_ascii_alphanumeric() || b"@+._:/=~-".contains(b);
    if !(first.is_ascii_alphanumeric() || first == b'@') || !name.iter().all(allowed) {
        return false;
    }
    let bad_segment = name
        .split(|&b| b == b'/')
        .any(|s| s.is_empty() || s == b"." || s == b"..");
    !bad_segment && !name.windows(2).any(|w| w == b":/")
}
