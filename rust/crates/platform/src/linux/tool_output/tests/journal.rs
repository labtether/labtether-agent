//! `journalctl --output=json` lines against the Go agent's own
//! `ParseJournalLine` answers for the same file
//! (`testdata/go/journal-lines.json`, made by the A2d step's oracle on the
//! lab VM). The fixture holds lines in systemd 257's form with neutral
//! host values, plus every case Go skips or treats specially.

use serde_json::Value;

use crate::linux::gotime::rfc3339;
use crate::linux::tool_output::gotext::scan_lines_max;
use crate::linux::tool_output::journal::{MAX_JOURNAL_LINE, parse_line};

const LINES: &[u8] = include_bytes!("../../../../testdata/journal-lines.jsonl");
const GO: &str = include_str!("../../../../testdata/go/journal-lines.json");
/// 2100-01-01: no line in the fixture carries this time.
const NOW: i64 = 4_102_444_800;

// Faults: a line Go skips is kept or the reverse (a non-string field, an
// empty or null MESSAGE, a line that is not one JSON object); a field is
// read from the wrong key; `.service` is stripped from a name of 8 bytes
// or from another suffix; a priority maps to the wrong level; the
// timestamp is not Go's (seconds cut, overflow, a non-digit not falling
// back to now); bytes that are not UTF-8 are joined into one U+FFFD.
#[test]
fn lines_match_go() {
    let go: Value = serde_json::from_str(GO).unwrap();
    assert_eq!(go["scan_error"], "<nil>");
    let rows = go["rows"].as_array().unwrap();
    let (lines, scanned) = scan_lines_max(LINES, MAX_JOURNAL_LINE);
    assert_eq!(scanned, Ok(()));
    assert_eq!(lines.len(), rows.len());
    let mut kept = 0;
    for (line, row) in lines.iter().zip(rows) {
        let shown = String::from_utf8_lossy(line);
        let got = parse_line(line, || NOW);
        assert_eq!(got.is_some(), row["ok"] == true, "{shown}");
        let Some(got) = got else { continue };
        kept += 1;
        let want = &row["entry"];
        assert_eq!(got.message, want["message"].as_str().unwrap(), "{shown}");
        assert_eq!(got.source, want["source"].as_str().unwrap(), "{shown}");
        assert_eq!(got.level, want["level"].as_str().unwrap(), "{shown}");
        if row["now_used"] == true {
            assert_eq!(got.timestamp, rfc3339(NOW, 0), "{shown}");
        } else {
            assert_eq!(
                got.timestamp,
                want["timestamp"].as_str().unwrap(),
                "{shown}"
            );
        }
    }
    assert_eq!(kept, 18, "the fixture's kept lines");
}
