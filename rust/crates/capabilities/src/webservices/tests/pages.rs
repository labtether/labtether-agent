//! Go's redirect target for the console's login page and Go's cache
//! pruning, against Go's own output (`testdata/go/redirects.txt` and
//! `prune.txt`, written by the Go test from `testdata/redirect-cases.jsonl`
//! and the fill order below).

use std::time::{Duration, UNIX_EPOCH};

use super::TESTDATA;
use crate::webservices::cache::Expiring;
use crate::webservices::location::same_origin_redirect;

fn lines(name: &str) -> Vec<String> {
    let text = std::fs::read_to_string(format!("{TESTDATA}/{name}")).unwrap();
    text.lines().map(str::to_owned).collect()
}

// Faults: a redirect followed to another host (the probe reads a page that
// service did not serve), the fragment kept, a relative or dot path not
// resolved as Go does, a target Go refuses followed anyway (a bad escape, a
// control character, a malformed host, port or user part), or the path
// escaped otherwise than Go writes it (the request then asks another path).
#[test]
fn login_redirects_match_go() {
    let cases = lines("redirect-cases.jsonl");
    let go = lines("go/redirects.txt");
    assert_eq!(cases.len(), go.len(), "one Go answer per case");
    for (case, want) in cases.iter().zip(&go) {
        let [from, location]: [String; 2] = serde_json::from_str(case).unwrap();
        assert_eq!(
            same_origin_redirect(&from, &location),
            *want,
            "{from} {location:?}"
        );
    }
}

// Faults: a cache grows past 1,024 entries (the agent's memory grows as
// services come and go), keeps expired results while dropping unexpired
// ones, or drops the latest-expiring instead of the earliest.
#[test]
fn caches_prune_as_go() {
    let now = UNIX_EPOCH + Duration::from_secs(1_794_000_000);
    const TOTAL: usize = 1040;
    let mut order = [0; TOTAL];
    for i in 0..TOTAL {
        order[(i * 7919) % TOTAL] = i;
    }
    let mut cache = Expiring::default();
    for i in order {
        let secs = u64::try_from(i).unwrap();
        let expires = now + Duration::from_secs(secs) - Duration::from_secs(12);
        cache.put(format!("k{i:04}"), (), expires, now);
    }
    let removed: Vec<String> = (0..TOTAL)
        .map(|i| format!("k{i:04}"))
        .filter(|key| !cache.contains(key))
        .collect();
    let text = format!("kept {}\nremoved {}", cache.len(), removed.join(","));
    assert_eq!(text, lines("go/prune.txt").join("\n"));
}
