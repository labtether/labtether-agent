//! The proxy readers' pieces against Go's own answers for the same input
//! (`testdata/proxy-cases.jsonl`; Go's answers in `go/proxy-parsers.txt`,
//! from the proxy package, and `go/proxy-routes.txt`, from the web service
//! package and Go's outbound rules, written by the Go oracle). One line
//! per case, in order; a value that may be empty is written after `=`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use labtether_agent_config::{Environment, web_proxy};
use serde::Deserialize;
use serde_json::Value;

use super::TESTDATA;
use crate::webservices::gourl;
use crate::webservices::proxy::outbound::Outbound;
use crate::webservices::proxy::{
    dashboard_url_from_labels, go_json_string, hosts_in_rule, normalize_image, npm_endpoint,
};
use crate::webservices::routes::{append_alt_url, backend_identity, port_from_url};

#[derive(Debug, Deserialize)]
struct Case {
    kind: String,
    #[serde(default)]
    a: String,
    #[serde(default)]
    b: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

fn cases() -> Vec<Case> {
    std::fs::read_to_string(format!("{TESTDATA}/proxy-cases.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn go(file: &str) -> Vec<String> {
    std::fs::read_to_string(format!("{TESTDATA}/go/{file}"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Go's `strconv.Quote` for the printable text compared here.
fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The names the oracle's container resolves.
fn hosts() -> BTreeMap<String, IpAddr> {
    let text = std::fs::read_to_string(format!("{TESTDATA}/scenario.json")).unwrap();
    let scenario: Value = serde_json::from_str(&text).unwrap();
    scenario["hosts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, ip)| (name.clone(), ip.as_str().unwrap().parse().unwrap()))
        .collect()
}

fn compare(kinds: &[&str], file: &str, answer: impl Fn(&Case) -> String) {
    let ours: Vec<String> = cases()
        .iter()
        .filter(|c| kinds.contains(&c.kind.as_str()))
        .map(|c| format!("{}\t{}", c.kind, answer(c)))
        .collect();
    let theirs = go(file);
    assert_eq!(ours.len(), theirs.len(), "{file}: case count");
    for (ours, theirs) in ours.iter().zip(&theirs) {
        assert_eq!(ours, theirs, "{file}");
    }
}

// Faults: Traefik's rule read otherwise (`Host` and `HostRegexp` in any
// case, with Go's `ſ` folding for `s`, inside other words, the first `)`
// ending the call, back-quoted, double- or single-quoted hosts, a
// `HostRegexp` pattern left out, each host once); the `api@internal`
// router labels read otherwise (names in any case and with spaces, TLS
// from the entry points or the `tls` labels); an image named otherwise
// (tag, digest, Docker Hub and registry prefixes, `library/`); NPM's
// API path joined otherwise to the address set by the owner.
#[test]
fn proxy_readers_match_go() {
    compare(
        &["rule", "labels", "image", "npmurl"],
        "proxy-parsers.txt",
        |c| match c.kind.as_str() {
            "rule" => match hosts_in_rule(&c.a) {
                hosts if hosts.is_empty() => "null".to_owned(),
                hosts => {
                    let quoted: Vec<String> = hosts.iter().map(|h| go_json_string(h)).collect();
                    format!("[{}]", quoted.join(","))
                }
            },
            "labels" => match dashboard_url_from_labels(&c.labels) {
                Some(url) => format!("true\t={url}"),
                None => "false\t=".to_owned(),
            },
            "image" => format!("={}", normalize_image(&c.a)),
            _ => npm_endpoint(&c.a, &c.b).unwrap_or_else(|_| "error".into()),
        },
    );
}

// Faults: a URL Go refuses taken (a control byte, `{` or a space in the
// host, a second colon in an http host, a bad `%` escape, an IPv4 address
// in brackets), or one Go takes refused; the port read otherwise (only a
// written one; none from a URL Go cannot parse); Traefik's backend
// identity written otherwise (the default port, the path, lower case);
// `alt_urls` added to otherwise (each URL once, case ignored, order
// kept); a redirect's `Location` resolved otherwise; Go's outbound rules
// read otherwise (insecure schemes, the scheme list, loopback, private
// addresses and names, link-local and IPv4-mapped addresses, the allow
// list's wildcards, networks and URLs, an unreadable private switch).
#[test]
fn routes_and_outbound_rules_match_go() {
    let hosts = hosts();
    compare(
        &["url", "alt", "redirect", "outbound"],
        "proxy-routes.txt",
        |c| match c.kind.as_str() {
            "url" => {
                let parsed = gourl::parse(&c.a).map_or_else(
                    || "error".to_owned(),
                    |u| {
                        let path = u.escaped_path();
                        format!(
                            "{} {} {}",
                            quote(u.hostname()),
                            quote(u.port()),
                            quote(&path)
                        )
                    },
                );
                format!(
                    "{parsed}\t{}\t={}",
                    port_from_url(&c.a),
                    backend_identity(&c.a)
                )
            }
            "alt" => format!("={}", append_alt_url(&c.a, &c.b)),
            "redirect" => gourl::parse(&c.a)
                .zip(gourl::parse(&c.b))
                .map_or_else(|| "error".into(), |(base, next)| base.resolve(&next).text()),
            _ => {
                let env = Environment::from_pairs(c.env.clone());
                let rules = Outbound::new(&web_proxy::from_environment(&env).outbound);
                let resolved = Outbound::name_to_resolve(&c.a)
                    .and_then(|name| hosts.get(&name).map(|ip| vec![*ip]));
                match rules.check_url(&c.a, resolved.as_deref()) {
                    Ok(()) => "ok".into(),
                    Err(_) => "refused".into(),
                }
            }
        },
    );
}
