//! The collector, cycle by cycle, against the Go collector's own reports
//! and probe requests for the same container lists, probe answers and
//! clock (`testdata/scenario.json`, Go's output in
//! `testdata/go/webservice-steps.json`, one line per step). The Go test
//! that wrote it runs Go's `RunCycle` with these inputs. The recognition
//! probes run one after another before the health checks, so their
//! requests compare in order (Go's list up to its first HEAD, which only a
//! health check sends); the health checks run at once and compare as a
//! set. Requests in a row to one origin with one client are written on
//! one line; a run marked `digest` keeps only the count and SHA-256 of
//! its recognition requests (they are many and none answers); a report
//! equal to the step before is written as `"same"`.
//!
//! Runs with the local port scan also compare the listening ports Go
//! read, each connection its scan made (as the oracle's listeners saw
//! them) and its HTTP checks (as a set: Go runs 16 at once). Go ran them in
//! an empty network namespace with the scenario's listeners on loopback;
//! [`FakeHost`] stands for it here.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use labtether_agent_config::PortScanSettings;
use labtether_agent_config::web_services::normalize_port_list;
use labtether_agent_core::Stop;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::scan::{FakeHost, Listener};
use super::{FixtureEngine, Recorder, Reply, Site, TESTDATA, TableProber};
use crate::docker::engine::EngineApi;
use crate::webservices::cycle::{Collector, Runner};
use crate::webservices::scan::ScanHost;

#[derive(Debug, Clone, Deserialize)]
struct Engine {
    #[serde(default)]
    file: String,
    #[serde(default)]
    repeat: usize,
    #[serde(default)]
    status: u16,
}

#[derive(Debug, Clone, Deserialize)]
struct Step {
    at: u64,
    engine: Option<String>,
    probes: Option<String>,
    sites: Option<String>,
    online: Option<bool>,
    asset: Option<String>,
    #[serde(default)]
    reconnect: bool,
    listeners: Option<String>,
}

/// A run's port scan setting: the list as written in the settings.
#[derive(Debug, Clone, Deserialize)]
struct ScanSetting {
    ports: String,
    include_listening: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Run {
    name: String,
    docker: String,
    #[serde(default)]
    digest: bool,
    host_ip: Option<String>,
    scan: Option<ScanSetting>,
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize)]
struct Scenario {
    host_ip: String,
    interval_s: u64,
    engine: BTreeMap<String, Engine>,
    probes: BTreeMap<String, BTreeMap<String, Option<Reply>>>,
    #[serde(default)]
    sites: BTreeMap<String, BTreeMap<String, Site>>,
    #[serde(default)]
    listeners: BTreeMap<String, Vec<Listener>>,
    runs: Vec<Run>,
}

#[derive(Debug, Deserialize)]
struct GoStep {
    run: String,
    step: usize,
    engine_asked: usize,
    /// The recognition requests in order, or their count and SHA-256.
    recognition: Value,
    health: Vec<String>,
    report: Value,
    #[serde(default)]
    listening: Vec<u16>,
    #[serde(default)]
    dials: Vec<String>,
    /// The scan's HTTP checks, sorted, or their count and SHA-256.
    #[serde(default)]
    scan: Value,
}

/// Requests in a row with the same client, method and origin on one
/// line: `<client> <method> <origin> <path> <path>...`.
fn grouped(asked: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut last = String::new();
    for entry in asked {
        let mut parts = entry.splitn(3, ' ');
        let (client, method) = (parts.next().unwrap(), parts.next().unwrap());
        let (scheme, rest) = parts.next().unwrap().split_once("://").unwrap();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let head = format!("{client} {method} {scheme}://{}", &rest[..end]);
        if head == last {
            let line = out.last_mut().unwrap();
            line.push(' ');
            line.push_str(&rest[end..]);
        } else {
            out.push(format!("{head} {}", &rest[end..]));
            last = head;
        }
    }
    out
}

/// The count and SHA-256 of requests, one per line.
fn digested(asked: &[String]) -> Value {
    let text = asked.join("\n");
    let hash: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    json!({"count": asked.len(), "sha256": hash})
}

/// The recognition requests as Go's output keeps them for this run.
fn recognition(asked: &[String], digest: bool) -> Value {
    if digest {
        digested(asked)
    } else {
        json!(grouped(asked))
    }
}

/// A run's port scan settings, the list read as the agent's settings
/// read it.
fn scan_settings(run: &Run) -> PortScanSettings {
    run.scan
        .as_ref()
        .map_or_else(PortScanSettings::default, |scan| PortScanSettings {
            enabled: true,
            include_listening: scan.include_listening,
            ports: normalize_port_list(&scan.ports).unwrap_or_default(),
        })
}

/// An engine answer as the Go test serves it: a recorded list, or a row
/// repeated with `{n}` as a three-digit count and `{port}` as 19000 + n.
fn engine_answer(engine: &Engine) -> Result<Vec<u8>, u16> {
    if engine.status >= 300 {
        return Err(engine.status);
    }
    let text = std::fs::read_to_string(format!("{TESTDATA}/engine/{}", engine.file)).unwrap();
    if engine.repeat == 0 {
        return Ok(text.into_bytes());
    }
    let rows: Vec<String> = (0..engine.repeat)
        .map(|n| {
            text.trim()
                .replace("{n}", &format!("{n:03}"))
                .replace("{port}", &(19000 + n).to_string())
        })
        .collect();
    Ok(format!("[{}]", rows.join(",")).into_bytes())
}

/// The report without what depends on timing, with Go's `null` and
/// Rust's empty lists alike.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "collected_at" | "cycle_duration_ms" | "duration_ms" | "response_ms"
                    )
                })
                .map(|(k, v)| (k.clone(), normalize(v)))
                .filter(|(_, v)| !matches!(v, Value::Null) && v != &json!([]) && v != &json!({}))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn go_steps() -> BTreeMap<(String, usize), GoStep> {
    let text = std::fs::read_to_string(format!("{TESTDATA}/go/webservice-steps.json")).unwrap();
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<GoStep>(line).unwrap())
        .map(|step| ((step.run.clone(), step.step), step))
        .collect()
}

// Faults, each a step where Rust would differ from Go: a stopped
// container, a UDP-only or unpublished port listed; another port chosen
// (known service's default port, likely web ports, at most four for an
// unknown container); a name, category, icon or health path not from the
// registry (image, then name hint, then image hint) or not overridden by
// the `labtether.*` labels; another ID, URL host or scheme guess; a probe
// to another path, by another method or client, or one more or fewer
// (HEAD then GET, the other scheme after no answer or a 400, the verified
// client after the insecure one); another status, score or scheme switch;
// a result kept past Go's 3-interval `up` or 1-interval `down` time, or
// probed again before it; the last Docker services not kept when the list
// fails, kept after a new connection, or kept from before; a report while
// offline; the asset ID read at another time; LabTether's console and API
// named or hidden otherwise; another statistic for a source.
// Recognition (Go's fingerprinting and connector probes): a probe to
// another path or in another order, or one more or fewer (LabTether's
// `/healthz`, `/version`, `/api/health`, login page and its one redirect,
// `/api/auth/login`; the root page, `/ui/` after a redirect, the TrueNAS,
// Synology and QNAP APIs; each connector probe in its port's order,
// stopping at 0.97; the other scheme only when nothing answered); a page
// marker missed or matched in another order (the backup server before
// Proxmox VE), past the first 64 KiB, on a 5xx page or an unreadable one;
// another name, key, category, icon or health path taken (a generic
// "Port N" name or the `Other` category replaced, others kept); another
// connector, confidence, auth hint, profile or evidence; Portainer or
// Home Assistant known by key probed; a result kept past Go's 15 or 5
// minutes (names) or 10 or 3 minutes (connectors), or asked again before.
// Local port scan: a scan while its setting is off; another port list
// (Go's 49 defaults, the owner's list instead of them, the first 128
// listening ports added only when asked); a port a service found earlier
// uses (its URL, public or private port) dialled; another address than
// the host's dialled; a TLS hello on other ports than Go's HTTPS ones, or
// none on them; a port kept without an HTTP answer at either scheme, or
// checked otherwise; another order (named by the registry, then likely
// web ports, then by number), more or fewer than 8 unnamed ports; another
// ID, name, URL or metadata; the scan's count or switch in the report.
#[test]
fn cycles_match_go() {
    let text = std::fs::read_to_string(format!("{TESTDATA}/scenario.json")).unwrap();
    let scenario: Scenario = serde_json::from_str(&text).unwrap();
    let expected = go_steps();
    let base = UNIX_EPOCH + Duration::from_secs(1_794_000_000);
    let mut compared = 0;
    for run in &scenario.runs {
        let prober = TableProber::default();
        let sender = Recorder::default();
        let engine = FixtureEngine::new();
        let runner = Runner::new(&Stop::new()).unwrap();
        let interval = Duration::from_secs(scenario.interval_s);
        let host_ip = run.host_ip.clone().unwrap_or(scenario.host_ip.clone());
        let host = FakeHost::new(&host_ip);
        let mut collector = Collector::new(host_ip.clone(), run.docker != "off", interval);
        collector.scan = scan_settings(run);
        let mut previous = Value::Null;
        for (index, step) in run.steps.iter().enumerate() {
            if let Some(name) = &step.engine {
                *engine.answer.lock().unwrap() = engine_answer(&scenario.engine[name]);
            }
            if let Some(name) = &step.probes {
                prober.set(scenario.probes[name].clone());
            }
            if let Some(name) = &step.sites {
                prober.set_sites(scenario.sites[name].clone());
            }
            if let Some(online) = step.online {
                sender
                    .offline
                    .store(!online, std::sync::atomic::Ordering::SeqCst);
            }
            if let Some(asset) = &step.asset {
                *sender.asset.lock().unwrap() = asset.clone();
            }
            if step.reconnect {
                sender
                    .connections
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            if let Some(name) = &step.listeners {
                host.set(scenario.listeners[name].clone());
            }
            let docker = (run.docker != "none").then_some(&engine as &dyn EngineApi);
            let now: SystemTime = base + Duration::from_secs(step.at);
            collector.run(&sender, docker, &prober, &host, &runner, &|| now);
            let where_ = format!("run {} step {index} (at {} s)", run.name, step.at);
            let go = &expected[&(run.name.clone(), index)];
            let engine_asked = std::mem::take(&mut *engine.asked.lock().unwrap()).len();
            assert_eq!(engine_asked, go.engine_asked, "{where_}: engine reads");
            let (scanned, fetched, attempted) = prober.take();
            let (dials, hosts, dialled) = host.take();
            if run.scan.is_some() {
                assert_eq!(host.listening(), go.listening, "{where_}: listening");
                let scanned = if run.digest {
                    digested(&scanned)
                } else {
                    json!(scanned)
                };
                assert_eq!(scanned, go.scan, "{where_}: scan's HTTP checks");
                assert!(
                    hosts.iter().all(|h| *h == host_ip),
                    "{where_}: dialled {hosts:?}"
                );
            } else {
                assert_eq!((dialled, scanned.len()), (0, 0), "{where_}: scan when off");
            }
            assert_eq!(dials, go.dials, "{where_}: connections");
            assert_eq!(
                recognition(&fetched, run.digest),
                go.recognition,
                "{where_}: recognition requests\nrust: {fetched:#?}"
            );
            assert_eq!(attempted, go.health, "{where_}: health checks");
            let sent = sender.take();
            let report = match sent.as_slice() {
                [] => Value::Null,
                [(kind, data)] => {
                    assert_eq!(kind, "webservice.report", "{where_}");
                    data.clone()
                }
                more => panic!("{where_}: {} messages", more.len()),
            };
            let go_report = if go.report == json!("same") {
                previous.clone()
            } else {
                go.report.clone()
            };
            assert_eq!(
                normalize(&report),
                normalize(&go_report),
                "{where_}: report\nrust: {report}\ngo:   {go_report}"
            );
            previous = go_report;
            compared += 1;
        }
    }
    assert_eq!(compared, expected.len(), "every Go step compared");
}
