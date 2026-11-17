//! Health checks: Go's `collector_health_probe.go` and
//! `collector_health_cache.go`. A service is probed with HEAD, then GET
//! when HEAD got no answer, at its health path; when that gets no answer
//! or a 400 the other scheme is tried too and the better answer wins (its
//! scheme then becomes the service URL). An answer under 500 is `up`,
//! anything else `down`. Results are kept per service, `up` for three
//! intervals (45 s to 10 min) and `down` for one (20 s to 2 min); at most
//! 16 checks run at once.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use futures_util::StreamExt;
use labtether_protocol::DiscoveredWebService;

use super::pages::Fetching;
use super::urls::alternate_scheme_url;

/// Go's `maxHealthCheckConcurrency` and `maxHealthCacheEntries`.
const MAX_IN_FLIGHT: usize = 16;
const MAX_CACHE_ENTRIES: usize = 2048;

/// Go's two probe clients: `client` checks certificates (and serves plain
/// http), `insecureClient` does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Client {
    Secure,
    Insecure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Method {
    Head,
    Get,
}

pub(crate) type Pending<'a> = Pin<Box<dyn Future<Output = Option<u16>> + Send + 'a>>;

/// One request with one of the clients: the status code, or `None` when
/// no answer came (Go's `client.Do` error).
pub(crate) trait Prober: Send + Sync {
    fn attempt<'a>(&'a self, client: Client, method: Method, url: &'a str) -> Pending<'a>;

    /// A recognition probe's GET: the status, `Location` and the first
    /// 64 KiB of the page, or `None` when no answer came.
    fn fetch<'a>(&'a self, client: Client, url: &'a str) -> Fetching<'a>;
}

/// Go's `doHealthRequest`: https goes to the client that does not check
/// certificates first and, when that gets no answer, to the one that does.
/// The port scan's HTTP check uses it too.
pub(crate) async fn request(prober: &dyn Prober, method: Method, url: &str) -> Option<u16> {
    // Go's `http.NewRequest` refuses a URL its parser refuses: no request.
    super::gourl::parse(url)?;
    let https = url.trim().to_ascii_lowercase().starts_with("https://");
    let first = if https {
        Client::Insecure
    } else {
        Client::Secure
    };
    match prober.attempt(first, method, url).await {
        Some(status) => Some(status),
        None if https => prober.attempt(Client::Secure, method, url).await,
        None => None,
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ProbeResult {
    base_url: String,
    status: u16,
    response_ms: i64,
    responded: bool,
}

/// Go's `probeHTTP`: HEAD, then GET when HEAD got no answer; the time is
/// that of the request that answered.
async fn probe_http(prober: &dyn Prober, url: &str) -> (u16, i64, bool) {
    for method in [Method::Head, Method::Get] {
        let start = Instant::now();
        if let Some(status) = request(prober, method, url).await {
            let elapsed = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);
            return (status, elapsed, true);
        }
    }
    (0, 0, false)
}

/// Go's `probeCandidateHealth`.
async fn probe_candidate(prober: &dyn Prober, base_url: &str, health_path: &str) -> ProbeResult {
    let url = if health_path.is_empty() {
        base_url.to_owned()
    } else {
        format!("{}{health_path}", base_url.trim_end_matches('/'))
    };
    let (status, response_ms, responded) = probe_http(prober, &url).await;
    ProbeResult {
        base_url: base_url.to_owned(),
        status,
        response_ms,
        responded,
    }
}

/// Go's `probeScore`.
fn score(result: &ProbeResult) -> u8 {
    match result.status {
        _ if !result.responded => 0,
        200..=399 => 4,
        401 | 403 | 404 => 3,
        400 => 1,
        402..=499 => 2,
        _ => 1,
    }
}

/// Go's `betterProbeResult`: the higher score; on a tie, https.
fn better(primary: ProbeResult, alternate: ProbeResult) -> ProbeResult {
    let (p, a) = (score(&primary), score(&alternate));
    let https = |r: &ProbeResult| r.base_url.to_ascii_lowercase().starts_with("https://");
    if a > p || (a == p && p > 0 && https(&alternate) && !https(&primary)) {
        alternate
    } else {
        primary
    }
}

/// Go's `probeHealthURL`.
async fn probe_health_url(prober: &dyn Prober, base_url: &str, health_path: &str) -> ProbeResult {
    let primary = probe_candidate(prober, base_url, health_path).await;
    if primary.responded && primary.status != 400 {
        return primary;
    }
    let alternate_url = alternate_scheme_url(base_url);
    if alternate_url.is_empty() {
        return primary;
    }
    let alternate = probe_candidate(prober, &alternate_url, health_path).await;
    better(primary, alternate)
}

fn up(status: u16) -> bool {
    status > 0 && status < 500
}

fn metadata<'a>(svc: &'a DiscoveredWebService, key: &str) -> &'a str {
    svc.metadata.get(key).map_or("", String::as_str)
}

/// Go's `healthCheckWithFallback`: `healthCheck`, then the URL behind a
/// proxy (`raw_url`) when the service is down.
async fn check(prober: &dyn Prober, svc: &mut DiscoveredWebService) {
    let health_path = metadata(svc, "health_path").to_owned();
    let result = probe_health_url(prober, &svc.url, &health_path).await;
    if result.responded {
        if !result.base_url.is_empty() && result.base_url != svc.url {
            svc.url = result.base_url;
        }
        svc.response_ms = result.response_ms;
        svc.status = if up(result.status) { "up" } else { "down" }.to_owned();
    } else {
        svc.response_ms = 0;
        svc.status = "down".to_owned();
    }
    let raw_url = metadata(svc, "raw_url").to_owned();
    if svc.status == "down" && !raw_url.is_empty() {
        let result = probe_health_url(prober, &raw_url, &health_path).await;
        if result.responded && up(result.status) {
            svc.status = "up".to_owned();
            svc.response_ms = result.response_ms;
        }
    }
}

/// Go's `serviceFingerprintBaseURL`: the URL, else `raw_url`, else
/// `backend_url`, the last one set winning.
pub(crate) fn base_url(svc: &DiscoveredWebService) -> String {
    let mut base = svc.url.trim();
    for key in ["raw_url", "backend_url"] {
        let value = metadata(svc, key).trim();
        if !value.is_empty() {
            base = value;
        }
    }
    base.to_owned()
}

/// Go's `healthCacheKeyForService`.
fn cache_key(svc: &DiscoveredWebService) -> String {
    let id = svc.id.trim();
    if !id.is_empty() {
        return format!("id:{}", id.to_lowercase());
    }
    let base = base_url(svc);
    if !base.is_empty() {
        return format!("url:{}", base.to_lowercase());
    }
    let url = svc.url.trim();
    if url.is_empty() {
        String::new()
    } else {
        format!("url:{}", url.to_lowercase())
    }
}

#[derive(Debug, Clone)]
struct Entry {
    input_url: String,
    output_url: String,
    status: String,
    response_ms: i64,
    checked_at: SystemTime,
}

/// The results kept between cycles.
#[derive(Debug)]
pub(crate) struct HealthCache {
    interval: Duration,
    entries: HashMap<String, Entry>,
}

impl HealthCache {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            entries: HashMap::new(),
        }
    }

    /// Go's `healthCacheTTL`.
    fn ttl(&self, status: &str) -> Duration {
        if status.trim().eq_ignore_ascii_case("down") {
            self.interval
                .clamp(Duration::from_secs(20), Duration::from_secs(120))
        } else {
            (self.interval * 3).clamp(Duration::from_secs(45), Duration::from_secs(600))
        }
    }

    fn age(now: SystemTime, then: SystemTime) -> Duration {
        now.duration_since(then).unwrap_or_default()
    }

    /// Go's `applyHealthChecksParallel`: kept results first, then the
    /// others checked at most 16 at a time, then kept for next time.
    pub async fn apply(
        &mut self,
        prober: &dyn Prober,
        services: &mut [DiscoveredWebService],
        now: SystemTime,
    ) {
        let mut jobs = Vec::new();
        for (index, svc) in services.iter_mut().enumerate() {
            let key = cache_key(svc);
            let input = {
                let base = base_url(svc);
                if base.is_empty() {
                    svc.url.trim().to_owned()
                } else {
                    base
                }
            };
            if !key.is_empty()
                && let Some(entry) = self.entries.get(&key)
            {
                if entry.input_url.eq_ignore_ascii_case(&input)
                    && Self::age(now, entry.checked_at) <= self.ttl(&entry.status)
                {
                    svc.status = entry.status.clone();
                    svc.response_ms = entry.response_ms;
                    if !entry.output_url.trim().is_empty() {
                        svc.url = entry.output_url.clone();
                    }
                    continue;
                }
                self.entries.remove(&key);
            }
            jobs.push((index, key, input));
        }
        if jobs.is_empty() {
            return;
        }
        let checked: Vec<(usize, DiscoveredWebService)> =
            futures_util::stream::iter(jobs.iter().map(|(index, _, _)| {
                let mut svc = services[*index].clone();
                async move {
                    check(prober, &mut svc).await;
                    (*index, svc)
                }
            }))
            .buffer_unordered(MAX_IN_FLIGHT)
            .collect()
            .await;
        for (index, svc) in checked {
            services[index] = svc;
        }
        for (index, key, input) in jobs {
            if key.is_empty() {
                continue;
            }
            let svc = &services[index];
            self.entries.insert(
                key,
                Entry {
                    input_url: input,
                    output_url: svc.url.trim().to_owned(),
                    status: svc.status.trim().to_lowercase(),
                    response_ms: svc.response_ms,
                    checked_at: now,
                },
            );
        }
        self.prune(now);
    }

    /// Go's `pruneHealthCache`: over 2,048 entries, the expired ones go,
    /// then the oldest.
    fn prune(&mut self, now: SystemTime) {
        if self.entries.len() <= MAX_CACHE_ENTRIES {
            return;
        }
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| Self::age(now, e.checked_at) > self.ttl(&e.status))
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.entries.remove(&key);
        }
        while self.entries.len() > MAX_CACHE_ENTRIES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.checked_at)
                .map(|(key, _)| key.clone())
            else {
                return;
            };
            self.entries.remove(&oldest);
        }
    }
}
