//! The proxies' APIs as the Go oracle serves them: answers from the
//! scenario's tables on loopback ports in a container with no network, so
//! a request reaches them only when its host is (or names) a loopback
//! address and its port is one the run's tables use. Each request that
//! reaches them is recorded as the oracle records it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Mutex;

use super::Reply;
use crate::webservices::proxy::api::{ApiRequest, ApiResponse, Exchanging, ProxyApi, Resolving};
use crate::webservices::proxy::outbound::{Outbound, check_ip};
use crate::webservices::urls::Target;

#[derive(Default)]
pub(crate) struct TableApi {
    pub table: Mutex<BTreeMap<String, Option<Reply>>>,
    /// The ports the oracle listens on.
    pub ports: BTreeSet<u16>,
    /// The names the oracle's container resolves (`--add-host`).
    pub hosts: BTreeMap<String, String>,
    pub asked: Mutex<Vec<String>>,
}

fn or_dash(value: Option<&str>) -> &str {
    value.filter(|v| !v.is_empty()).unwrap_or("-")
}

/// The `host:port` of a recorded request, as the oracle sorts by it.
fn origin(line: &str) -> String {
    let url = line.split(' ').nth(1).unwrap_or("");
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    rest[..end].to_owned()
}

impl TableApi {
    pub fn new(
        tables: &[&BTreeMap<String, Option<Reply>>],
        hosts: &BTreeMap<String, String>,
    ) -> Self {
        let ports = tables
            .iter()
            .flat_map(|table| table.keys())
            .filter_map(|key| Target::parse(key.split_once(' ')?.1))
            .map(|target| target.port)
            .collect();
        Self {
            ports,
            hosts: hosts.clone(),
            ..Self::default()
        }
    }

    pub fn set(&self, table: BTreeMap<String, Option<Reply>>) {
        *self.table.lock().unwrap() = table;
    }

    /// The requests since the last call, each origin's in order, the
    /// origins sorted.
    pub fn take(&self) -> Vec<String> {
        let mut asked = std::mem::take(&mut *self.asked.lock().unwrap());
        asked.sort_by_key(|line| origin(line));
        asked
    }

    /// The addresses a name has in the oracle's container.
    fn addresses(&self, host: &str) -> Vec<IpAddr> {
        if host.eq_ignore_ascii_case("localhost") {
            return vec![IpAddr::from([127, 0, 0, 1]), "::1".parse().unwrap()];
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        self.hosts
            .get(host)
            .and_then(|ip| ip.parse().ok())
            .into_iter()
            .collect()
    }

    fn answer(
        &self,
        request: &ApiRequest,
        rules: Option<(&Outbound, &str)>,
    ) -> Result<ApiResponse, String> {
        let target = Target::parse(&request.url).ok_or("unsupported URL")?;
        let addresses = self.addresses(&target.host.to_ascii_lowercase());
        if addresses.is_empty() {
            return Err("no such host".into());
        }
        if let Some((rules, scheme)) = rules {
            for ip in &addresses {
                check_ip(
                    &target.host,
                    *ip,
                    rules.allow_loopback(),
                    rules.allow_private(scheme),
                )?;
            }
        }
        let loopback = addresses.iter().any(|ip| ip.to_canonical().is_loopback());
        if !loopback || !self.ports.contains(&target.port) || target.https {
            return Err("connection refused".into());
        }
        let body = request.json.as_deref().map(String::from_utf8_lossy);
        let line = format!(
            "{} {} auth={} type={} ref={} body={}",
            request.method,
            request.url,
            or_dash(request.authorization.as_deref()),
            if request.json.is_some() {
                "application/json"
            } else {
                "-"
            },
            or_dash(request.referer.as_deref()),
            or_dash(body.as_deref()),
        );
        self.asked.lock().unwrap().push(line);
        let key = format!("{} {}", request.method, request.url);
        let reply = self.table.lock().unwrap().get(&key).cloned().flatten();
        let reply = reply.ok_or("connection closed")?;
        let page = reply.page();
        Ok(ApiResponse {
            status: page.status,
            location: page.location,
            body: page.body.unwrap_or_default(),
        })
    }
}

impl ProxyApi for TableApi {
    fn exchange<'a>(
        &'a self,
        request: &'a ApiRequest,
        rules: Option<(&'a Outbound, &'a str)>,
    ) -> Exchanging<'a> {
        let answer = self.answer(request, rules);
        Box::pin(async move { answer })
    }

    fn resolve<'a>(&'a self, host: &'a str) -> Resolving<'a> {
        let found = self
            .hosts
            .get(host)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .map(|ip| vec![ip]);
        Box::pin(async move { found })
    }
}
