//! Reverse-proxy routes: Go's `internal/agentcore/proxy` providers and the
//! first half of `enrichFromProxies` (`collector_service_metadata.go`).
//! Each provider switched on (Traefik, Caddy, NPM, in that order) looks
//! for its proxy among the containers (or takes its address from the
//! environment) and reads its routes; all run at once, as Go's goroutines.
//!
//! Go applies the results in the order its goroutines finish; this
//! applies them in the providers' order. The two agree unless two
//! providers route to the same service in one cycle.

pub(crate) mod api;
mod caddy;
pub(crate) mod http;
mod npm;
pub(crate) mod outbound;
mod traefik;

use data_encoding::BASE64;
use futures_util::future::join_all;
use labtether_agent_config::ProxySettings;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

use crate::docker::raw::{Container, Port};
use api::ProxyApi;
use outbound::Outbound;

#[cfg(test)]
pub(crate) use npm::{endpoint as npm_endpoint, go_json_string};
#[cfg(test)]
pub(crate) use traefik::{dashboard_url_from_labels, hosts_in_rule};

/// Go's `proxy.Route`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub domain: String,
    pub backend_url: String,
    pub tls: bool,
    pub router_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Traefik,
    Caddy,
    Npm,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Traefik => "traefik",
            Self::Caddy => "caddy",
            Self::Npm => "npm",
        }
    }
}

/// `null` reads as the zero value, as Go's decoder leaves the field unset.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Go's `json.NewDecoder(body).Decode`: the first JSON value, whatever
/// follows it.
fn decode_first<T: DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    serde_json::Deserializer::from_slice(body)
        .into_iter::<T>()
        .next()
        .unwrap_or_else(|| Err(serde::de::Error::custom("EOF")))
        .map_err(|error| error.to_string())
}

/// Go's `FindHostPort`: the published port of the first mapping of
/// `private`, 0 when none.
fn find_host_port(ports: &[Port], private: i64) -> i64 {
    ports
        .iter()
        .find(|p| p.private_port == private && p.public_port > 0)
        .map_or(0, |p| p.public_port)
}

/// Go's `normalizeDockerImage` of `proxy/helpers.go`.
pub(crate) fn normalize_image(image: &str) -> String {
    let mut image = image.trim().to_lowercase();
    if image.is_empty() {
        return image;
    }
    if let Some(at) = image.find('@') {
        image.truncate(at);
    }
    let name_start = image.rfind('/').map_or(0, |slash| slash + 1);
    if let Some(colon) = image[name_start..].rfind(':') {
        image.truncate(name_start + colon);
    }
    let mut image = image.as_str();
    for prefix in [
        "registry-1.docker.io/library/",
        "registry-1.docker.io/",
        "index.docker.io/library/",
        "index.docker.io/",
        "docker.io/library/",
        "docker.io/",
    ] {
        image = image.strip_prefix(prefix).unwrap_or(image);
    }
    if let Some(slash) = image.find('/').filter(|slash| *slash > 0) {
        let host = &image[..slash];
        if host == "localhost" || host.contains(['.', ':']) {
            image = &image[slash + 1..];
        }
    }
    image
        .strip_prefix("library/")
        .unwrap_or(image)
        .trim()
        .to_owned()
}

/// The providers switched on and their state between cycles.
pub(crate) struct Providers {
    settings: ProxySettings,
    kinds: Vec<Kind>,
    outbound: Outbound,
    npm_token: npm::Token,
}

impl Providers {
    /// As Go's `NewWebServiceCollector`: none while the source is off.
    pub fn new(settings: &ProxySettings) -> Self {
        let switched = [
            (Kind::Traefik, settings.traefik),
            (Kind::Caddy, settings.caddy),
            (Kind::Npm, settings.npm),
        ];
        Self {
            kinds: switched
                .into_iter()
                .filter(|(_, on)| settings.enabled && *on)
                .map(|(kind, _)| kind)
                .collect(),
            outbound: Outbound::new(&settings.outbound),
            settings: settings.clone(),
            npm_token: npm::Token::default(),
        }
    }

    /// Go's `ProxyEnabled`.
    pub fn enabled(&self) -> bool {
        self.settings.enabled
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Each provider's routes, or why it failed; none when its proxy was
    /// not found.
    pub async fn fetch(
        &self,
        api: &dyn ProxyApi,
        containers: &[Container],
    ) -> Vec<(Kind, Result<Vec<Route>, String>)> {
        join_all(
            self.kinds
                .iter()
                .map(|kind| self.one(*kind, api, containers)),
        )
        .await
    }

    async fn one(
        &self,
        kind: Kind,
        api: &dyn ProxyApi,
        containers: &[Container],
    ) -> (Kind, Result<Vec<Route>, String>) {
        let s = &self.settings;
        let found = match kind {
            Kind::Traefik => traefik::detect(containers, &s.traefik_url),
            Kind::Caddy => caddy::detect(containers, &s.caddy_url),
            Kind::Npm => npm::detect(containers, &s.npm_url, s.npm_http),
        };
        let Some(url) = found else {
            return (kind, Ok(Vec::new()));
        };
        log::info!("webservices: proxy/{} detected at {url}", kind.name());
        let routes = match kind {
            Kind::Traefik => {
                let auth = s
                    .traefik_password
                    .as_ref()
                    .filter(|_| !s.traefik_user.is_empty())
                    .map(|password| {
                        let pair = format!("{}:{}", s.traefik_user, password.expose());
                        format!("Basic {}", BASE64.encode(pair.as_bytes()))
                    });
                traefik::fetch(api, &url, auth).await
            }
            Kind::Caddy => caddy::fetch(api, &url).await,
            Kind::Npm => {
                let password = s.npm_password.as_ref();
                npm::fetch(
                    api,
                    &self.outbound,
                    &url,
                    &s.npm_email,
                    password,
                    &self.npm_token,
                )
                .await
            }
        };
        (kind, routes)
    }
}
