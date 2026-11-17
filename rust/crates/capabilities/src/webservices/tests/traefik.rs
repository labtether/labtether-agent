//! Traefik's routes from real Traefik API answers, the files the Go
//! agent's test reads (`internal/agentcore/proxy/testdata/traefik/`):
//! one Traefik v3 and one v2, each with the file and Docker providers, and
//! the route list for them (`routes.json`), each backend the server Traefik
//! itself sends that host to.

use serde::Deserialize;

use crate::webservices::proxy::api::{ApiRequest, ApiResponse, Exchanging, ProxyApi, Resolving};
use crate::webservices::proxy::outbound::Outbound;
use crate::webservices::proxy::traefik_fetch;

const ANSWERS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../internal/agentcore/proxy/testdata/traefik"
);

/// The two lists of one recorded Traefik, at `http://localhost:8080`.
struct Recorded {
    routers: Vec<u8>,
    services: Vec<u8>,
}

impl ProxyApi for Recorded {
    fn exchange<'a>(
        &'a self,
        request: &'a ApiRequest,
        _rules: Option<(&'a Outbound, &'a str)>,
    ) -> Exchanging<'a> {
        let body = match request.url.as_str() {
            "http://localhost:8080/api/http/routers?per_page=1000" => Some(&self.routers),
            "http://localhost:8080/api/http/services?per_page=1000" => Some(&self.services),
            _ => None,
        };
        let answer = body
            .map(|body| ApiResponse {
                status: 200,
                location: String::new(),
                body: body.clone(),
            })
            .ok_or_else(|| "connection refused".to_owned());
        Box::pin(async move { answer })
    }

    fn resolve<'a>(&'a self, _host: &'a str) -> Resolving<'a> {
        Box::pin(async { None })
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Expected {
    domain: String,
    backend_url: String,
    tls: bool,
    router_name: String,
}

fn read(version: &str, file: &str) -> Vec<u8> {
    std::fs::read(format!("{ANSWERS}/{version}/{file}")).unwrap()
}

// Fault: the routers list gives a service in the router's own provider by
// its bare name (`f1` for router `f1@file`) while the services list names
// it `f1@file`. Looked up by the bare name (as Go did), 7 of these 9
// routes lost their backend, so each became a service of its own instead
// of joining the service it proxies.
#[test]
fn bare_service_names_take_the_router_provider() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    for version in ["v3.7.19", "v2.11.63"] {
        let api = Recorded {
            routers: read(version, "routers.json"),
            services: read(version, "services.json"),
        };
        let routes = runtime
            .block_on(traefik_fetch(&api, "http://localhost:8080", None))
            .unwrap();
        let got: Vec<Expected> = routes
            .into_iter()
            .map(|r| Expected {
                domain: r.domain,
                backend_url: r.backend_url,
                tls: r.tls,
                router_name: r.router_name,
            })
            .collect();
        let want: Vec<Expected> = serde_json::from_slice(&read(version, "routes.json")).unwrap();
        assert_eq!(got, want, "{version}");
    }
}
