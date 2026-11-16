//! The registry against the Go agent's (`testdata/go/registry.txt`,
//! written by the Go test from Go's own registry): every service's fields,
//! and the lookups by each of its images (as written, and changed in case
//! with a Docker Hub prefix, a tag and a digest) and by its key, name and
//! icon; then lookups of names, domains, URLs and images that Go's tests
//! and containers use.

use crate::webservices::registry::{self, KnownService};

fn key(found: Option<&KnownService>) -> &'static str {
    found.map_or("-", |service| service.key)
}

/// The changed image: `DOCKER.IO/<IMAGE>:Latest@sha256:0`.
fn variant(image: &str) -> String {
    format!("DOCKER.IO/{}:Latest@sha256:0", image.to_uppercase())
}

/// One line per service, as the Go test writes it.
fn service_line(service: &KnownService) -> String {
    let images = service.docker_images.join(",");
    let by_image: Vec<String> = service
        .docker_images
        .iter()
        .map(|image| {
            let plain = key(registry::by_docker_image(image));
            let changed = key(registry::by_docker_image(&variant(image)));
            format!("{plain}/{changed}")
        })
        .collect();
    let by_hint = [service.key, service.name, service.icon_key]
        .map(|hint| key(registry::by_hint(hint)))
        .join(",");
    format!(
        "service\t{}\t{}\t{}\t{}\t{}\t{}\t{images}\t{}\t{by_hint}",
        service.key,
        service.name,
        service.category,
        service.icon_key,
        service.default_port,
        service.health_path,
        by_image.join(",")
    )
}

// Faults: a service missing, added or changed from Go's catalog (its name,
// category, icon, default port, health path or images: the Services page
// then names, sorts or checks a container otherwise); an image or hint
// lookup that finds another service or none (tag, digest, registry host,
// Docker Hub prefix or case not stripped as Go; the first key in sorted
// order not winning a shared image or hint; an alias missing; a name
// split into other parts).
#[test]
fn registry_matches_go() {
    let text = std::fs::read_to_string(format!("{}/go/registry.txt", super::TESTDATA)).unwrap();
    let mut go_services = Vec::new();
    let mut lookups = 0;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields[0] {
            "service" => go_services.push(line.to_owned()),
            "image" => {
                assert_eq!(
                    key(registry::by_docker_image(fields[1])),
                    fields[2],
                    "{line}"
                );
                lookups += 1;
            }
            "hint" => {
                assert_eq!(key(registry::by_hint(fields[1])), fields[2], "{line}");
                lookups += 1;
            }
            other => panic!("unknown line kind {other}"),
        }
    }
    let ours: Vec<String> = registry::all().map(service_line).collect();
    assert_eq!(ours.len(), go_services.len(), "service count");
    for (rust, go) in ours.iter().zip(&go_services) {
        assert_eq!(rust, go);
    }
    assert!(lookups > 40, "{lookups} extra lookups");
}
