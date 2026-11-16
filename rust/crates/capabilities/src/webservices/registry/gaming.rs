//! The gaming service catalog, as the Go agent's `registry_gaming.go`.

use super::{GAMING, KnownService};

pub(super) const SERVICES: &[KnownService] = &[
    KnownService {
        key: "crafty",
        name: "Crafty Controller",
        category: GAMING,
        icon_key: "crafty-controller",
        default_port: 8443,
        health_path: "/",
        docker_images: &["registry.gitlab.com/crafty-controller/crafty-4"],
    },
    KnownService {
        key: "pterodactyl",
        name: "Pterodactyl",
        category: GAMING,
        icon_key: "pterodactyl",
        default_port: 80,
        health_path: "/",
        docker_images: &["ghcr.io/pterodactyl/panel"],
    },
    KnownService {
        key: "pelican",
        name: "Pelican Panel",
        category: GAMING,
        icon_key: "pelican-panel",
        default_port: 80,
        health_path: "/",
        docker_images: &["ghcr.io/pelican-dev/panel"],
    },
    KnownService {
        key: "pufferpanel",
        name: "PufferPanel",
        category: GAMING,
        icon_key: "pufferpanel",
        default_port: 8080,
        health_path: "/api/health",
        docker_images: &["pufferpanel/pufferpanel"],
    },
    KnownService {
        key: "amp",
        name: "AMP",
        category: GAMING,
        icon_key: "amp",
        default_port: 8080,
        health_path: "/",
        docker_images: &["cubecoders/amp"],
    },
];
