//! The databases service catalog, as the Go agent's `registry_databases.go`.

use super::{DATABASES, KnownService};

pub(super) const SERVICES: &[KnownService] = &[
    KnownService {
        key: "pgadmin",
        name: "pgAdmin",
        category: DATABASES,
        icon_key: "pgadmin",
        default_port: 80,
        health_path: "/misc/ping",
        docker_images: &["dpage/pgadmin4"],
    },
    KnownService {
        key: "adminer",
        name: "Adminer",
        category: DATABASES,
        icon_key: "adminer",
        default_port: 8080,
        health_path: "/",
        docker_images: &["adminer"],
    },
    KnownService {
        key: "phpmyadmin",
        name: "phpMyAdmin",
        category: DATABASES,
        icon_key: "phpmyadmin",
        default_port: 80,
        health_path: "/",
        docker_images: &["phpmyadmin"],
    },
    KnownService {
        key: "redis-commander",
        name: "Redis Commander",
        category: DATABASES,
        icon_key: "redis",
        default_port: 8081,
        health_path: "/",
        docker_images: &["rediscommander/redis-commander"],
    },
    KnownService {
        key: "mongo-express",
        name: "Mongo Express",
        category: DATABASES,
        icon_key: "mongodb",
        default_port: 8081,
        health_path: "/",
        docker_images: &["mongo-express"],
    },
    KnownService {
        key: "dbgate",
        name: "DbGate",
        category: DATABASES,
        icon_key: "dbgate",
        default_port: 3000,
        health_path: "/",
        docker_images: &["dbgate/dbgate"],
    },
    KnownService {
        key: "cloudbeaver",
        name: "CloudBeaver",
        category: DATABASES,
        icon_key: "cloudbeaver",
        default_port: 8978,
        health_path: "/status",
        docker_images: &["dbeaver/cloudbeaver"],
    },
];
